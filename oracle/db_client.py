"""Oracle connection pool, UTC SQL repository, and Defense-in-Depth verifier."""

from __future__ import annotations

import logging
import re
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Sequence

import oracledb

try:
    from oracle.config import BridgeConfig
except ImportError:  # pragma: no cover - direct execution from oracle/ directory
    from config import BridgeConfig

logger = logging.getLogger("oracle_ids.db")

_CLIENT_INIT_LOCK = threading.Lock()
_BIND_PREFIX_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")
_ORACLE_IDENTIFIER_RE = re.compile(r"\A[A-Z][A-Z0-9_#$]{0,127}\Z")
_UTC_TS_RE = re.compile(r"\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\Z")

_EXCLUDED_SYSTEM_USERS: tuple[str, ...] = (
    "PDBADMIN",
    "AUDSYS",
    "SYS",
    "SYSTEM",
    "DBSNMP",
    "OUTLN",
    "XDB",
    "PUBLIC",
)

_IDE_METADATA_OBJECTS: tuple[str, ...] = (
    "DUAL",
    "ALL_OBJECTS",
    "ALL_TAB_COLS",
    "ALL_SYNONYMS",
    "ALL_TABLES",
    "ALL_VIEWS",
    "ALL_USERS",
    "ALL_PROCEDURES",
    "ALL_ARGUMENTS",
    "ALL_CONSTRAINTS",
    "ALL_INDEXES",
    "ALL_TRIGGERS",
    "ALL_SOURCE",
    "NLS_SESSION_PARAMETERS",
    "V$OPTION",
    "V$VERSION",
    "USER_ROLE_PRIVS",
    "DATABASE_COMPATIBLE_LEVEL",
    "USER_USERS",
    "DBMS_APPLICATION_INFO",
    "DBMS_OUTPUT",
)

# Oracle POSIX ERE (<= 512 bytes, no \b) ensuring IDE metadata noise suppression
# never drops SQLi, honeytoken, NV-table, or dangerous package abuse via DUAL/ALL_*.
_IDE_SQL_SUSPICIOUS_REGEX = (
    r"(^|[^A-Z0-9_])("
    r"UNION|NV|NV_TRAP|001099000000|OR|"
    r"DBMS_PIPE|DBMS_LOCK|DBMS_CRYPTO|DBMS_LDAP|"
    r"UTL_[A-Z0-9_]*|XMLTYPE|EXTRACTVALUE|EXECUTE|ADMINISTER|"
    r"V\$ENCRYPTION_[A-Z_]*|V_\$ENCRYPTION_[A-Z_]*|"
    r"DBA_ENCRYPTED_COLUMNS|USER_ENCRYPTED_COLUMNS|ENC\$"
    r")([^A-Z0-9_]|$)|--|/\*"
)

_CORE_AUDIT_POLICIES: tuple[str, ...] = (
    "IDS_LOGON_POL",
    "IDS_DDL_POL",
    "IDS_DML_NV_POL",
    "IDS_PRIV_ABUSE_POL",
    "IDS_SECURITY_VIOLATIONS_POL",
)
_CRYPTO_AUDIT_POLICY = "IDS_CRYPTO_KEY_POL"
_ALL_AUDIT_POLICIES: tuple[str, ...] = _CORE_AUDIT_POLICIES + (_CRYPTO_AUDIT_POLICY,)

_IDENTIFIED_BY_RE = re.compile(
    r"(\bIDENTIFIED\s+BY(?:\s+VALUES)?\s+)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s;,]+)"
    r"(?:\s+REPLACE\s+(?:\"[^\"]*\"|'[^']*'|[^\s;,]+))?",
    re.IGNORECASE,
)
_CONNECT_CRED_RE = re.compile(
    r"(\bCONN(?:ECT)?\s+)(\"[^\"]+\"|[A-Za-z0-9_#$]+)\s*/\s*(?:\"[^\"]*\"|'[^']*'|[^\s@;,]+)",
    re.IGNORECASE,
)
_PWD_ASSIGN_RE = re.compile(
    r"(\b(?:PASSWORD|PWD)\s*=\s*)(?:\"[^\"]*\"|'[^']*'|[^\s;,&]+)",
    re.IGNORECASE,
)


def sanitize_sql_credentials(sql_text: str | None) -> str:
    """Scrub plaintext credentials (IDENTIFIED BY ..., CONNECT u/p, PASSWORD=...) from SQL text."""
    if not sql_text:
        return ""
    text = str(sql_text)

    def _mask_identified_by(match: re.Match[str]) -> str:
        full = match.group(0)
        prefix = match.group(1)
        if re.search(r"\s+REPLACE\s+", full, re.IGNORECASE):
            return f"{prefix}*** REPLACE ***"
        return f"{prefix}***"

    text = _IDENTIFIED_BY_RE.sub(_mask_identified_by, text)
    text = _CONNECT_CRED_RE.sub(r"\1\2/***", text)
    text = _PWD_ASSIGN_RE.sub(r"\1***", text)
    return text


def _normalize_utc_cutoff(cutoff_utc: str | None) -> str:
    """Normalize a UTC timestamp string into 'YYYY-MM-DD HH24:MI:SS' format."""
    if not cutoff_utc:
        return "1970-01-01 00:00:00"
    cleaned = str(cutoff_utc).strip().replace("T", " ")
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1]
    candidate = cleaned[:19]
    if _UTC_TS_RE.fullmatch(candidate):
        return candidate
    logger.warning("Invalid UTC cutoff %r; falling back to epoch baseline.", cutoff_utc)
    return "1970-01-01 00:00:00"


def _build_bind_in_clause(
    usernames: Sequence[str],
    prefix: str = "u",
    column: str | None = None,
) -> tuple[str, dict[str, str]]:
    """Build bind placeholders (chunked <= 900 items) with pure bind parameters and zero interpolation."""
    if not _BIND_PREFIX_RE.fullmatch(prefix):
        raise ValueError(f"Invalid bind parameter prefix: {prefix!r}")

    deduped: list[str] = []
    seen: set[str] = set()
    for raw in usernames:
        val = str(raw or "").strip()
        if not val or val in seen:
            continue
        seen.add(val)
        deduped.append(val)

    if not deduped:
        return ("1 = 0", {}) if column else ("NULL", {})

    binds: dict[str, str] = {}
    chunk_size = 900
    chunks = [deduped[i : i + chunk_size] for i in range(0, len(deduped), chunk_size)]

    if column is not None:
        if not re.fullmatch(r"\A[A-Za-z_][A-Za-z0-9_.]*\Z", column):
            raise ValueError(f"Invalid SQL column identifier: {column!r}")
        predicates: list[str] = []
        idx = 0
        for chunk in chunks:
            ph_list: list[str] = []
            for val in chunk:
                key = f"{prefix}{idx}"
                ph_list.append(f":{key}")
                binds[key] = val
                idx += 1
            predicates.append(f"{column} IN ({', '.join(ph_list)})")
        if len(predicates) == 1:
            return predicates[0], binds
        return f"({' OR '.join(predicates)})", binds

    if len(chunks) == 1:
        ph_list = []
        for idx, val in enumerate(chunks[0]):
            key = f"{prefix}{idx}"
            ph_list.append(f":{key}")
            binds[key] = val
        return ", ".join(ph_list), binds

    # Fallback when caller embeds result directly inside IN (...) for > 900 values
    subqueries: list[str] = []
    idx = 0
    for chunk in chunks:
        ph_list = []
        for val in chunk:
            key = f"{prefix}{idx}"
            ph_list.append(f":{key}")
            binds[key] = val
            idx += 1
        subqueries.append(f"SELECT COLUMN_VALUE FROM TABLE(SYS.ODCIVARCHAR2LIST({', '.join(ph_list)}))")
    return " UNION ALL ".join(subqueries), binds


def _build_trigger_ddl(table_owner: str) -> str:
    """Return SYS.TRG_PROTECT_NV DDL aligned with SYS_FREEPDB1.sql."""
    if table_owner not in ("SYSTEM", "SYS"):
        raise ValueError(f"Unexpected NV table owner: {table_owner!r}")
    return f"""
    CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV
    BEFORE INSERT OR UPDATE OR DELETE ON {table_owner}.NV
    FOR EACH ROW
    DECLARE
        PRAGMA AUTONOMOUS_TRANSACTION;
        v_user        VARCHAR2(50);
        v_max_allowed NUMBER(10,2);
    BEGIN
        v_user := UPPER(SYS_CONTEXT('USERENV', 'SESSION_USER'));

        IF v_user IN ('SYS', 'SYSTEM') THEN
            RETURN;
        END IF;

        IF DELETING THEN
            INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
            VALUES (v_user, 'UNAUTHORIZED_DELETE', 'Cố tình xóa nhân viên mã: ' || :OLD.manv);
            COMMIT;
            RAISE_APPLICATION_ERROR(-20001, 'IDS BLOCK: Ban khong duoc phep xoa du lieu nhan vien!');
        END IF;

        IF INSERTING THEN
            IF UPPER(TRIM(:NEW.manv)) = 'NV_TRAP'
               OR :NEW.luong IS NULL
               OR :NEW.luong <= 0
               OR :NEW.luong > 5000 THEN
                INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
                VALUES (
                    v_user,
                    'UNAUTHORIZED_DML_INTEGRITY',
                    'Từ chối INSERT vi phạm toàn vẹn dữ liệu: manv=' || NVL(:NEW.manv, 'NULL')
                    || ', luong=' || NVL(TO_CHAR(:NEW.luong), 'NULL')
                );
                COMMIT;
                RAISE_APPLICATION_ERROR(-20004, 'IDS BLOCK (ORA-20004): Tu choi INSERT vi pham tinh toan ven du lieu / luong bat thuong!');
            END IF;
        END IF;

        IF UPDATING('LUONG') THEN
            BEGIN
                SELECT max_allowed_luong
                INTO v_max_allowed
                FROM SYS.IDS_SALARY_BASELINES
                WHERE manv = :OLD.manv;
            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    v_max_allowed := NULL;
            END;

            IF :NEW.luong IS NULL
               OR :NEW.luong <= 0
               OR (:OLD.luong IS NOT NULL AND :NEW.luong > :OLD.luong * 1.5)
               OR (:OLD.luong IS NOT NULL AND :NEW.luong < :OLD.luong * 0.5)
               OR (v_max_allowed IS NOT NULL AND :NEW.luong > v_max_allowed)
               OR (:OLD.manv <> 'NV_TRAP' AND :NEW.luong > 5000) THEN
                INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
                VALUES (
                    v_user,
                    'ABNORMAL_SALARY_MODIFICATION',
                    'Thay đổi lương bất thường từ ' || NVL(TO_CHAR(:OLD.luong), 'NULL')
                    || ' lên ' || NVL(TO_CHAR(:NEW.luong), 'NULL')
                    || ' (manv: ' || :OLD.manv
                    || CASE WHEN v_max_allowed IS NOT NULL THEN ', trần tích lũy: ' || TO_CHAR(v_max_allowed) ELSE '' END
                    || ')'
                );
                COMMIT;
                RAISE_APPLICATION_ERROR(-20002, 'IDS BLOCK: Phat hien hanh vi gian lan thay doi luong vuot nguong hoac Salami Attack!');
            END IF;
        END IF;

        IF UPDATING('MANV') AND (:NEW.manv IS NULL OR :NEW.manv <> :OLD.manv) THEN
            INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
            VALUES (
                v_user,
                'UNAUTHORIZED_DML_INTEGRITY',
                'Cố tình thay đổi khóa chính MANV từ ' || :OLD.manv || ' thành ' || NVL(:NEW.manv, 'NULL')
            );
            COMMIT;
            RAISE_APPLICATION_ERROR(-20004, 'IDS BLOCK (ORA-20004): Khong duoc phep thay doi ma nhan vien (MANV)!');
        END IF;

        IF UPDATING('CMND') OR UPDATING('HOTEN') THEN
            IF :NEW.cmnd IS NULL
               OR NVL(LENGTH(TRIM(:NEW.cmnd)), 0) < 9
               OR :NEW.hoten IS NULL
               OR NVL(LENGTH(TRIM(:NEW.hoten)), 0) < 2
               OR NVL(:NEW.cmnd, '~') <> NVL(:OLD.cmnd, '~')
               OR NVL(:NEW.hoten, '~') <> NVL(:OLD.hoten, '~') THEN
                INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
                VALUES (
                    v_user,
                    'UNAUTHORIZED_DML_INTEGRITY',
                    'Cố tình xóa trắng hoặc giả mạo PII (CMND/HOTEN) của nhân viên mã: ' || :OLD.manv
                );
                COMMIT;
                RAISE_APPLICATION_ERROR(-20004, 'IDS BLOCK (ORA-20004): Khong duoc phep xoa trang hoac gia mao thong tin dinh danh (CMND/HOTEN)!');
            END IF;
        END IF;
    END;
    """


_FGA_HANDLER_DDL = """
CREATE OR REPLACE PROCEDURE SYS.IDS_FGA_TRAP_HANDLER(
    object_schema VARCHAR2,
    object_name   VARCHAR2,
    policy_name   VARCHAR2
) AS
    PRAGMA AUTONOMOUS_TRANSACTION;
    v_user VARCHAR2(100);
    v_sql  VARCHAR2(4000);
    v_type VARCHAR2(100) := 'HONEYTOKEN_TRAP_BLOCK';
BEGIN
    v_user := UPPER(SYS_CONTEXT('USERENV', 'SESSION_USER'));
    IF v_user IN ('SYS', 'SYSTEM') THEN
        RETURN;
    END IF;

    v_sql := SUBSTR(SYS_CONTEXT('USERENV', 'CURRENT_SQL'), 1, 2000);

    IF v_sql IS NOT NULL AND (
        REGEXP_LIKE(
            v_sql,
            '(^|[^A-Z0-9_])(OR([[:space:]]+\\(?|\\()[[:space:]]*(1[[:space:]]*=[[:space:]]*1|2[[:space:]]*=[[:space:]]*2)|OR[[:space:]]*\\(?[[:space:]]*''1''[[:space:]]*=[[:space:]]*''1''|UNION([[:space:]]+ALL)?[[:space:]]+SELECT)([^A-Z0-9_]|$)',
            'i'
        )
        OR REGEXP_LIKE(v_sql, '(--|/\\*)')
        OR REGEXP_LIKE(
            v_sql,
            '(^|[^A-Z0-9_])(DBMS_PIPE|DBMS_LOCK[[:space:]]*\\.[[:space:]]*SLEEP|UTL_HTTP|UTL_INADDR|UTL_FILE)([^A-Z0-9_]|$)',
            'i'
        )
    ) THEN
        v_type := 'SQL_INJECTION_BLOCK';
    END IF;

    INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
    VALUES (
        v_user,
        v_type,
        NVL(v_sql, 'Truy cap trai phep ban ghi bay NV_TRAP (' || policy_name || ')')
    );
    COMMIT;

    RAISE_APPLICATION_ERROR(
        -20003,
        'IDS ACTIVE BLOCK (ORA-20003): Phat hien hanh vi doc trom du lieu nhay cam / SQL Injection cham bay Honeytoken NV_TRAP! Truy van bi tu choi tuc thoi!'
    );
END;
"""


class OracleDbClient:
    """Thread-safe Oracle connection pool wrapper and UTC SQL repository."""

    def __init__(self, config: BridgeConfig) -> None:
        self.config = config
        self._pool_lock = threading.Lock()
        self._pool: oracledb.ConnectionPool | None = None

    def _ensure_client_mode(self) -> None:
        if self.config.oracle_client_mode != "thick":
            return
        with _CLIENT_INIT_LOCK:
            if not oracledb.is_thin_mode():
                return
            lib_dir = self.config.oracle_lib_dir or None
            logger.info("Initializing Oracle thick client (lib_dir=%s)", lib_dir or "<default>")
            oracledb.init_oracle_client(lib_dir=lib_dir)

    def _build_pool_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "min": 1,
            "max": 4,
            "increment": 1,
        }
        if self.config.oracle_os_auth:
            kwargs["externalauth"] = True
            if self.config.oracle_dsn:
                kwargs["dsn"] = self.config.oracle_dsn
        else:
            kwargs["user"] = self.config.oracle_user
            kwargs["password"] = self.config.oracle_password
            kwargs["dsn"] = self.config.oracle_dsn

        if self.config.oracle_auth_mode == "sysdba":
            kwargs["mode"] = oracledb.AUTH_MODE_SYSDBA
        return kwargs

    def _get_or_create_pool(self) -> oracledb.ConnectionPool:
        with self._pool_lock:
            if self._pool is None:
                self._ensure_client_mode()
                pool_kwargs = self._build_pool_kwargs()
                logger.info(
                    "Creating Oracle connection pool (dsn=%s, mode=%s, client=%s, os_auth=%s)",
                    self.config.oracle_dsn or "<external>",
                    self.config.oracle_auth_mode,
                    self.config.oracle_client_mode,
                    self.config.oracle_os_auth,
                )
                self._pool = oracledb.create_pool(**pool_kwargs)
            return self._pool

    @contextmanager
    def acquire(self) -> Iterator[tuple[oracledb.Connection, oracledb.Cursor]]:
        """Yield a pooled (conn, cur) pair and guarantee cursor close and pool release."""
        pool = self._get_or_create_pool()
        conn = pool.acquire()
        cur: oracledb.Cursor | None = None
        try:
            cur = conn.cursor()
            yield conn, cur
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception as exc:
                    logger.debug("Failed to close Oracle cursor cleanly: %s", exc)
            try:
                if hasattr(pool, "release"):
                    pool.release(conn)
                else:
                    conn.close()
            except Exception as exc:
                logger.warning("Failed releasing Oracle connection to pool (%s); closing directly.", exc)
                try:
                    conn.close()
                except Exception as close_exc:
                    logger.debug("Direct Oracle connection close also failed: %s", close_exc)

    def close(self) -> None:
        """Close the Oracle connection pool cleanly on shutdown."""
        with self._pool_lock:
            pool = self._pool
            self._pool = None
        if pool is None:
            return
        try:
            pool.close()
        except Exception as exc:
            logger.warning("Graceful pool.close() failed (%s); forcing close.", exc)
            try:
                pool.close(force=True)
            except Exception:
                logger.exception("Forced Oracle connection pool close failed.")

    @staticmethod
    def _build_bind_in_clause(
        usernames: Sequence[str],
        prefix: str = "u",
        column: str | None = None,
    ) -> tuple[str, dict[str, str]]:
        return _build_bind_in_clause(usernames, prefix=prefix, column=column)

    def get_oracle_utc_now_str(self, cur: Any) -> str:
        """Return current Oracle server timestamp in UTC formatted as YYYY-MM-DD HH24:MI:SS."""
        cur.execute("SELECT TO_CHAR(SYS_EXTRACT_UTC(SYSTIMESTAMP), 'YYYY-MM-DD HH24:MI:SS') FROM DUAL")
        row = cur.fetchone()
        if not row or not row[0]:
            raise RuntimeError("Oracle returned an empty UTC timestamp.")
        return str(row[0]).strip()

    def flush_audit_trail(self, cur: Any) -> bool:
        """Flush Oracle Unified Audit Trail buffers to disk."""
        last_exc: Exception | None = None
        for stmt in (
            "BEGIN DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL; END;",
            "BEGIN AUDSYS.DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL; END;",
            "BEGIN SYS.DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL; END;",
        ):
            try:
                cur.execute(stmt)
                return True
            except Exception as exc:
                last_exc = exc
                logger.debug("Audit trail flush variant failed (%s): %s", stmt, exc)
        logger.warning("Unable to flush unified audit trail via DBMS_AUDIT_MGMT: %s", last_exc)
        return False

    def fetch_rows_as_dicts(
        self,
        cur: Any,
        query: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a SQL query and normalize rows into uppercase-keyed dictionaries."""
        if params:
            cur.execute(query, params)
        else:
            cur.execute(query)
        if not cur.description:
            return []
        cols = [col[0] for col in cur.description]
        result: list[dict[str, Any]] = []
        for row in cur.fetchall():
            item: dict[str, Any] = {}
            for idx, val in enumerate(row):
                if hasattr(val, "read"):
                    val = val.read()
                if isinstance(val, str):
                    val = val.replace("\x00", "").strip()
                item[cols[idx]] = val if val is not None else ""
            result.append(item)
        return result

    def fetch_users(
        self,
        cur: Any,
        monitored_users: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch non-Oracle-maintained lab users and compute NV DML_STATUS without auto-granting."""
        cleaned_monitored = [
            str(u).strip().upper()
            for u in (monitored_users or ())
            if str(u or "").strip() and str(u).strip().upper() not in _EXCLUDED_SYSTEM_USERS
        ]
        excl_clause, excl_binds = _build_bind_in_clause(_EXCLUDED_SYSTEM_USERS, prefix="excl")
        params: dict[str, Any] = dict(excl_binds)

        if cleaned_monitored:
            mon_predicate, mon_binds = _build_bind_in_clause(
                cleaned_monitored,
                prefix="mon",
                column="username",
            )
            params.update(mon_binds)
            user_filter = f"(oracle_maintained = 'N' OR {mon_predicate})"
        else:
            user_filter = "oracle_maintained = 'N'"

        query_users = f"""
            SELECT username AS USERNAME,
                   account_status AS ACCOUNT_STATUS,
                   TO_CHAR(lock_date, 'YYYY-MM-DD HH24:MI:SS') AS LOCK_DATE
            FROM dba_users
            WHERE {user_filter}
              AND username NOT IN ({excl_clause})
            ORDER BY username
        """
        users = self.fetch_rows_as_dicts(cur, query_users, params)
        usernames = [str(u.get("USERNAME") or "").upper() for u in users if u.get("USERNAME")]
        priv_map = self._fetch_user_nv_privileges(cur, usernames)

        for u_row in users:
            uname = str(u_row.get("USERNAME") or "").upper()
            u_privs = priv_map.get(uname, set())
            has_dml = any(p in u_privs for p in ("INSERT", "UPDATE", "DELETE"))
            u_row["DML_STATUS"] = "FULL DML" if has_dml else "READ-ONLY"
            u_row["PRIVILEGES"] = ", ".join(sorted(u_privs)) if u_privs else "NONE"

        return users

    def _fetch_user_nv_privileges(
        self,
        cur: Any,
        usernames: Sequence[str],
    ) -> dict[str, set[str]]:
        """Query actual dba_tab_privs grants on SYS.NV / SYSTEM.NV without mutating grants."""
        priv_map: dict[str, set[str]] = {u: set() for u in usernames}
        if not usernames:
            return priv_map
        grantee_predicate, binds = _build_bind_in_clause(usernames, prefix="g", column="grantee")
        try:
            cur.execute(
                f"""
                SELECT grantee, privilege
                FROM dba_tab_privs
                WHERE table_name = 'NV'
                  AND owner IN ('SYSTEM', 'SYS')
                  AND {grantee_predicate}
                """,
                binds,
            )
            for grantee, priv in cur.fetchall():
                g_upper = str(grantee or "").upper()
                if g_upper in priv_map and priv:
                    priv_map[g_upper].add(str(priv).upper())
        except Exception as exc:
            logger.warning("Failed querying dba_tab_privs on NV: %s", exc)
        return priv_map

    def fetch_audit_rows(
        self,
        cur: Any,
        usernames: Sequence[str],
        cutoff_utc: str,
        limit: int = 250,
    ) -> list[dict[str, Any]]:
        """Fetch unified_audit_trail entries in UTC with bind parameters and scrubbed credentials."""
        clean_users = [str(u).strip().upper() for u in usernames if str(u or "").strip()]
        if not clean_users:
            return []

        user_predicate, params = _build_bind_in_clause(clean_users, prefix="u", column="dbusername")
        meta_clause, meta_binds = _build_bind_in_clause(_IDE_METADATA_OBJECTS, prefix="meta")
        query_params: dict[str, Any] = {
            **params,
            **meta_binds,
            "cutoff": _normalize_utc_cutoff(cutoff_utc),
            "lim": max(1, min(int(limit), 5000)),
        }

        query = f"""
            SELECT TO_CHAR(SYS_EXTRACT_UTC(event_timestamp), 'YYYY-MM-DD HH24:MI:SS') AS EVENT_TIMESTAMP,
                   dbusername AS DBUSERNAME,
                   action_name AS ACTION_NAME,
                   object_schema AS OBJECT_SCHEMA,
                   object_name AS OBJECT_NAME,
                   sql_text AS SQL_TEXT,
                   return_code AS RETURN_CODE,
                   os_username AS OS_USERNAME,
                   userhost AS USERHOST,
                   client_program_name AS CLIENT_PROGRAM_NAME,
                   audit_type AS AUDIT_TYPE,
                   fga_policy_name AS FGA_POLICY_NAME,
                   unified_audit_policies AS UNIFIED_AUDIT_POLICIES
            FROM unified_audit_trail
            WHERE {user_predicate}
              AND SYS_EXTRACT_UTC(event_timestamp) > TO_TIMESTAMP(:cutoff, 'YYYY-MM-DD HH24:MI:SS')
              AND NOT (
                action_name = 'SELECT'
                AND NVL(return_code, 0) = 0
                AND fga_policy_name IS NULL
                AND UPPER(NVL(object_schema, 'SYS')) IN ('SYS', 'PUBLIC')
                AND UPPER(NVL(object_name, 'NONE')) IN ({meta_clause})
                AND NOT REGEXP_LIKE(
                  NVL(sql_text, ' '),
                  '{_IDE_SQL_SUSPICIOUS_REGEX}',
                  'i'
                )
              )
            ORDER BY SYS_EXTRACT_UTC(event_timestamp) DESC
            FETCH FIRST :lim ROWS ONLY
        """
        rows = self.fetch_rows_as_dicts(cur, query, query_params)
        for row in rows:
            row["SQL_TEXT"] = sanitize_sql_credentials(str(row.get("SQL_TEXT") or ""))
        return rows

    def fetch_fga_rows(
        self,
        cur: Any,
        usernames: Sequence[str],
        cutoff_utc: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch FGA audit records in UTC without suppressing STAT_FUNC hits on FGA_HONEYTOKEN_TRAP."""
        clean_users = [str(u).strip().upper() for u in usernames if str(u or "").strip()]
        if not clean_users:
            return []

        user_predicate, params = _build_bind_in_clause(clean_users, prefix="u", column="dbusername")
        query_params: dict[str, Any] = {
            **params,
            "cutoff": _normalize_utc_cutoff(cutoff_utc),
            "lim": max(1, min(int(limit), 1000)),
        }

        query = f"""
            SELECT TO_CHAR(SYS_EXTRACT_UTC(event_timestamp), 'YYYY-MM-DD HH24:MI:SS') AS EVENT_TIMESTAMP,
                   dbusername AS DBUSERNAME,
                   action_name AS ACTION_NAME,
                   object_schema AS OBJECT_SCHEMA,
                   object_name AS OBJECT_NAME,
                   fga_policy_name AS FGA_POLICY_NAME,
                   audit_type AS AUDIT_TYPE,
                   sql_text AS SQL_TEXT,
                   os_username AS OS_USERNAME,
                   userhost AS USERHOST,
                   client_program_name AS CLIENT_PROGRAM_NAME,
                   return_code AS RETURN_CODE
            FROM unified_audit_trail
            WHERE {user_predicate}
              AND (audit_type = 'FineGrainedAudit' OR fga_policy_name IS NOT NULL)
              AND SYS_EXTRACT_UTC(event_timestamp) > TO_TIMESTAMP(:cutoff, 'YYYY-MM-DD HH24:MI:SS')
            ORDER BY SYS_EXTRACT_UTC(event_timestamp) DESC
            FETCH FIRST :lim ROWS ONLY
        """
        rows = self.fetch_rows_as_dicts(cur, query, query_params)
        for row in rows:
            row["SQL_TEXT"] = sanitize_sql_credentials(str(row.get("SQL_TEXT") or ""))
        return rows

    def fetch_failed_logons(
        self,
        cur: Any,
        usernames: Sequence[str],
        cutoff_utc: str,
        window_minutes: int = 15,
    ) -> list[dict[str, Any]]:
        """Fetch ORA-01017 failed logons in UTC grouped per (dbusername, userhost, os_username)."""
        clean_users = [str(u).strip().upper() for u in usernames if str(u or "").strip()]
        if not clean_users:
            return []

        user_predicate, params = _build_bind_in_clause(clean_users, prefix="u", column="dbusername")
        query_params: dict[str, Any] = {
            **params,
            "cutoff": _normalize_utc_cutoff(cutoff_utc),
            "window_minutes": max(1, int(window_minutes)),
        }

        query = f"""
            SELECT dbusername AS DBUSERNAME,
                   userhost AS USERHOST,
                   os_username AS OS_USERNAME,
                   COUNT(*) AS FAIL_COUNT,
                   MAX(TO_CHAR(SYS_EXTRACT_UTC(event_timestamp), 'YYYY-MM-DD HH24:MI:SS')) AS LAST_ATTEMPT,
                   MAX(client_program_name) AS CLIENT_PROGRAM_NAME
            FROM unified_audit_trail
            WHERE action_name = 'LOGON'
              AND return_code = 1017
              AND {user_predicate}
              AND SYS_EXTRACT_UTC(event_timestamp) > SYS_EXTRACT_UTC(SYSTIMESTAMP) - NUMTODSINTERVAL(:window_minutes, 'MINUTE')
              AND SYS_EXTRACT_UTC(event_timestamp) > TO_TIMESTAMP(:cutoff, 'YYYY-MM-DD HH24:MI:SS')
            GROUP BY dbusername, userhost, os_username
            ORDER BY FAIL_COUNT DESC, LAST_ATTEMPT DESC
        """
        return self.fetch_rows_as_dicts(cur, query, query_params)

    def fetch_trigger_alerts(
        self,
        cur: Any,
        cutoff_utc: str = "1970-01-01 00:00:00",
    ) -> list[dict[str, Any]]:
        """Fetch active block alerts from SYS.IDS_TRIGGER_ALERTS in UTC order."""
        norm_cutoff = _normalize_utc_cutoff(cutoff_utc)
        query = """
            SELECT alert_id AS ALERT_ID,
                   TO_CHAR(SYS_EXTRACT_UTC(event_time), 'YYYY-MM-DD HH24:MI:SS') AS EVENT_TIME,
                   db_user AS DB_USER,
                   attack_type AS ATTACK_TYPE,
                   details AS DETAILS
            FROM SYS.IDS_TRIGGER_ALERTS
            WHERE SYS_EXTRACT_UTC(event_time) > TO_TIMESTAMP(:cutoff, 'YYYY-MM-DD HH24:MI:SS')
            ORDER BY SYS_EXTRACT_UTC(event_time) DESC, alert_id DESC
        """
        rows = self.fetch_rows_as_dicts(cur, query, {"cutoff": norm_cutoff})
        for row in rows:
            row["DETAILS"] = sanitize_sql_credentials(str(row.get("DETAILS") or ""))
        return rows

    def fetch_employees(self, cur: Any) -> list[dict[str, Any]]:
        """Fetch employee records including NV_TRAP honeytoken from SYS.NV."""
        query = """
            SELECT manv AS MANV,
                   hoten AS HOTEN,
                   luong AS LUONG,
                   gioitinh AS GIOITINH,
                   cmnd AS CMND
            FROM SYS.NV
            ORDER BY CASE WHEN manv = 'NV_TRAP' THEN 1 ELSE 0 END, manv
        """
        return self.fetch_rows_as_dicts(cur, query)

    def verify_and_sync_defense_objects(self) -> dict[str, Any]:
        """Verify and synchronize triggers, FGA policies/handler, and unified audit policies."""
        errors: list[str] = []
        trigger_ok = False
        fga_ok = False
        audit_ok = False
        crypto_policy_ok = False

        try:
            with self.acquire() as (conn, cur):
                table_owner = self._resolve_nv_table_owner(cur, errors)
                trigger_ok = self._verify_and_sync_trigger(cur, conn, table_owner, errors)
                fga_ok = self._verify_and_sync_fga(cur, conn, table_owner, errors)
                audit_ok, crypto_policy_ok = self._verify_and_sync_audit_policies(
                    cur, conn, table_owner, errors
                )
        except Exception as exc:
            logger.exception("Failed connecting to Oracle while verifying defense objects.")
            errors.append(f"Oracle connection/verification failed: {exc}")

        return {
            "trigger_ok": trigger_ok,
            "fga_ok": fga_ok,
            "audit_ok": audit_ok,
            "crypto_policy_ok": crypto_policy_ok,
            "errors": errors,
        }

    def _resolve_nv_table_owner(self, cur: Any, errors: list[str]) -> str:
        try:
            cur.execute(
                """
                SELECT owner
                FROM dba_tables
                WHERE table_name = 'NV'
                  AND owner IN ('SYSTEM', 'SYS')
                ORDER BY DECODE(owner, 'SYSTEM', 1, 2)
                """
            )
            row = cur.fetchone()
            if row and row[0] in ("SYSTEM", "SYS"):
                return str(row[0])
            msg = "Physical table SYSTEM.NV / SYS.NV was not found in dba_tables."
            logger.warning(msg)
            errors.append(msg)
        except Exception as exc:
            logger.warning("Unable to inspect dba_tables for NV: %s", exc)
            errors.append(f"dba_tables check for NV failed: {exc}")
        return "SYSTEM"

    def _migrate_trigger_alerts_event_time_tz(
        self,
        cur: Any,
        conn: Any,
        errors: list[str],
    ) -> None:
        """Migrate legacy timezone-naive SYS.IDS_TRIGGER_ALERTS.event_time to TIMESTAMP WITH TIME ZONE."""
        try:
            cur.execute(
                """
                SELECT data_type
                FROM dba_tab_columns
                WHERE owner = 'SYS'
                  AND table_name = 'IDS_TRIGGER_ALERTS'
                  AND column_name = 'EVENT_TIME'
                """
            )
            col_row = cur.fetchone()
            if not col_row or not col_row[0]:
                return
            data_type = str(col_row[0]).upper()
            if "TIME ZONE" in data_type:
                return

            logger.info(
                "Migrating legacy SYS.IDS_TRIGGER_ALERTS.event_time (%s) to TIMESTAMP WITH TIME ZONE.",
                data_type,
            )
            migration_plsql = """
            DECLARE
                v_tz_col NUMBER := 0;
                v_max_id NUMBER := 0;
                v_ora_12988 EXCEPTION;
                PRAGMA EXCEPTION_INIT(v_ora_12988, -12988);
            BEGIN
                SELECT COUNT(*) INTO v_tz_col
                FROM dba_tab_columns
                WHERE owner = 'SYS'
                  AND table_name = 'IDS_TRIGGER_ALERTS'
                  AND column_name = 'EVENT_TIME_TZ';
                IF v_tz_col = 0 THEN
                    EXECUTE IMMEDIATE 'ALTER TABLE SYS.IDS_TRIGGER_ALERTS ADD (event_time_tz TIMESTAMP WITH TIME ZONE)';
                END IF;
                EXECUTE IMMEDIATE 'UPDATE SYS.IDS_TRIGGER_ALERTS SET event_time_tz = FROM_TZ(event_time, DBTIMEZONE)';
                COMMIT;
                BEGIN
                    EXECUTE IMMEDIATE 'ALTER TABLE SYS.IDS_TRIGGER_ALERTS DROP COLUMN event_time';
                    EXECUTE IMMEDIATE 'ALTER TABLE SYS.IDS_TRIGGER_ALERTS RENAME COLUMN event_time_tz TO event_time';
                    EXECUTE IMMEDIATE 'ALTER TABLE SYS.IDS_TRIGGER_ALERTS MODIFY (event_time DEFAULT SYSTIMESTAMP)';
                EXCEPTION
                    WHEN v_ora_12988 THEN
                        BEGIN
                            EXECUTE IMMEDIATE 'DROP TABLE SYS.IDS_TRIGGER_ALERTS_TZ_MIG PURGE';
                        EXCEPTION WHEN OTHERS THEN NULL;
                        END;
                        EXECUTE IMMEDIATE 'CREATE TABLE SYS.IDS_TRIGGER_ALERTS_TZ_MIG (alert_id NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY, event_time TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP, db_user VARCHAR2(50), attack_type VARCHAR2(100), details VARCHAR2(4000))';
                        EXECUTE IMMEDIATE 'INSERT INTO SYS.IDS_TRIGGER_ALERTS_TZ_MIG (alert_id, event_time, db_user, attack_type, details) SELECT alert_id, NVL(event_time_tz, FROM_TZ(event_time, DBTIMEZONE)), db_user, attack_type, details FROM SYS.IDS_TRIGGER_ALERTS';
                        COMMIT;
                        EXECUTE IMMEDIATE 'DROP TABLE SYS.IDS_TRIGGER_ALERTS PURGE';
                        EXECUTE IMMEDIATE 'ALTER TABLE SYS.IDS_TRIGGER_ALERTS_TZ_MIG RENAME TO IDS_TRIGGER_ALERTS';
                        EXECUTE IMMEDIATE 'SELECT NVL(MAX(alert_id), 0) FROM SYS.IDS_TRIGGER_ALERTS' INTO v_max_id;
                        IF v_max_id > 0 THEN
                            EXECUTE IMMEDIATE 'ALTER TABLE SYS.IDS_TRIGGER_ALERTS MODIFY (alert_id GENERATED ALWAYS AS IDENTITY (START WITH ' || TO_CHAR(v_max_id + 1) || '))';
                        ELSE
                            EXECUTE IMMEDIATE 'ALTER TABLE SYS.IDS_TRIGGER_ALERTS MODIFY (alert_id GENERATED ALWAYS AS IDENTITY)';
                        END IF;
                END;
            END;
            """
            cur.execute(migration_plsql)
            conn.commit()
        except Exception as exc:
            logger.warning(
                "Failed migrating SYS.IDS_TRIGGER_ALERTS.event_time to TIMESTAMP WITH TIME ZONE: %s",
                exc,
                exc_info=True,
            )
            errors.append(f"IDS_TRIGGER_ALERTS.event_time migration failed: {exc}")
            try:
                conn.rollback()
            except Exception:
                pass

    def _verify_and_sync_trigger(
        self,
        cur: Any,
        conn: Any,
        table_owner: str,
        errors: list[str],
    ) -> bool:
        try:
            cur.execute(
                """
                SELECT table_name
                FROM dba_tables
                WHERE owner = 'SYS'
                  AND table_name IN ('IDS_TRIGGER_ALERTS', 'IDS_SALARY_BASELINES')
                """
            )
            existing_tables = {str(r[0]).upper() for r in cur.fetchall()}

            if "IDS_TRIGGER_ALERTS" not in existing_tables:
                cur.execute(
                    """
                    CREATE TABLE SYS.IDS_TRIGGER_ALERTS (
                        alert_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        event_time TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP,
                        db_user VARCHAR2(50),
                        attack_type VARCHAR2(100),
                        details VARCHAR2(4000)
                    )
                    """
                )
                existing_tables.add("IDS_TRIGGER_ALERTS")
            else:
                self._migrate_trigger_alerts_event_time_tz(cur, conn, errors)

            if "IDS_SALARY_BASELINES" not in existing_tables:
                cur.execute(
                    """
                    CREATE TABLE SYS.IDS_SALARY_BASELINES (
                        manv VARCHAR2(10) PRIMARY KEY,
                        base_luong NUMBER(10,2) NOT NULL,
                        max_allowed_luong NUMBER(10,2) NOT NULL,
                        updated_at TIMESTAMP DEFAULT SYSTIMESTAMP
                    )
                    """
                )
                cur.execute(
                    f"""
                    INSERT INTO SYS.IDS_SALARY_BASELINES (manv, base_luong, max_allowed_luong)
                    SELECT manv, luong, luong * 1.5
                    FROM {table_owner}.NV
                    WHERE manv IN ('NV1', 'NV2', 'NV3', 'NV4')
                    """
                )
                conn.commit()
                existing_tables.add("IDS_SALARY_BASELINES")

            cur.execute(
                """
                SELECT t.status, o.status
                FROM dba_triggers t
                LEFT JOIN dba_objects o
                  ON o.owner = t.owner
                 AND o.object_name = t.trigger_name
                 AND o.object_type = 'TRIGGER'
                WHERE t.owner = 'SYS'
                  AND t.trigger_name = 'TRG_PROTECT_NV'
                """
            )
            trig_row = cur.fetchone()
            trig_enabled = bool(trig_row and str(trig_row[0]).upper() == "ENABLED")
            trig_valid = bool(trig_row and str(trig_row[1] or "").upper() == "VALID")

            needs_hoten_upgrade = False
            if trig_row and trig_valid:
                cur.execute(
                    """
                    SELECT text
                    FROM dba_source
                    WHERE owner = 'SYS'
                      AND name = 'TRG_PROTECT_NV'
                      AND type = 'TRIGGER'
                    ORDER BY line
                    """
                )
                trig_src = "\n".join(str(r[0] or "") for r in cur.fetchall())
                if trig_src and "NVL(:NEW.HOTEN" not in trig_src.upper():
                    needs_hoten_upgrade = True

            if not trig_row or not trig_valid or needs_hoten_upgrade:
                cur.execute(_build_trigger_ddl(table_owner))
                conn.commit()
            if trig_row and not trig_enabled:
                cur.execute("ALTER TRIGGER SYS.TRG_PROTECT_NV ENABLE")
                conn.commit()

            cur.execute(
                """
                SELECT t.status, o.status
                FROM dba_triggers t
                JOIN dba_objects o
                  ON o.owner = t.owner
                 AND o.object_name = t.trigger_name
                 AND o.object_type = 'TRIGGER'
                WHERE t.owner = 'SYS'
                  AND t.trigger_name = 'TRG_PROTECT_NV'
                """
            )
            final_row = cur.fetchone()
            ok = bool(
                "IDS_TRIGGER_ALERTS" in existing_tables
                and final_row
                and str(final_row[0]).upper() == "ENABLED"
                and str(final_row[1]).upper() == "VALID"
            )
            if not ok:
                errors.append("SYS.TRG_PROTECT_NV or SYS.IDS_TRIGGER_ALERTS is missing/disabled/invalid.")
            return ok
        except Exception as exc:
            logger.warning("Trigger verification/sync failed: %s", exc, exc_info=True)
            errors.append(f"Trigger verification/sync failed: {exc}")
            return False

    def _verify_and_sync_fga(
        self,
        cur: Any,
        conn: Any,
        table_owner: str,
        errors: list[str],
    ) -> bool:
        try:
            cur.execute(
                """
                SELECT status
                FROM dba_objects
                WHERE owner = 'SYS'
                  AND object_name = 'IDS_FGA_TRAP_HANDLER'
                  AND object_type = 'PROCEDURE'
                """
            )
            proc_row = cur.fetchone()
            proc_valid = bool(proc_row and str(proc_row[0]).upper() == "VALID")

            cur.execute(
                """
                SELECT text
                FROM dba_source
                WHERE owner = 'SYS'
                  AND name = 'IDS_FGA_TRAP_HANDLER'
                  AND type = 'PROCEDURE'
                ORDER BY line
                """
            )
            handler_src = "\n".join(str(r[0] or "") for r in cur.fetchall())
            has_legacy_bug = bool(
                not handler_src
                or "\\b" in handler_src
                or "COUNT|SUM|AVG" in handler_src.upper()
            )

            if not proc_valid or has_legacy_bug:
                logger.info("Deploying/updating SYS.IDS_FGA_TRAP_HANDLER aligned with SYS_FREEPDB1.sql")
                cur.execute(_FGA_HANDLER_DDL)
                conn.commit()

            cur.execute(
                """
                SELECT object_schema, policy_name, enabled, handler_module
                FROM dba_audit_policies
                WHERE object_name = 'NV'
                  AND policy_name IN ('FGA_HONEYTOKEN_TRAP', 'FGA_HIGH_SALARY_ACCESS')
                """
            )
            existing_fga = {
                str(r[1]).upper(): {
                    "schema": str(r[0]).upper(),
                    "enabled": str(r[2]).upper(),
                    "handler": str(r[3] or "").upper(),
                }
                for r in cur.fetchall()
            }

            trap_pol = existing_fga.get("FGA_HONEYTOKEN_TRAP")
            if (
                not trap_pol
                or trap_pol["schema"] != table_owner
                or trap_pol["handler"] != "IDS_FGA_TRAP_HANDLER"
            ):
                if trap_pol:
                    try:
                        cur.execute(
                            "BEGIN DBMS_FGA.DROP_POLICY(object_schema => :sch, object_name => 'NV', policy_name => 'FGA_HONEYTOKEN_TRAP'); END;",
                            {"sch": trap_pol["schema"]},
                        )
                    except Exception as drop_exc:
                        logger.debug("Drop FGA_HONEYTOKEN_TRAP failed: %s", drop_exc)
                cur.execute(
                    """
                    BEGIN
                        DBMS_FGA.ADD_POLICY(
                            object_schema   => :sch,
                            object_name     => 'NV',
                            policy_name     => 'FGA_HONEYTOKEN_TRAP',
                            audit_condition => 'manv = ''NV_TRAP''',
                            audit_column    => NULL,
                            handler_schema  => 'SYS',
                            handler_module  => 'IDS_FGA_TRAP_HANDLER',
                            statement_types => 'SELECT, UPDATE, DELETE',
                            enable          => TRUE
                        );
                    END;
                    """,
                    {"sch": table_owner},
                )
            elif trap_pol["enabled"] != "YES":
                cur.execute(
                    "BEGIN DBMS_FGA.ENABLE_POLICY(object_schema => :sch, object_name => 'NV', policy_name => 'FGA_HONEYTOKEN_TRAP', enable => TRUE); END;",
                    {"sch": table_owner},
                )

            sal_pol = existing_fga.get("FGA_HIGH_SALARY_ACCESS")
            if not sal_pol or sal_pol["schema"] != table_owner:
                if sal_pol:
                    try:
                        cur.execute(
                            "BEGIN DBMS_FGA.DROP_POLICY(object_schema => :sch, object_name => 'NV', policy_name => 'FGA_HIGH_SALARY_ACCESS'); END;",
                            {"sch": sal_pol["schema"]},
                        )
                    except Exception as drop_exc:
                        logger.debug("Drop FGA_HIGH_SALARY_ACCESS failed: %s", drop_exc)
                cur.execute(
                    """
                    BEGIN
                        DBMS_FGA.ADD_POLICY(
                            object_schema     => :sch,
                            object_name       => 'NV',
                            policy_name       => 'FGA_HIGH_SALARY_ACCESS',
                            audit_condition   => NULL,
                            audit_column      => 'LUONG, CMND',
                            statement_types   => 'SELECT, UPDATE, DELETE',
                            enable            => TRUE,
                            audit_column_opts => DBMS_FGA.ANY_COLUMNS
                        );
                    END;
                    """,
                    {"sch": table_owner},
                )
            elif sal_pol["enabled"] != "YES":
                cur.execute(
                    "BEGIN DBMS_FGA.ENABLE_POLICY(object_schema => :sch, object_name => 'NV', policy_name => 'FGA_HIGH_SALARY_ACCESS', enable => TRUE); END;",
                    {"sch": table_owner},
                )

            conn.commit()

            cur.execute(
                """
                SELECT status
                FROM dba_objects
                WHERE owner = 'SYS'
                  AND object_name = 'IDS_FGA_TRAP_HANDLER'
                  AND object_type = 'PROCEDURE'
                """
            )
            final_proc = cur.fetchone()
            cur.execute(
                """
                SELECT policy_name, enabled, handler_module
                FROM dba_audit_policies
                WHERE object_schema = :sch
                  AND object_name = 'NV'
                  AND policy_name IN ('FGA_HONEYTOKEN_TRAP', 'FGA_HIGH_SALARY_ACCESS')
                """,
                {"sch": table_owner},
            )
            final_fga = {
                str(r[0]).upper(): (str(r[1]).upper(), str(r[2] or "").upper())
                for r in cur.fetchall()
            }
            trap_state = final_fga.get("FGA_HONEYTOKEN_TRAP")
            sal_state = final_fga.get("FGA_HIGH_SALARY_ACCESS")
            ok = bool(
                final_proc
                and str(final_proc[0]).upper() == "VALID"
                and trap_state == ("YES", "IDS_FGA_TRAP_HANDLER")
                and sal_state is not None
                and sal_state[0] == "YES"
            )
            if not ok:
                errors.append("FGA handler or policies (FGA_HONEYTOKEN_TRAP / FGA_HIGH_SALARY_ACCESS) unhealthy.")
            return ok
        except Exception as exc:
            logger.warning("FGA verification/sync failed: %s", exc, exc_info=True)
            errors.append(f"FGA verification/sync failed: {exc}")
            return False

    def _verify_and_sync_audit_policies(
        self,
        cur: Any,
        conn: Any,
        table_owner: str,
        errors: list[str],
    ) -> tuple[bool, bool]:
        try:
            pol_in, pol_binds = _build_bind_in_clause(_ALL_AUDIT_POLICIES, prefix="pol")
            cur.execute(
                f"SELECT DISTINCT policy_name FROM audit_unified_policies WHERE policy_name IN ({pol_in})",
                pol_binds,
            )
            defined_policies = {str(r[0]).upper() for r in cur.fetchall()}

            enabled_map = self._query_enabled_audit_policies(cur, pol_in, pol_binds)
            existing_monitored = self._query_existing_monitored_users(cur)

            policy_create_ddls: dict[str, tuple[str, ...]] = {
                "IDS_LOGON_POL": ("CREATE AUDIT POLICY ids_logon_pol ACTIONS LOGON, LOGOFF",),
                "IDS_DDL_POL": (
                    "CREATE AUDIT POLICY ids_ddl_pol ACTIONS CREATE TABLE, DROP TABLE, ALTER TABLE, TRUNCATE TABLE",
                ),
                "IDS_DML_NV_POL": (
                    f"CREATE AUDIT POLICY ids_dml_nv_pol ACTIONS SELECT, INSERT, UPDATE, DELETE ON {table_owner}.NV",
                ),
                "IDS_PRIV_ABUSE_POL": (
                    "CREATE AUDIT POLICY ids_priv_abuse_pol ACTIONS GRANT, REVOKE, CREATE USER, ALTER USER, DROP USER, ALTER SYSTEM, SET ROLE",
                ),
                "IDS_SECURITY_VIOLATIONS_POL": (
                    "CREATE AUDIT POLICY ids_security_violations_pol ACTIONS ALTER DATABASE, AUDIT, NOAUDIT",
                ),
                "IDS_CRYPTO_KEY_POL": (
                    "CREATE AUDIT POLICY ids_crypto_key_pol ACTIONS ADMINISTER KEY MANAGEMENT, SELECT ON SYS.V_$ENCRYPTION_KEYS, SELECT ON SYS.V_$ENCRYPTION_WALLET, SELECT ON SYS.ENC$, EXECUTE ON SYS.DBMS_CRYPTO",
                    "CREATE AUDIT POLICY ids_crypto_key_pol ACTIONS ADMINISTER KEY MANAGEMENT",
                ),
            }

            for pol_name in _ALL_AUDIT_POLICIES:
                if pol_name not in defined_policies:
                    self._create_audit_policy(cur, pol_name, policy_create_ddls[pol_name], errors)

                entities = enabled_map.get(pol_name, set())
                covered = "ALL USERS" in entities or (
                    bool(existing_monitored) and all(u in entities for u in existing_monitored)
                )
                if not covered:
                    self._enable_audit_policy(cur, pol_name, existing_monitored, errors)

            conn.commit()
            final_enabled = self._query_enabled_audit_policies(cur, pol_in, pol_binds)

            def _is_policy_healthy(pol_name: str) -> bool:
                entities = final_enabled.get(pol_name, set())
                if "ALL USERS" in entities:
                    return True
                return bool(existing_monitored) and all(u in entities for u in existing_monitored)

            core_statuses = {p: _is_policy_healthy(p) for p in _CORE_AUDIT_POLICIES}
            missing_core = [p for p, healthy in core_statuses.items() if not healthy]
            if missing_core:
                errors.append(f"Unified audit policies not enabled: {', '.join(missing_core)}")
            audit_ok = not missing_core

            crypto_ok = _is_policy_healthy(_CRYPTO_AUDIT_POLICY)
            if not crypto_ok:
                errors.append(f"Unified audit policy {_CRYPTO_AUDIT_POLICY} is not enabled.")

            return audit_ok, crypto_ok
        except Exception as exc:
            logger.warning("Unified audit policy verification failed: %s", exc, exc_info=True)
            errors.append(f"Unified audit policy verification failed: {exc}")
            return False, False

    def _query_enabled_audit_policies(
        self,
        cur: Any,
        pol_in: str,
        pol_binds: dict[str, str],
    ) -> dict[str, set[str]]:
        cur.execute(
            f"""
            SELECT policy_name, entity_name
            FROM audit_unified_enabled_policies
            WHERE policy_name IN ({pol_in})
            """,
            pol_binds,
        )
        enabled_map: dict[str, set[str]] = {}
        for pol_name, entity_name in cur.fetchall():
            p_upper = str(pol_name or "").upper()
            e_upper = str(entity_name or "").upper()
            if p_upper:
                enabled_map.setdefault(p_upper, set()).add(e_upper)
        return enabled_map

    def _query_existing_monitored_users(self, cur: Any) -> list[str]:
        candidates = [
            str(u).strip().upper()
            for u in self.config.monitored_users
            if _ORACLE_IDENTIFIER_RE.fullmatch(str(u or "").strip().upper())
            and str(u).strip().upper() not in _EXCLUDED_SYSTEM_USERS
        ]
        if not candidates:
            return []
        pred, binds = _build_bind_in_clause(candidates, prefix="mu", column="username")
        cur.execute(f"SELECT username FROM dba_users WHERE {pred}", binds)
        return [str(r[0]).upper() for r in cur.fetchall() if r and r[0]]

    def _create_audit_policy(
        self,
        cur: Any,
        pol_name: str,
        ddl_candidates: tuple[str, ...],
        errors: list[str],
    ) -> None:
        last_exc: Exception | None = None
        for ddl in ddl_candidates:
            try:
                cur.execute(ddl)
                if pol_name == "IDS_CRYPTO_KEY_POL" and "V_$ENCRYPTION_KEYS" not in ddl:
                    for action_sql in (
                        "ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS SELECT ON SYS.V_$ENCRYPTION_KEYS",
                        "ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS SELECT ON SYS.V_$ENCRYPTION_WALLET",
                        "ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS SELECT ON SYS.ENC$",
                        "ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS EXECUTE ON SYS.DBMS_CRYPTO",
                    ):
                        try:
                            cur.execute(action_sql)
                        except Exception as sub_exc:
                            logger.warning("Failed adding crypto audit action (%s): %s", action_sql, sub_exc)
                            errors.append(f"{pol_name} partial action failed ({action_sql}): {sub_exc}")
                return
            except Exception as exc:
                last_exc = exc
                logger.debug("Audit policy creation attempt failed for %s: %s", pol_name, exc)
        if last_exc is not None:
            logger.warning("Failed creating audit policy %s: %s", pol_name, last_exc)
            errors.append(f"Failed creating audit policy {pol_name}: {last_exc}")

    def _enable_audit_policy(
        self,
        cur: Any,
        pol_name: str,
        monitored_users: Sequence[str],
        errors: list[str],
    ) -> None:
        try:
            cur.execute(f"AUDIT POLICY {pol_name.lower()}")
            return
        except Exception as global_exc:
            logger.debug("Global AUDIT POLICY %s failed (%s); trying monitored users.", pol_name, global_exc)
            if not monitored_users:
                errors.append(f"Failed enabling audit policy {pol_name}: {global_exc}")
                return

        for uname in monitored_users:
            if not _ORACLE_IDENTIFIER_RE.fullmatch(uname):
                continue
            try:
                cur.execute(
                    f"BEGIN EXECUTE IMMEDIATE 'AUDIT POLICY {pol_name.lower()} BY ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u); END;",
                    {"u": uname},
                )
            except Exception as user_exc:
                logger.warning("Failed enabling audit policy %s for %s: %s", pol_name, uname, user_exc)
                errors.append(f"Failed enabling audit policy {pol_name} by {uname}: {user_exc}")
