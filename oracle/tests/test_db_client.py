"""Unit and security tests for oracle.db_client (UTC, SQL whitelist, binds, and trigger TZ sync)."""

from __future__ import annotations

import os
import re
import sys
import unittest
from typing import Any, Callable
from unittest.mock import patch

try:
    from oracle import db_client
    from oracle.config import BridgeConfig
    from oracle.db_client import OracleDbClient, _build_bind_in_clause, sanitize_sql_credentials
except ImportError:  # pragma: no cover - direct execution inside oracle/
    _ORACLE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _ORACLE_DIR not in sys.path:
        sys.path.insert(0, _ORACLE_DIR)
    import db_client
    from config import BridgeConfig
    from db_client import OracleDbClient, _build_bind_in_clause, sanitize_sql_credentials

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_POLICY_PATH = os.path.join(_REPO_ROOT, "shared", "detection_policy.json")


def _make_test_config() -> BridgeConfig:
    return BridgeConfig(
        oracle_user="sys",
        oracle_password="",
        oracle_dsn="localhost:1521/FREEPDB1",
        oracle_auth_mode="sysdba",
        oracle_os_auth=True,
        oracle_client_mode="thin",
        oracle_lib_dir="",
        bridge_host="127.0.0.1",
        bridge_port=8050,
        dashboard_url="http://localhost:3000",
        bridge_api_token="unit-test-token",
        poll_interval_sec=2.0,
        monitored_users=("U1", "U2", "U3", "U4"),
        policy_path=_POLICY_PATH,
        state_file=os.path.join(_REPO_ROOT, "oracle", ".ids_state.json"),
        max_request_body_bytes=1048576,
    )


class FakeCursor:
    """Fake Oracle cursor recording SQL statements and bind parameters."""

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], tuple[list[tuple[str, ...]], list[tuple[Any, ...]]]]
        | None = None,
    ) -> None:
        self.executed: list[tuple[str, dict[str, Any] | None]] = []
        self._responder = responder
        self.description: list[tuple[str, ...]] = []
        self._rows: list[tuple[Any, ...]] = []
        self.closed = False

    def execute(self, query: str, params: dict[str, Any] | None = None) -> None:
        self.executed.append((query, dict(params) if params is not None else None))
        if self._responder is not None:
            desc, rows = self._responder(query, params)
            self.description = list(desc)
            self._rows = list(rows)
        else:
            self.description = []
            self._rows = []

    def fetchall(self) -> list[tuple[Any, ...]]:
        rows = list(self._rows)
        self._rows = []
        return rows

    def fetchone(self) -> tuple[Any, ...] | None:
        if not self._rows:
            return None
        return self._rows.pop(0)

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    """Fake Oracle connection tracking commits, rollbacks, and cursor acquisition."""

    def __init__(self, cur: FakeCursor) -> None:
        self._cur = cur
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self) -> FakeCursor:
        return self._cur

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


class FakePool:
    """Fake Oracle connection pool tracking acquire, release, and close calls."""

    def __init__(self, conn: FakeConnection) -> None:
        self._conn = conn
        self.acquired = 0
        self.released: list[FakeConnection] = []
        self.closed = False

    def acquire(self) -> FakeConnection:
        self.acquired += 1
        return self._conn

    def release(self, conn: FakeConnection) -> None:
        self.released.append(conn)

    def close(self, force: bool = False) -> None:
        self.closed = True


class TestBindInClauseAndSanitization(unittest.TestCase):
    """Verify ORA-01795 bind chunking, identifier checks, and credential scrubbing."""

    def test_build_bind_in_clause_chunks_over_900_usernames_with_column(self) -> None:
        users = [f"LAB_USER_{i}" for i in range(1950)]
        clause, binds = _build_bind_in_clause(users, prefix="u", column="dbusername")

        self.assertEqual(len(binds), 1950)
        self.assertEqual(binds["u0"], "LAB_USER_0")
        self.assertEqual(binds["u1949"], "LAB_USER_1949")
        self.assertNotIn("LAB_USER_", clause)

        in_groups = re.findall(r"dbusername IN \(([^)]+)\)", clause)
        self.assertEqual(len(in_groups), 3)
        chunk_sizes = [len(group.split(",")) for group in in_groups]
        self.assertEqual(chunk_sizes, [900, 900, 150])
        self.assertTrue(all(size <= 900 for size in chunk_sizes))
        self.assertIn(" OR ", clause)

    def test_build_bind_in_clause_chunks_over_900_without_column(self) -> None:
        users = [f"U_{i}" for i in range(950)]
        clause, binds = _build_bind_in_clause(users, prefix="u", column=None)

        self.assertEqual(len(binds), 950)
        self.assertNotIn("U_0", clause)
        self.assertEqual(clause.count("SYS.ODCIVARCHAR2LIST("), 2)
        self.assertIn(" UNION ALL ", clause)

    def test_build_bind_in_clause_dedup_empty_and_validation(self) -> None:
        clause, binds = _build_bind_in_clause([" U1 ", "", "U1", "U2"], prefix="m", column="owner")
        self.assertEqual(clause, "owner IN (:m0, :m1)")
        self.assertEqual(binds, {"m0": "U1", "m1": "U2"})

        empty_clause, empty_binds = _build_bind_in_clause(["", "   "], prefix="u", column="dbusername")
        self.assertEqual(empty_clause, "1 = 0")
        self.assertEqual(empty_binds, {})

        with self.assertRaises(ValueError):
            _build_bind_in_clause(["U1"], prefix="bad-prefix", column="dbusername")
        with self.assertRaises(ValueError):
            _build_bind_in_clause(["U1"], prefix="u", column="dbusername; DROP TABLE nv")

    def test_sanitize_sql_credentials_scrubs_password_patterns(self) -> None:
        samples = [
            ('ALTER USER U1 IDENTIFIED BY "Secret!123"', "ALTER USER U1 IDENTIFIED BY ***"),
            ("CREATE USER U5 IDENTIFIED BY Pass1234", "CREATE USER U5 IDENTIFIED BY ***"),
            ("ALTER USER U1 IDENTIFIED BY OldPwd1 REPLACE NewPwd2", "ALTER USER U1 IDENTIFIED BY *** REPLACE ***"),
            ("CONN U1/MySecret@localhost:1521/FREEPDB1", "CONN U1/***@localhost:1521/FREEPDB1"),
            ('CONNECT U2/"Quoted$Pwd"@FREEPDB1', "CONNECT U2/***@FREEPDB1"),
            ("SET PASSWORD=TopSecret123", "SET PASSWORD=***"),
        ]
        for raw, expected in samples:
            self.assertEqual(sanitize_sql_credentials(raw), expected)


class TestFetchAuditRows(unittest.TestCase):
    """Verify fetch_audit_rows IDE whitelist hardening, bind safety, and credential scrubbing."""

    def setUp(self) -> None:
        self.client = OracleDbClient(_make_test_config())

    def test_fetch_audit_rows_sql_predicate_not_blanket_excluding_and_regex_safe(self) -> None:
        cur = FakeCursor()
        self.client.fetch_audit_rows(cur, ["U1", "U2"], "2026-11-22 10:00:00", limit=200)

        self.assertEqual(len(cur.executed), 1)
        query, params = cur.executed[0]
        assert params is not None

        # Must NOT blanket-exclude metadata object names
        self.assertNotRegex(query, r"AND\s+NVL\(object_name,\s*'NONE'\)\s+NOT\s+IN\s*\(")

        # Must enforce strict benign-IDE conjunction before excluding any row
        self.assertIn("AND NOT (", query)
        self.assertIn("action_name = 'SELECT'", query)
        self.assertIn("NVL(return_code, 0) = 0", query)
        self.assertIn("fga_policy_name IS NULL", query)
        self.assertIn("UPPER(NVL(object_schema, 'SYS')) IN ('SYS', 'PUBLIC')", query)
        self.assertIn("IN (:meta0", query)
        self.assertIn("AND NOT REGEXP_LIKE(", query)

        # Extract the Oracle POSIX ERE pattern inside REGEXP_LIKE and verify constraints
        match = re.search(
            r"NOT\s+REGEXP_LIKE\(\s*NVL\(sql_text,\s*' '\),\s*'([^']+)',\s*'i'\s*\)",
            query,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "Expected literal POSIX ERE pattern inside NOT REGEXP_LIKE")
        assert match is not None
        ora_pattern = match.group(1)

        self.assertNotIn(r"\b", ora_pattern)
        self.assertLessEqual(len(ora_pattern.encode("utf-8")), 512)

        # Verify POSIX ERE pattern catches attack queries targeting DUAL/ALL_* while ignoring benign IDE SQL
        compiled = re.compile(ora_pattern, re.IGNORECASE)
        attack_sqls = [
            "SELECT DBMS_LOCK.SLEEP(5) FROM DUAL",
            "SELECT UTL_FILE.FOPEN('/tmp', 'x', 'r') FROM DUAL",
            "SELECT UTL_HTTP.REQUEST('http://evil.local') FROM DUAL",
            "SELECT UTL_INADDR.GET_HOST_ADDRESS FROM DUAL",
            "SELECT DBMS_CRYPTO.HASH(UTL_I18N.STRING_TO_RAW('a', 'AL32UTF8'), 2) FROM DUAL",
            "SELECT DBMS_PIPE.RECEIVE_MESSAGE('p', 5) FROM DUAL",
            "SELECT DBMS_LDAP.INIT('10.0.0.1', 389) FROM DUAL",
            "SELECT * FROM ALL_USERS UNION SELECT manv, hoten, cmnd FROM SYS.NV",
            "SELECT 1 FROM DUAL WHERE 1=1 OR 2=2",
            "SELECT 1 FROM DUAL -- sql comment",
            "SELECT /*+ hint */ 1 FROM DUAL",
            "SELECT XMLTYPE('<a/>') FROM DUAL",
            "SELECT EXTRACTVALUE(doc, '/a') FROM DUAL",
            "SELECT EXECUTE IMMEDIATE 'DROP TABLE NV' FROM DUAL",
            "SELECT * FROM SYS.V$ENCRYPTION_KEYS, DUAL",
            "SELECT * FROM SYS.ENC$, DUAL",
            "SELECT 'NV_TRAP' FROM DUAL",
        ]
        for sql in attack_sqls:
            self.assertIsNotNone(compiled.search(sql), f"Attack SQL must match REGEXP_LIKE: {sql}")

        benign_ide_sqls = [
            "SELECT USER FROM DUAL",
            "SELECT 1 FROM DUAL",
            "SELECT * FROM ALL_OBJECTS WHERE OWNER = 'U1'",
            "SELECT * FROM V$VERSION",
            "SELECT OBJECT_NAME FROM ALL_TABLES ORDER BY OBJECT_NAME",
            "SELECT DBMS_APPLICATION_INFO.READ_MODULE FROM DUAL",
            "SELECT 'VENDOR' FROM DUAL",
        ]
        for sql in benign_ide_sqls:
            self.assertIsNone(compiled.search(sql), f"Benign IDE SQL unexpectedly matched: {sql}")

    def test_fetch_audit_rows_uses_pure_bind_variables_and_scrubs_credentials(self) -> None:
        hostile_user = "U1' OR '1'='1"
        cols = [
            ("EVENT_TIMESTAMP",),
            ("DBUSERNAME",),
            ("ACTION_NAME",),
            ("OBJECT_SCHEMA",),
            ("OBJECT_NAME",),
            ("SQL_TEXT",),
            ("RETURN_CODE",),
            ("OS_USERNAME",),
            ("USERHOST",),
            ("CLIENT_PROGRAM_NAME",),
            ("AUDIT_TYPE",),
            ("FGA_POLICY_NAME",),
            ("UNIFIED_AUDIT_POLICIES",),
        ]
        returned_rows = [
            (
                "2026-11-22 10:05:00",
                "U1",
                "ALTER USER",
                "SYS",
                "U2",
                "ALTER USER U2 IDENTIFIED BY SuperSecret99!",
                0,
                "pc",
                "LAPTOP-R03ORTGV",
                "sqlplus.exe",
                "Standard",
                None,
                "IDS_PRIV_ABUSE_POL",
            ),
            (
                "2026-11-22 10:06:00",
                "U1",
                "SELECT",
                "SYS",
                "DUAL",
                "CONNECT U1/SecretPass@FREEPDB1",
                0,
                "pc",
                "LAPTOP-R03ORTGV",
                "sqlplus.exe",
                "Standard",
                None,
                "",
            ),
        ]
        cur = FakeCursor(responder=lambda _q, _p: (cols, returned_rows))
        rows = self.client.fetch_audit_rows(
            cur,
            [hostile_user],
            "2026-11-22T09:00:00Z",
            limit=120,
        )

        self.assertEqual(len(cur.executed), 1)
        query, params = cur.executed[0]
        assert params is not None

        self.assertNotIn(hostile_user, query)
        self.assertNotIn("2026-11-22 09:00:00", query)
        self.assertEqual(params["u0"], hostile_user)
        self.assertEqual(params["meta0"], "DUAL")
        self.assertEqual(params["cutoff"], "2026-11-22 09:00:00")
        self.assertEqual(params["lim"], 120)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["SQL_TEXT"], "ALTER USER U2 IDENTIFIED BY ***")
        self.assertEqual(rows[1]["SQL_TEXT"], "CONNECT U1/***@FREEPDB1")

    def test_fetch_audit_rows_empty_usernames_returns_empty_without_query(self) -> None:
        cur = FakeCursor()
        self.assertEqual(self.client.fetch_audit_rows(cur, [], "2026-11-22 00:00:00"), [])
        self.assertEqual(cur.executed, [])


class TestFetchFgaAndTriggerAlerts(unittest.TestCase):
    """Verify FGA STAT_FUNC non-filtering and UTC trigger alert queries."""

    def setUp(self) -> None:
        self.client = OracleDbClient(_make_test_config())

    def test_fetch_fga_rows_preserves_stat_func_hits_on_honeytoken_trap(self) -> None:
        cols = [
            ("EVENT_TIMESTAMP",),
            ("DBUSERNAME",),
            ("ACTION_NAME",),
            ("OBJECT_SCHEMA",),
            ("OBJECT_NAME",),
            ("FGA_POLICY_NAME",),
            ("AUDIT_TYPE",),
            ("SQL_TEXT",),
            ("OS_USERNAME",),
            ("USERHOST",),
            ("CLIENT_PROGRAM_NAME",),
            ("RETURN_CODE",),
        ]
        fga_rows_db = [
            (
                "2026-11-22 10:15:00",
                "U3",
                "SELECT",
                "SYSTEM",
                "NV",
                "FGA_HONEYTOKEN_TRAP",
                "FineGrainedAudit",
                "SELECT COUNT(*) FROM SYS.NV WHERE manv = 'NV_TRAP'",
                "stat_u3",
                "ANALYST-PC03",
                "SQL Developer",
                20003,
            ),
        ]
        cur = FakeCursor(responder=lambda _q, _p: (cols, fga_rows_db))
        rows = self.client.fetch_fga_rows(cur, ["U3"], "2026-11-22 10:00:00")

        query, params = cur.executed[0]
        assert params is not None
        self.assertIn("SYS_EXTRACT_UTC(event_timestamp)", query)
        self.assertIn("audit_type = 'FineGrainedAudit' OR fga_policy_name IS NOT NULL", query)
        for forbidden_filter in ("COUNT", "SUM", "AVG", "STAT_FUNC", "NOT REGEXP_LIKE"):
            self.assertNotIn(forbidden_filter, query.upper())

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["FGA_POLICY_NAME"], "FGA_HONEYTOKEN_TRAP")
        self.assertIn("COUNT(*)", rows[0]["SQL_TEXT"])

    def test_fetch_trigger_alerts_uses_sys_extract_utc_and_scrubs_details(self) -> None:
        cols = [
            ("ALERT_ID",),
            ("EVENT_TIME",),
            ("DB_USER",),
            ("ATTACK_TYPE",),
            ("DETAILS",),
        ]
        db_rows = [
            (
                7,
                "2026-11-22 10:20:00",
                "U1",
                "SQL_INJECTION_BLOCK",
                "SELECT * FROM SYS.NV; -- CONN U1/SecretPwd@FREEPDB1",
            )
        ]
        cur = FakeCursor(responder=lambda _q, _p: (cols, db_rows))
        rows = self.client.fetch_trigger_alerts(cur, "2026-11-22T10:00:00Z")

        query, params = cur.executed[0]
        self.assertIn("TO_CHAR(SYS_EXTRACT_UTC(event_time), 'YYYY-MM-DD HH24:MI:SS') AS EVENT_TIME", query)
        self.assertIn("WHERE SYS_EXTRACT_UTC(event_time) > TO_TIMESTAMP(:cutoff, 'YYYY-MM-DD HH24:MI:SS')", query)
        self.assertIn("ORDER BY SYS_EXTRACT_UTC(event_time) DESC, alert_id DESC", query)
        self.assertEqual(params, {"cutoff": "2026-11-22 10:00:00"})
        self.assertEqual(rows[0]["DETAILS"], "SELECT * FROM SYS.NV; -- CONN U1/***@FREEPDB1")


class TestTriggerTimezoneAndHotenSync(unittest.TestCase):
    """Verify TIMESTAMP WITH TIME ZONE DDL/migration, HOTEN trigger parity, and pool lifecycle."""

    def setUp(self) -> None:
        self.client = OracleDbClient(_make_test_config())

    def test_verify_and_sync_trigger_creates_table_with_tz_and_hoten_trigger(self) -> None:
        state = {"table_created": False, "trigger_created": False}

        def responder(query: str, _params: dict[str, Any] | None):
            upper_q = query.upper()
            if "FROM DBA_TABLES" in upper_q:
                rows = [("IDS_SALARY_BASELINES",)]
                if state["table_created"]:
                    rows.append(("IDS_TRIGGER_ALERTS",))
                return [("TABLE_NAME",)], rows
            if "CREATE TABLE SYS.IDS_TRIGGER_ALERTS" in upper_q:
                state["table_created"] = True
                return [], []
            if "FROM DBA_TRIGGERS" in upper_q:
                if state["trigger_created"]:
                    return [("STATUS",), ("STATUS",)], [("ENABLED", "VALID")]
                return [("STATUS",), ("STATUS",)], []
            if "CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV" in upper_q:
                state["trigger_created"] = True
                return [], []
            return [], []

        cur = FakeCursor(responder=responder)
        conn = FakeConnection(cur)
        errors: list[str] = []

        ok = self.client._verify_and_sync_trigger(cur, conn, "SYSTEM", errors)
        self.assertTrue(ok)
        self.assertEqual(errors, [])

        create_table_sqls = [q for q, _ in cur.executed if "CREATE TABLE SYS.IDS_TRIGGER_ALERTS" in q]
        self.assertEqual(len(create_table_sqls), 1)
        self.assertIn("event_time TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP", create_table_sqls[0])

        trigger_sqls = [q for q, _ in cur.executed if "CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV" in q]
        self.assertEqual(len(trigger_sqls), 1)
        self.assertIn("OR NVL(:NEW.hoten, '~') <> NVL(:OLD.hoten, '~')", trigger_sqls[0])

    def test_verify_and_sync_trigger_migrates_legacy_plain_timestamp_column(self) -> None:
        def responder(query: str, _params: dict[str, Any] | None):
            upper_q = query.upper()
            if "FROM DBA_TABLES" in upper_q:
                return [("TABLE_NAME",)], [("IDS_TRIGGER_ALERTS",), ("IDS_SALARY_BASELINES",)]
            if "FROM DBA_TAB_COLUMNS" in upper_q:
                return [("DATA_TYPE",)], [("TIMESTAMP(6)",)]
            if "FROM DBA_TRIGGERS" in upper_q:
                return [("STATUS",), ("STATUS",)], [("ENABLED", "VALID")]
            if "FROM DBA_SOURCE" in upper_q:
                return [("TEXT",)], [("OR NVL(:NEW.hoten, '~') <> NVL(:OLD.hoten, '~')",)]
            return [], []

        cur = FakeCursor(responder=responder)
        conn = FakeConnection(cur)
        errors: list[str] = []

        ok = self.client._verify_and_sync_trigger(cur, conn, "SYSTEM", errors)
        self.assertTrue(ok)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(conn.commits, 1)

        mig_sqls = [q for q, _ in cur.executed if "event_time_tz" in q]
        self.assertEqual(len(mig_sqls), 1)
        mig = mig_sqls[0]
        self.assertIn("event_time_tz TIMESTAMP WITH TIME ZONE", mig)
        self.assertIn("UPDATE SYS.IDS_TRIGGER_ALERTS SET event_time_tz = FROM_TZ(event_time, DBTIMEZONE)", mig)
        self.assertIn("DROP COLUMN event_time", mig)
        self.assertIn("RENAME COLUMN event_time_tz TO event_time", mig)
        self.assertIn("DEFAULT SYSTIMESTAMP", mig)

    def test_verify_and_sync_trigger_skips_migration_when_already_tz(self) -> None:
        def responder(query: str, _params: dict[str, Any] | None):
            upper_q = query.upper()
            if "FROM DBA_TABLES" in upper_q:
                return [("TABLE_NAME",)], [("IDS_TRIGGER_ALERTS",), ("IDS_SALARY_BASELINES",)]
            if "FROM DBA_TAB_COLUMNS" in upper_q:
                return [("DATA_TYPE",)], [("TIMESTAMP(6) WITH TIME ZONE",)]
            if "FROM DBA_TRIGGERS" in upper_q:
                return [("STATUS",), ("STATUS",)], [("ENABLED", "VALID")]
            if "FROM DBA_SOURCE" in upper_q:
                return [("TEXT",)], [("OR NVL(:NEW.hoten, '~') <> NVL(:OLD.hoten, '~')",)]
            return [], []

        cur = FakeCursor(responder=responder)
        conn = FakeConnection(cur)
        errors: list[str] = []

        ok = self.client._verify_and_sync_trigger(cur, conn, "SYSTEM", errors)
        self.assertTrue(ok)
        self.assertEqual(errors, [])
        self.assertFalse(any("event_time_tz" in q for q, _ in cur.executed))

    def test_verify_and_sync_trigger_logs_warning_if_migration_fails(self) -> None:
        def responder(query: str, _params: dict[str, Any] | None):
            upper_q = query.upper()
            if "FROM DBA_TABLES" in upper_q:
                return [("TABLE_NAME",)], [("IDS_TRIGGER_ALERTS",), ("IDS_SALARY_BASELINES",)]
            if "EVENT_TIME_TZ" in upper_q:
                raise RuntimeError("ORA-00054: resource busy and acquire with NOWAIT specified")
            if "FROM DBA_TAB_COLUMNS" in upper_q:
                return [("DATA_TYPE",)], [("TIMESTAMP(6)",)]
            if "FROM DBA_TRIGGERS" in upper_q:
                return [("STATUS",), ("STATUS",)], [("ENABLED", "VALID")]
            if "FROM DBA_SOURCE" in upper_q:
                return [("TEXT",)], [("OR NVL(:NEW.hoten, '~') <> NVL(:OLD.hoten, '~')",)]
            return [], []

        cur = FakeCursor(responder=responder)
        conn = FakeConnection(cur)
        errors: list[str] = []

        with self.assertLogs("oracle_ids.db", level="WARNING") as logs:
            ok = self.client._verify_and_sync_trigger(cur, conn, "SYSTEM", errors)

        self.assertTrue(ok)
        self.assertEqual(conn.rollbacks, 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("migration failed", errors[0])
        self.assertTrue(any("TIMESTAMP WITH TIME ZONE" in msg for msg in logs.output))

    def test_verify_and_sync_trigger_upgrades_legacy_trigger_missing_hoten_check(self) -> None:
        def responder(query: str, _params: dict[str, Any] | None):
            upper_q = query.upper()
            if "FROM DBA_TABLES" in upper_q:
                return [("TABLE_NAME",)], [("IDS_TRIGGER_ALERTS",), ("IDS_SALARY_BASELINES",)]
            if "FROM DBA_TAB_COLUMNS" in upper_q:
                return [("DATA_TYPE",)], [("TIMESTAMP(6) WITH TIME ZONE",)]
            if "FROM DBA_TRIGGERS" in upper_q:
                return [("STATUS",), ("STATUS",)], [("ENABLED", "VALID")]
            if "FROM DBA_SOURCE" in upper_q:
                return [("TEXT",)], [("OR NVL(:NEW.cmnd, '~') <> NVL(:OLD.cmnd, '~') THEN",)]
            return [], []

        cur = FakeCursor(responder=responder)
        conn = FakeConnection(cur)
        errors: list[str] = []

        ok = self.client._verify_and_sync_trigger(cur, conn, "SYSTEM", errors)
        self.assertTrue(ok)
        self.assertEqual(errors, [])

        redeployed = [q for q, _ in cur.executed if "CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV" in q]
        self.assertEqual(len(redeployed), 1)
        self.assertIn("OR NVL(:NEW.hoten, '~') <> NVL(:OLD.hoten, '~')", redeployed[0])

    def test_acquire_and_close_pool_lifecycle(self) -> None:
        cur = FakeCursor(responder=lambda _q, _p: ([("TS",)], [("2026-11-22 10:30:00",)]))
        conn = FakeConnection(cur)
        fake_pool = FakePool(conn)

        with patch.object(db_client.oracledb, "create_pool", return_value=fake_pool) as mock_create:
            with self.client.acquire() as (acquired_conn, acquired_cur):
                self.assertIs(acquired_conn, conn)
                self.assertIs(acquired_cur, cur)
                ts = self.client.get_oracle_utc_now_str(acquired_cur)
                self.assertEqual(ts, "2026-11-22 10:30:00")

            mock_create.assert_called_once()
            self.assertTrue(cur.closed)
            self.assertEqual(fake_pool.released, [conn])

            self.client.close()
            self.assertTrue(fake_pool.closed)


if __name__ == "__main__":
    unittest.main()
