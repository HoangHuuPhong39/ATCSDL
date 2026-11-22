"""Safe Oracle Active IPS actions with identifier allowlisting and DBMS_ASSERT."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # pragma: no cover
    from oracle.db_client import OracleDbClient

logger = logging.getLogger("oracle_ids.ips")

DEFAULT_PROTECTED_ACCOUNTS: frozenset[str] = frozenset(
    {"SYS", "SYSTEM", "PUBLIC", "PDBADMIN", "AUDSYS", "DBSNMP", "OUTLN", "XDB"}
)
_ORACLE_IDENTIFIER_RE = re.compile(r"\A[A-Z][A-Z0-9_#$]{0,127}\Z")
_UTC_TS_RE = re.compile(r"\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\Z")
_DEFAULT_POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "shared",
    "detection_policy.json",
)


def load_protected_accounts(policy_path: str | None = None) -> set[str]:
    """Load protected Oracle accounts from detection_policy.json with safe fallback."""
    target_path = policy_path or _DEFAULT_POLICY_PATH
    accounts = set(DEFAULT_PROTECTED_ACCOUNTS)
    if not os.path.isfile(target_path):
        logger.debug("Policy file not found at %s; using default protected accounts.", target_path)
        return accounts
    try:
        with open(target_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        policy_accounts = raw.get("protected_accounts")
        if isinstance(policy_accounts, list):
            loaded = {str(item).strip().upper() for item in policy_accounts if str(item).strip()}
            accounts.update(loaded)
        else:
            logger.warning("Policy field 'protected_accounts' in %s is not a list; using defaults.", target_path)
    except Exception as exc:
        logger.warning("Failed loading protected_accounts from %s (%s); using defaults.", target_path, exc)
    return accounts


def validate_oracle_identifier(
    username: str,
    protected_accounts: set[str] | None = None,
) -> str:
    """Validate and normalize an Oracle username while rejecting protected system accounts."""
    if not isinstance(username, str):
        raise ValueError(f"Invalid Oracle identifier: expected string, got {type(username).__name__}.")
    cleaned = username.strip().upper()
    if not _ORACLE_IDENTIFIER_RE.fullmatch(cleaned):
        raise ValueError(
            f"Invalid Oracle identifier {username!r}: must match ^[A-Z][A-Z0-9_#$]{{0,127}}$."
        )
    protected = (
        {str(acc).strip().upper() for acc in protected_accounts}
        if protected_accounts is not None
        else load_protected_accounts()
    )
    if cleaned in protected:
        raise ValueError(f"Operation rejected: {cleaned!r} is a protected Oracle account.")
    return cleaned


def _resolve_protected_accounts(db_client: OracleDbClient | Any) -> set[str]:
    policy_path = getattr(getattr(db_client, "config", None), "policy_path", None)
    return load_protected_accounts(policy_path)


def _resolve_utc_now(db_client: OracleDbClient | Any, cur: Any, cutoff: str | None) -> str:
    if cutoff:
        cleaned = str(cutoff).strip().replace("T", " ")
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1]
        candidate = cleaned[:19]
        if _UTC_TS_RE.fullmatch(candidate):
            return candidate
        logger.warning("Ignoring malformed UTC cutoff %r; querying Oracle UTC clock.", cutoff)
    return str(db_client.get_oracle_utc_now_str(cur))


def _clean_unified_audit_trail(cur: Any, conn: Any) -> bool:
    try:
        cur.execute(
            """
            BEGIN
                DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(
                    audit_trail_type        => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
                    use_last_arch_timestamp => FALSE
                );
            END;
            """
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.warning("Failed cleaning Oracle unified audit trail: %s", exc)
        return False


def _restore_default_nv_rows(cur: Any, conn: Any) -> bool:
    try:
        cur.execute(
            """
            MERGE INTO SYSTEM.NV t USING (
                SELECT 'NV1' m, 'Nguyen Van A' h, 900 l, 'Nam' g, '001206012345' c FROM DUAL UNION ALL
                SELECT 'NV2', 'Tran Thi B', 850, 'Nu', '001206099999' FROM DUAL UNION ALL
                SELECT 'NV3', 'Le Van C', 1200, 'Nam', '001206088888' FROM DUAL UNION ALL
                SELECT 'NV4', 'Pham Thi D', 950, 'Nu', '001206534243' FROM DUAL UNION ALL
                SELECT 'NV_TRAP', :trap_name, 99999, 'Nam', '001099000000' FROM DUAL
            ) s ON (t.manv = s.m)
            WHEN MATCHED THEN
                UPDATE SET t.hoten = s.h, t.luong = s.l, t.gioitinh = s.g, t.cmnd = s.c
            WHEN NOT MATCHED THEN
                INSERT (manv, hoten, luong, gioitinh, cmnd) VALUES (s.m, s.h, s.l, s.g, s.c)
            """,
            {"trap_name": "Hoang Van Sếp (VIP)"},
        )
        conn.commit()
        return True
    except Exception as exc:
        logger.warning("Failed restoring default SYSTEM.NV rows: %s", exc)
        return False


def lock_user(db_client: OracleDbClient | Any, username: str) -> tuple[bool, str]:
    """Level 3 - Full Isolation: lock the Oracle user account and kill its active sessions."""
    try:
        uname = validate_oracle_identifier(username, protected_accounts=_resolve_protected_accounts(db_client))
    except ValueError as exc:
        logger.warning("lock_user rejected input %r: %s", username, exc)
        return False, str(exc)

    try:
        with db_client.acquire() as (conn, cur):
            cur.execute(
                "BEGIN EXECUTE IMMEDIATE 'ALTER USER ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u) || ' ACCOUNT LOCK'; END;",
                {"u": uname},
            )
            cur.execute("SELECT sid, serial# FROM v$session WHERE username = :u", {"u": uname})
            sessions = cur.fetchall()
            for raw_sid, raw_serial in sessions:
                try:
                    sid_int = int(raw_sid)
                    serial_int = int(raw_serial)
                    if sid_int <= 0 or serial_int < 0:
                        raise ValueError(f"Non-positive session ID ({sid_int}, {serial_int})")
                    cur.execute(f"ALTER SYSTEM KILL SESSION '{sid_int},{serial_int}' IMMEDIATE")
                except Exception as sess_exc:
                    logger.warning(
                        "Failed killing session (%r, %r) for locked user %s: %s",
                        raw_sid,
                        raw_serial,
                        uname,
                        sess_exc,
                    )
            conn.commit()
        return (
            True,
            f"[Level 3 - Full Isolation] Đã KHÓA tài khoản {uname} và ngắt tức thời các phiên kết nối!",
        )
    except Exception as exc:
        logger.exception("lock_user failed for %s", uname)
        return False, str(exc)


def unlock_user(
    db_client: OracleDbClient | Any,
    state_store: Any,
    username: str,
    utc_cutoff: str | None = None,
) -> tuple[bool, str]:
    """Unlock a non-protected Oracle user and advance its UTC cleared timestamp."""
    try:
        uname = validate_oracle_identifier(username, protected_accounts=_resolve_protected_accounts(db_client))
    except ValueError as exc:
        logger.warning("unlock_user rejected input %r: %s", username, exc)
        return False, str(exc)

    try:
        with db_client.acquire() as (conn, cur):
            cur.execute(
                "BEGIN EXECUTE IMMEDIATE 'ALTER USER ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u) || ' ACCOUNT UNLOCK'; END;",
                {"u": uname},
            )
            now_utc = _resolve_utc_now(db_client, cur, utc_cutoff)
            conn.commit()
        if state_store is not None:
            state_store.set_user_cleared_at(uname, now_utc)
        return True, f"Đã MỞ KHÓA tài khoản {uname} và đặt lại điểm rủi ro (Risk Score = 0)!"
    except Exception as exc:
        logger.exception("unlock_user failed for %s", uname)
        return False, str(exc)


def revoke_dml_user(db_client: OracleDbClient | Any, username: str) -> tuple[bool, str]:
    """Level 2 - Privilege Containment: revoke INSERT/UPDATE/DELETE on SYS.NV while keeping SELECT."""
    try:
        uname = validate_oracle_identifier(username, protected_accounts=_resolve_protected_accounts(db_client))
    except ValueError as exc:
        logger.warning("revoke_dml_user rejected input %r: %s", username, exc)
        return False, str(exc)

    try:
        with db_client.acquire() as (conn, cur):
            revoked_any = False
            unexpected_error: Exception | None = None
            try:
                cur.execute(
                    "BEGIN EXECUTE IMMEDIATE 'REVOKE INSERT, UPDATE, DELETE ON SYS.NV FROM ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u); END;",
                    {"u": uname},
                )
                revoked_any = True
            except Exception as batch_exc:
                logger.debug("Batch REVOKE DML on SYS.NV from %s failed (%s); retrying per privilege.", uname, batch_exc)
                for priv in ("INSERT", "UPDATE", "DELETE"):
                    try:
                        cur.execute(
                            f"BEGIN EXECUTE IMMEDIATE 'REVOKE {priv} ON SYS.NV FROM ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u); END;",
                            {"u": uname},
                        )
                        revoked_any = True
                    except Exception as priv_exc:
                        if "ORA-01927" in str(priv_exc):
                            logger.debug("Privilege %s on SYS.NV was already absent for %s.", priv, uname)
                        else:
                            unexpected_error = priv_exc
                            logger.warning("REVOKE %s ON SYS.NV FROM %s failed: %s", priv, uname, priv_exc)

            if not revoked_any and unexpected_error is not None:
                raise unexpected_error

            try:
                cur.execute(
                    "BEGIN EXECUTE IMMEDIATE 'GRANT SELECT ON SYS.NV TO ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u); END;",
                    {"u": uname},
                )
            except Exception as sel_exc:
                logger.warning("Failed ensuring SELECT ON SYS.NV for %s: %s", uname, sel_exc)
            conn.commit()

        if revoked_any:
            return (
                True,
                f"[Level 2 - Privilege Containment] Đã thu hồi quyền DML (INSERT, UPDATE, DELETE) của {uname} -> Chuyển về chế độ Read-Only!",
            )
        return True, f"Tài khoản {uname} hiện đã ở chế độ Read-Only (chỉ có quyền SELECT)!"
    except Exception as exc:
        logger.exception("revoke_dml_user failed for %s", uname)
        return False, str(exc)


def grant_dml_user(
    db_client: OracleDbClient | Any,
    state_store: Any,
    username: str,
) -> tuple[bool, str]:
    """Restore full DML privileges on SYS.NV and reset the user's UTC risk baseline."""
    try:
        uname = validate_oracle_identifier(username, protected_accounts=_resolve_protected_accounts(db_client))
    except ValueError as exc:
        logger.warning("grant_dml_user rejected input %r: %s", username, exc)
        return False, str(exc)

    try:
        with db_client.acquire() as (conn, cur):
            cur.execute(
                "BEGIN EXECUTE IMMEDIATE 'GRANT SELECT, INSERT, UPDATE, DELETE ON SYS.NV TO ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u); END;",
                {"u": uname},
            )
            now_utc = db_client.get_oracle_utc_now_str(cur)
            conn.commit()
        if state_store is not None:
            state_store.set_user_cleared_at(uname, now_utc)
        return (
            True,
            f"Đã KHÔI PHỤC toàn bộ quyền DML (SELECT, INSERT, UPDATE, DELETE) trên SYS.NV cho {uname}!",
        )
    except Exception as exc:
        logger.exception("grant_dml_user failed for %s", uname)
        return False, str(exc)


def _unlock_and_restore_monitored_users(
    cur: Any,
    monitored_users: Sequence[str],
    protected_accounts: set[str],
) -> list[str]:
    restored: list[str] = []
    for raw_user in monitored_users:
        try:
            uname = validate_oracle_identifier(str(raw_user or ""), protected_accounts=protected_accounts)
        except ValueError as exc:
            logger.warning("Skipping invalid/protected monitored user %r during reset: %s", raw_user, exc)
            continue
        restored.append(uname)
        try:
            cur.execute(
                "BEGIN EXECUTE IMMEDIATE 'ALTER USER ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u) || ' ACCOUNT UNLOCK'; END;",
                {"u": uname},
            )
        except Exception as unlock_exc:
            logger.warning("Failed unlocking monitored user %s during reset: %s", uname, unlock_exc)
        try:
            cur.execute(
                "BEGIN EXECUTE IMMEDIATE 'GRANT SELECT, INSERT, UPDATE, DELETE ON SYS.NV TO ' || DBMS_ASSERT.SIMPLE_SQL_NAME(:u); END;",
                {"u": uname},
            )
        except Exception as grant_exc:
            logger.warning("Failed granting DML on SYS.NV to %s during reset: %s", uname, grant_exc)
    return restored


def clear_alert_history(
    db_client: OracleDbClient | Any,
    state_store: Any,
    *,
    target: str = "all",
    alert_id: Any = None,
    alert_key: str | None = None,
    fga_key: str | None = None,
    audit_key: str | None = None,
    reviewed_keys: Sequence[str] | None = None,
    reviewed_fga_keys: Sequence[str] | None = None,
    reviewed_trigger_ids: Sequence[Any] | None = None,
    reviewed_audit_keys: Sequence[str] | None = None,
    cutoff: str | None = None,
    monitored_users: Sequence[str] = ("U1", "U2", "U3", "U4"),
) -> tuple[bool, str]:
    """Clear selected or full IDS/FGA/Trigger/Audit history using UTC cutoffs and safe SQL."""
    norm_target = str(target or "all").strip().lower()
    valid_targets = {
        "single_ids",
        "single_trigger",
        "single_fga",
        "single_audit",
        "reviewed",
        "ids",
        "fga",
        "triggers",
        "audit",
        "all",
    }
    if norm_target not in valid_targets:
        return False, f"Invalid clear target: {target!r}"

    protected = _resolve_protected_accounts(db_client)

    try:
        with db_client.acquire() as (conn, cur):
            now_utc = _resolve_utc_now(db_client, cur, cutoff)

            if norm_target == "single_ids":
                if not alert_key:
                    return False, "Thiếu alert_key để xóa cảnh báo IDS!"
                if state_store is not None:
                    state_store.dismiss_alert(str(alert_key))
                return True, "Đã xóa cảnh báo khỏi danh sách!"

            if norm_target == "single_trigger":
                if alert_id is None:
                    return False, "Thiếu alert_id để xóa bản ghi Trigger!"
                try:
                    tid = int(alert_id)
                except (TypeError, ValueError):
                    return False, f"alert_id không hợp lệ: {alert_id!r}"
                cur.execute("DELETE FROM SYS.IDS_TRIGGER_ALERTS WHERE alert_id = :id", {"id": tid})
                conn.commit()
                return True, f"Đã xóa bản ghi Trigger #{tid}!"

            if norm_target == "single_fga":
                key_val = fga_key or alert_key
                if not key_val:
                    return False, "Thiếu fga_key để xóa sự kiện FGA!"
                if state_store is not None:
                    state_store.dismiss_fga(str(key_val))
                return True, "Đã xóa sự kiện FGA khỏi danh sách!"

            if norm_target == "single_audit":
                key_val = audit_key or alert_key
                if not key_val:
                    return False, "Thiếu audit_key để xóa nhật ký Audit!"
                if state_store is not None:
                    state_store.dismiss_audit(str(key_val))
                return True, "Đã xóa dòng nhật ký Audit khỏi danh sách!"

            if norm_target == "reviewed":
                r_alert_keys = [str(k) for k in (reviewed_keys or ()) if k is not None and str(k)]
                r_fga_keys = [str(k) for k in (reviewed_fga_keys or ()) if k is not None and str(k)]
                r_audit_keys = [str(k) for k in (reviewed_audit_keys or ()) if k is not None and str(k)]

                deleted_triggers = 0
                for raw_tid in (reviewed_trigger_ids or ()):
                    try:
                        tid = int(raw_tid)
                    except (TypeError, ValueError):
                        logger.warning("Skipping invalid reviewed trigger ID: %r", raw_tid)
                        continue
                    try:
                        cur.execute("DELETE FROM SYS.IDS_TRIGGER_ALERTS WHERE alert_id = :id", {"id": tid})
                        deleted_triggers += 1
                    except Exception as trig_exc:
                        logger.warning("Failed deleting reviewed trigger #%s: %s", tid, trig_exc)
                if deleted_triggers:
                    conn.commit()

                remaining_active: int | None = None
                if state_store is not None:
                    remaining_active = state_store.clear_reviewed(
                        alert_keys=r_alert_keys,
                        fga_keys=r_fga_keys,
                        audit_keys=r_audit_keys,
                    )

                if r_alert_keys and isinstance(remaining_active, int) and remaining_active == 0:
                    _clean_unified_audit_trail(cur, conn)

                return True, "Đã xóa vĩnh viễn các cảnh báo đã kiểm duyệt khỏi bộ nhớ!"

            if norm_target == "fga":
                if state_store is not None:
                    state_store.clear_fga(now_utc)
                return True, "Đã xóa lịch sử sự kiện FGA!"

            if norm_target == "audit":
                if state_store is not None:
                    state_store.clear_audit(now_utc)
                _clean_unified_audit_trail(cur, conn)
                return True, "Đã xóa nhật ký Unified Audit Trail và giải phóng bộ nhớ!"

            if norm_target == "triggers":
                cur.execute("DELETE FROM SYS.IDS_TRIGGER_ALERTS")
                conn.commit()
                _restore_default_nv_rows(cur, conn)
                return True, "Đã xóa toàn bộ lịch sử cảnh báo Trigger!"

            # norm_target in ("ids", "all")
            restored_users = _unlock_and_restore_monitored_users(cur, monitored_users, protected)
            if state_store is not None:
                if norm_target == "ids":
                    state_store.clear_ids(now_utc, monitored_users=restored_users)
                else:
                    state_store.clear_all(now_utc, monitored_users=restored_users)

            _clean_unified_audit_trail(cur, conn)

            if norm_target == "all":
                cur.execute("DELETE FROM SYS.IDS_TRIGGER_ALERTS")
                conn.commit()

            _restore_default_nv_rows(cur, conn)
            conn.commit()

            if norm_target == "ids":
                return True, "Đã xóa lịch sử cảnh báo IDS, đặt lại Risk Score = 0 & khôi phục quyền User!"
            return True, "Đã xóa toàn bộ lịch sử cảnh báo IDS, FGA, Trigger & khôi phục trạng thái User!"
    except Exception as exc:
        logger.exception("clear_alert_history failed (target=%s)", norm_target)
        return False, str(exc)
