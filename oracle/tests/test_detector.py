"""Unit, evasion, and security regression tests for oracle.detector."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

try:
    from oracle import detector
    from oracle.state_store import StateStore
except ImportError:  # pragma: no cover - direct execution inside oracle/
    _ORACLE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _ORACLE_DIR not in sys.path:
        sys.path.insert(0, _ORACLE_DIR)
    import detector
    from state_store import StateStore

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_POLICY_PATH = os.path.join(_REPO_ROOT, "shared", "detection_policy.json")


def _make_audit_row(
    *,
    user: str = "U1",
    event_time: str = "2026-11-22 10:00:00",
    action: str = "SELECT",
    object_schema: str = "SYS",
    object_name: str = "NV",
    sql_text: str = "SELECT manv, hoten FROM SYS.NV",
    return_code: int = 0,
    os_username: str = "pc",
    userhost: str = "LAPTOP-R03ORTGV",
    client_program: str = "SQL Developer",
    audit_type: str = "Standard",
    fga_policy: str = "",
    unified_policies: str = "",
) -> dict:
    return {
        "EVENT_TIMESTAMP": event_time,
        "DBUSERNAME": user,
        "ACTION_NAME": action,
        "OBJECT_SCHEMA": object_schema,
        "OBJECT_NAME": object_name,
        "SQL_TEXT": sql_text,
        "RETURN_CODE": return_code,
        "OS_USERNAME": os_username,
        "USERHOST": userhost,
        "CLIENT_PROGRAM_NAME": client_program,
        "AUDIT_TYPE": audit_type,
        "FGA_POLICY_NAME": fga_policy,
        "UNIFIED_AUDIT_POLICIES": unified_policies,
    }


def _make_user_map(*users: str, acct_status: str = "OPEN", dml_status: str = "FULL DML") -> dict:
    target_users = users or ("U1", "U2", "U3", "U4")
    return {
        u: {
            "USERNAME": u,
            "ACCOUNT_STATUS": acct_status,
            "DML_STATUS": dml_status,
        }
        for u in target_users
    }


class DetectorTestBase(unittest.TestCase):
    """Shared temporary StateStore and loaded policy fixture."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self._tmpdir.name, ".ids_state.json")
        self.store = StateStore(self.state_file)
        self.policy = detector.load_policy(_POLICY_PATH)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()


class TestThresholdsAndPolicy(DetectorTestBase):
    """Verify policy thresholds and scoring rules match shared/detection_policy.json."""

    def test_policy_thresholds_match_contract(self) -> None:
        thresholds = self.policy["thresholds"]
        self.assertEqual((thresholds["level_0"]["min"], thresholds["level_0"]["max"]), (0, 19))
        self.assertEqual((thresholds["level_1"]["min"], thresholds["level_1"]["max"]), (20, 49))
        self.assertEqual((thresholds["level_2"]["min"], thresholds["level_2"]["max"]), (50, 79))
        self.assertEqual((thresholds["level_3"]["min"], thresholds["level_3"]["max"]), (80, 100))
        self.assertFalse(self.policy["scoring"]["clamp_by_tier"])

        expected_levels = (
            (-5, 0),
            (0, 0),
            (19, 0),
            (20, 1),
            (49, 1),
            (50, 2),
            (79, 2),
            (80, 3),
            (100, 3),
            (135, 3),
        )
        for score, expected_lvl in expected_levels:
            lvl, label = detector.classify_response_level(score, policy=self.policy)
            self.assertEqual(lvl, expected_lvl, f"score={score}")
            self.assertEqual(label, thresholds[f"level_{expected_lvl}"]["label"])


class TestDbmsAttackGroups(DetectorTestBase):
    """Verify detection coverage across all 5 DBMS attack groups and trigger blocks."""

    def test_honeytoken_trap_variants(self) -> None:
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:00:01",
                sql_text="SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP'",
            ),
            _make_audit_row(
                user="U2",
                userhost="WORKSTATION-FIN02",
                os_username="fin_u2",
                event_time="2026-11-22 10:00:02",
                sql_text="SELECT * FROM SYS.NV WHERE cmnd = '001099000000'",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:00:03",
                sql_text="SELECT hoten FROM SYS.NV",
                fga_policy="FGA_HONEYTOKEN_TRAP",
                audit_type="FineGrainedAudit",
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1", "U2", "U3"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 3)
        for alert in alerts:
            self.assertTrue(alert["key"].startswith("TRAP|"))
            self.assertEqual(alert["severity"], "CRITICAL")
            self.assertEqual(alert["risk_score"], 95)

    def test_sql_injection_variants(self) -> None:
        payloads = [
            "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1",
            "SELECT manv, hoten FROM SYS.NV UNION SELECT 'x', user FROM DUAL",
            "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 2=2",
            "SELECT DBMS_LOCK.SLEEP(5) FROM DUAL",
            "SELECT UTL_FILE.FOPEN('/etc', 'passwd', 'r') FROM DUAL",
            "SELECT * FROM SYS.NV WHERE manv = 'NV1' -- inline bypass",
        ]
        rows = [
            _make_audit_row(
                event_time=f"2026-11-22 10:01:0{idx}",
                object_name="DUAL" if "FROM DUAL" in sql else "NV",
                sql_text=sql,
            )
            for idx, sql in enumerate(payloads)
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), len(payloads))
        for alert in alerts:
            self.assertTrue(alert["key"].startswith("SQLI|"), alert)
            self.assertEqual(alert["severity"], "CRITICAL")
            self.assertEqual(alert["risk_score"], 95)

    def test_crypto_key_access_variants(self) -> None:
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:02:01",
                object_name="V$ENCRYPTION_KEYS",
                sql_text="SELECT * FROM SYS.V$ENCRYPTION_KEYS",
            ),
            _make_audit_row(
                event_time="2026-11-22 10:02:02",
                object_name="ENC$",
                sql_text="SELECT * FROM SYS.ENC$",
            ),
            _make_audit_row(
                event_time="2026-11-22 10:02:03",
                object_name="DBMS_CRYPTO",
                sql_text="SELECT SYS.DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW('x'), 2) FROM DUAL",
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 3)
        for alert in alerts:
            self.assertTrue(alert["key"].startswith("CRYPTO|"))
            self.assertEqual(alert["severity"], "CRITICAL")
            self.assertEqual(alert["risk_score"], 92)

    def test_privilege_escalation_grant_dba_and_create_user(self) -> None:
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:03:01",
                action="GRANT",
                object_name="",
                sql_text="GRANT DBA TO U1",
                return_code=1031,
            ),
            _make_audit_row(
                event_time="2026-11-22 10:03:02",
                action="CREATE USER",
                object_name="",
                sql_text="CREATE USER ROGUE_ADMIN IDENTIFIED BY WeakPass123",
                return_code=1031,
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 2)
        for alert in alerts:
            self.assertTrue(alert["key"].startswith("PRIV|"))
            self.assertEqual(alert["severity"], "CRITICAL")
            self.assertEqual(alert["risk_score"], 88)
        self.assertNotIn("WeakPass123", json.dumps(alerts))

    def test_ddl_destructive_and_modify(self) -> None:
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:04:01",
                action="DROP TABLE",
                sql_text="DROP TABLE SYS.NV",
                return_code=1031,
            ),
            _make_audit_row(
                event_time="2026-11-22 10:04:02",
                action="ALTER TABLE",
                sql_text="ALTER TABLE SYS.NV ADD (tmp VARCHAR2(20))",
                return_code=1031,
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        by_action = {a["risk_score"]: a for a in alerts}
        self.assertEqual(len(alerts), 2)
        self.assertEqual(by_action[85]["severity"], "CRITICAL")
        self.assertIn("DROP TABLE", by_action[85]["attack_type"])
        self.assertEqual(by_action[65]["severity"], "HIGH")
        self.assertIn("ALTER TABLE", by_action[65]["attack_type"])

    def test_readonly_dml_violation_ora_41900(self) -> None:
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:05:01",
                action="UPDATE",
                sql_text="UPDATE SYS.NV SET luong = 9000 WHERE manv = 'NV1'",
                return_code=41900,
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1", dml_status="READ-ONLY"),
            state_store=self.store,
            policy=self.policy,
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["key"].startswith("DML_RO|"))
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 65)
        self.assertIn("ORA-41900", alerts[0]["attack_type"])

    def test_trigger_blocks_20001_to_20004(self) -> None:
        trig_rows = [
            {
                "ALERT_ID": 101,
                "EVENT_TIME": "2026-11-22 10:06:01",
                "DB_USER": "U1",
                "ATTACK_TYPE": "UNAUTHORIZED_DELETE",
                "DETAILS": "Cố tình xóa nhân viên mã: NV1",
            },
            {
                "ALERT_ID": 102,
                "EVENT_TIME": "2026-11-22 10:06:02",
                "DB_USER": "U1",
                "ATTACK_TYPE": "ABNORMAL_SALARY_MODIFICATION",
                "DETAILS": "Thay đổi lương bất thường từ 900 lên 5000",
            },
            {
                "ALERT_ID": 103,
                "EVENT_TIME": "2026-11-22 10:06:03",
                "DB_USER": "U2",
                "ATTACK_TYPE": "FGA_TRAP_BLOCK",
                "DETAILS": "SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP'",
            },
            {
                "ALERT_ID": 104,
                "EVENT_TIME": "2026-11-22 10:06:04",
                "DB_USER": "U1",
                "ATTACK_TYPE": "UNAUTHORIZED_DML_INTEGRITY",
                "DETAILS": "Từ chối INSERT vi phạm toàn vẹn dữ liệu",
            },
            {
                "ALERT_ID": 105,
                "EVENT_TIME": "2026-11-22 10:06:05",
                "DB_USER": "SYS",
                "ATTACK_TYPE": "UNAUTHORIZED_DELETE",
                "DETAILS": "Protected user must be skipped",
            },
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            [], [], trig_rows, _make_user_map("U1", "U2"), state_store=self.store, policy=self.policy
        )
        by_key = {a["key"]: a for a in alerts}
        self.assertEqual(len(alerts), 4)
        self.assertIn("ORA-20001", by_key["TRIG|101|U1|2026-11-22 10:06:01"]["attack_type"])
        self.assertEqual(by_key["TRIG|101|U1|2026-11-22 10:06:01"]["risk_score"], 65)
        self.assertIn("ORA-20002", by_key["TRIG|102|U1|2026-11-22 10:06:02"]["attack_type"])
        self.assertEqual(by_key["TRIG|102|U1|2026-11-22 10:06:02"]["risk_score"], 65)
        self.assertIn("ORA-20003", by_key["TRIG|103|U2|2026-11-22 10:06:03"]["attack_type"])
        self.assertEqual(by_key["TRIG|103|U2|2026-11-22 10:06:03"]["risk_score"], 95)
        self.assertIn("ORA-20004", by_key["TRIG|104|U1|2026-11-22 10:06:04"]["attack_type"])
        self.assertEqual(by_key["TRIG|104|U1|2026-11-22 10:06:04"]["risk_score"], 65)


class TestSdbInferenceAndScoring(DetectorTestBase):
    """Verify all 4 SDB inference types plus low-risk statistical probes."""

    def test_fga_high_salary_access(self) -> None:
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:10:01",
                sql_text="SELECT hoten, luong FROM SYS.NV WHERE manv = 'NV1'",
                fga_policy="FGA_HIGH_SALARY_ACCESS",
                audit_type="FineGrainedAudit",
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["key"].startswith("FGA_SAL|"))
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["risk_score"], 35)

    def test_sdb_low_probe_one_or_two_queries(self) -> None:
        rows = [
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:11:01",
                sql_text="SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam'",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:11:02",
                sql_text="SELECT AVG(luong) FROM SYS.NV WHERE gioitinh = 'Nu'",
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U3"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["key"].startswith("STAT_WARN|"))
        self.assertEqual(alerts[0]["severity"], "LOW")
        self.assertEqual(alerts[0]["risk_score"], 28)

    def test_sdb_count_based_single_combined_and_two_query_same_where(self) -> None:
        combined_rows = [
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:12:01",
                sql_text="SELECT COUNT(*), SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nu' AND hoten LIKE 'Tran%'",
            ),
        ]
        alerts_single, _, _, _ = detector.analyze_audit_logs(
            combined_rows, [], [], _make_user_map("U3"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts_single), 1)
        self.assertTrue(alerts_single[0]["key"].startswith("STAT_COUNT_SUM|"))
        self.assertEqual(alerts_single[0]["severity"], "HIGH")
        self.assertEqual(alerts_single[0]["risk_score"], 65)

        fresh_store = StateStore(os.path.join(self._tmpdir.name, ".ids_state_two.json"))
        two_query_rows = [
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:13:01",
                sql_text="SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam' AND luong > 800",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:13:02",
                sql_text="SELECT SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam'   AND luong > 800",
            ),
        ]
        alerts_two, _, _, _ = detector.analyze_audit_logs(
            two_query_rows, [], [], _make_user_map("U3"), state_store=fresh_store, policy=self.policy
        )
        self.assertEqual(len(alerts_two), 1)
        self.assertTrue(alerts_two[0]["key"].startswith("STAT_COUNT_SUM|"))
        self.assertEqual(alerts_two[0]["severity"], "HIGH")
        self.assertEqual(alerts_two[0]["risk_score"], 65)

    def test_sdb_tracker_attack(self) -> None:
        rows = [
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:14:01",
                sql_text="SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam'",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:14:02",
                sql_text="SELECT SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam' OR manv = 'NV2'",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:14:03",
                sql_text="SELECT SUM(luong) FROM SYS.NV WHERE NOT (gioitinh = 'Nu') AND manv != 'NV1'",
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U3"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["key"].startswith("STAT_INF|"))
        self.assertIn("Tracker", alerts[0]["attack_type"])
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 72)

    def test_sdb_linear_system_attack(self) -> None:
        rows = [
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:15:01",
                sql_text="SELECT SUM(luong) FROM SYS.NV WHERE manv IN ('NV1', 'NV2')",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:15:02",
                sql_text="SELECT SUM(luong) FROM SYS.NV WHERE manv IN ('NV2', 'NV3')",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:15:03",
                sql_text="SELECT AVG(luong) FROM SYS.NV WHERE manv IN ('NV1', 'NV3')",
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U3"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["key"].startswith("STAT_INF|"))
        self.assertIn("Linear System", alerts[0]["attack_type"])
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 78)


class TestEvasionAndSecurityRegressions(DetectorTestBase):
    """Verify evasion defenses, sliding windows, Anti-DoS, and credential scrubbing."""

    def test_ide_whitelist_blindness_defeated(self) -> None:
        union_dual_row = _make_audit_row(
            event_time="2026-11-22 10:20:01",
            object_schema="SYS",
            object_name="DUAL",
            sql_text="SELECT * FROM SYS.NV UNION SELECT 1,2,3,4,5 FROM DUAL",
        )
        exists_all_objects_row = _make_audit_row(
            event_time="2026-11-22 10:20:02",
            object_schema="SYS",
            object_name="ALL_OBJECTS",
            sql_text="SELECT * FROM SYS.NV WHERE 1=1 AND EXISTS (SELECT 1 FROM ALL_OBJECTS)",
        )
        trap_all_objects_row = _make_audit_row(
            event_time="2026-11-22 10:20:03",
            object_schema="SYS",
            object_name="ALL_OBJECTS",
            sql_text="SELECT * FROM SYS.NV WHERE manv='NV_TRAP' AND EXISTS (SELECT 1 FROM ALL_OBJECTS)",
        )
        benign_dual_row = _make_audit_row(
            event_time="2026-11-22 10:20:04",
            object_schema="SYS",
            object_name="DUAL",
            sql_text="SELECT 1 FROM DUAL",
        )

        self.assertFalse(detector.is_benign_ide_metadata_query(union_dual_row, self.policy))
        self.assertFalse(detector.is_benign_ide_metadata_query(exists_all_objects_row, self.policy))
        self.assertFalse(detector.is_benign_ide_metadata_query(trap_all_objects_row, self.policy))
        self.assertTrue(detector.is_benign_ide_metadata_query(benign_dual_row, self.policy))

        # Verify benign DUAL produces 0 alerts while disguised SQLi & TRAP are caught.
        benign_alerts, _, _, _ = detector.analyze_audit_logs(
            [benign_dual_row], [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(benign_alerts, [])

        attack_rows = [union_dual_row, trap_all_objects_row] + [
            _make_audit_row(
                event_time=f"2026-11-22 10:21:0{i % 4}",
                object_schema="SYS",
                object_name="ALL_OBJECTS",
                sql_text="SELECT * FROM SYS.NV WHERE 1=1 AND EXISTS (SELECT 1 FROM ALL_OBJECTS)",
            )
            for i in range(10)
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            attack_rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        keys = [a["key"] for a in alerts]
        self.assertTrue(any(k.startswith("SQLI|") for k in keys))
        self.assertTrue(any(k.startswith("TRAP|") for k in keys))
        self.assertTrue(any(k.startswith("BULK|") for k in keys))

    def test_privilege_escalation_before_readonly(self) -> None:
        row = _make_audit_row(
            event_time="2026-11-22 10:25:01",
            action="GRANT",
            object_name="NV",
            sql_text="GRANT UPDATE ON SYS.NV TO U2",
            return_code=1031,
        )
        alerts, _, _, _ = detector.analyze_audit_logs(
            [row], [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["key"].startswith("PRIV|"))
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["risk_score"], 88)

    def test_bulk_querying_sliding_window_and_no_nvl_false_positive(self) -> None:
        # 1 older query 30s earlier + 10 queries within 4s window (descending arrival order)
        burst_rows = [
            _make_audit_row(
                event_time=f"2026-11-22 10:30:{30 + (i % 4):02d}",
                sql_text=f"SELECT hoten FROM SYS.NV WHERE manv = 'NV{(i % 4) + 1}'",
            )
            for i in range(10)
        ]
        burst_rows.reverse()
        burst_rows.append(
            _make_audit_row(
                event_time="2026-11-22 10:30:00",
                sql_text="SELECT hoten FROM SYS.NV WHERE manv = 'NV1'",
            )
        )
        alerts, _, _, _ = detector.analyze_audit_logs(
            burst_rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["key"].startswith("BULK|"))
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["risk_score"], 42)

        # NVL(...) / CONVERT(...) must NOT falsely match NV table
        nvl_store = StateStore(os.path.join(self._tmpdir.name, ".ids_state_nvl.json"))
        nvl_rows = [
            _make_audit_row(
                event_time="2026-11-22 10:31:00",
                object_name="DUAL",
                sql_text="SELECT NVL(hoten, 'X') FROM DUAL",
            )
            for _ in range(12)
        ] + [
            _make_audit_row(
                event_time="2026-11-22 10:31:00",
                object_name="CUSTOM_DUMMY",
                sql_text="SELECT CONVERT('abc', 'UTF8') FROM DUAL",
            )
            for _ in range(12)
        ]
        nvl_alerts, _, _, _ = detector.analyze_audit_logs(
            nvl_rows, [], [], _make_user_map("U1"), state_store=nvl_store, policy=self.policy
        )
        self.assertEqual(nvl_alerts, [])

    def test_no_tier_clamping_escalates_high_alerts_to_level_3(self) -> None:
        score = detector.compute_user_risk_score([65, 65, 75], policy=self.policy)
        self.assertEqual(score, 83)
        lvl, _ = detector.classify_response_level(score, policy=self.policy)
        self.assertEqual(lvl, 3)

        # End-to-end: 3 HIGH alerts (DML_RO 65 + DDL ALTER 65 + Masquerading 75 -> 83 -> Level 3 lock)
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:35:01",
                action="UPDATE",
                sql_text="UPDATE SYS.NV SET luong = 3000 WHERE manv = 'NV1'",
                return_code=41900,
                userhost="WORKSTATION-FIN02",
                os_username="bob",
            ),
            _make_audit_row(
                event_time="2026-11-22 10:35:02",
                action="ALTER TABLE",
                sql_text="ALTER TABLE SYS.NV ADD (note VARCHAR2(10))",
                return_code=1031,
            ),
        ]
        mock_ips = MagicMock()
        mock_ips.lock_user.return_value = (True, "locked")
        mock_db = MagicMock()

        alerts, auto_locked, auto_revoked, risk_summary = detector.analyze_audit_logs(
            rows,
            [],
            [],
            _make_user_map("U1"),
            state_store=self.store,
            policy=self.policy,
            db_client=mock_db,
            auto_block=True,
            ips_actions_module=mock_ips,
        )
        self.assertEqual(len(alerts), 3)
        self.assertEqual(risk_summary["U1"]["risk_score"], 83)
        self.assertEqual(risk_summary["U1"]["response_level"], 3)
        self.assertEqual(auto_locked, ["U1"])
        self.assertEqual(auto_revoked, [])
        mock_ips.lock_user.assert_called_once_with(mock_db, "U1")

    def test_brute_force_anti_dos_external_vs_trusted(self) -> None:
        # 3 external failures -> HIGH (70), auto_lock_exempt=True, MUST NOT lock user
        ext_failed = [
            {
                "DBUSERNAME": "U1",
                "USERHOST": "192.168.56.109",
                "OS_USERNAME": "ext_user",
                "FAIL_COUNT": 3,
                "LAST_ATTEMPT": "2026-11-22 10:40:00",
                "CLIENT_PROGRAM_NAME": "sqlplus",
            }
        ]
        mock_ips = MagicMock()
        mock_ips.lock_user.return_value = (True, "locked")
        mock_ips.revoke_dml_user.return_value = (True, "revoked")
        mock_db = MagicMock()

        alerts, auto_locked, auto_revoked, summary = detector.analyze_audit_logs(
            [],
            ext_failed,
            [],
            _make_user_map("U1"),
            state_store=self.store,
            policy=self.policy,
            db_client=mock_db,
            auto_block=True,
            ips_actions_module=mock_ips,
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 70)
        self.assertTrue(alerts[0]["auto_lock_exempt"])
        self.assertEqual(auto_locked, [])
        self.assertEqual(auto_revoked, ["U1"])
        mock_ips.lock_user.assert_not_called()

        # Even if extra non-exempt LOW/MED alerts push total >= 80, external BF still exempts auto-lock!
        extra_rows = [
            _make_audit_row(
                event_time="2026-11-22 10:40:05",
                sql_text="SELECT hoten, luong FROM SYS.NV WHERE manv='NV1'",
                fga_policy="FGA_HIGH_SALARY_ACCESS",
            ),
            _make_audit_row(
                event_time="2026-11-22 10:40:06",
                sql_text="SELECT COUNT(*) FROM SYS.NV WHERE gioitinh='Nam'",
            ),
            _make_audit_row(
                event_time="2026-11-22 10:40:07",
                client_program="curl",
                sql_text="SELECT hoten FROM SYS.NV",
            ),
        ]
        mock_ips.reset_mock()
        _, auto_locked_2, _, summary_2 = detector.analyze_audit_logs(
            extra_rows,
            ext_failed,
            [],
            _make_user_map("U1", dml_status="READ-ONLY"),
            state_store=self.store,
            policy=self.policy,
            db_client=mock_db,
            auto_block=True,
            ips_actions_module=mock_ips,
        )
        self.assertGreaterEqual(summary_2["U1"]["risk_score"], 80)
        self.assertEqual(auto_locked_2, [])
        mock_ips.lock_user.assert_not_called()

        # >=5 failures from trusted host -> Level 3 lock (90)
        trusted_store = StateStore(os.path.join(self._tmpdir.name, ".ids_state_bf_trusted.json"))
        trusted_failed = [
            {
                "DBUSERNAME": "U1",
                "USERHOST": "LAPTOP-R03ORTGV",
                "OS_USERNAME": "pc",
                "FAIL_COUNT": 5,
                "LAST_ATTEMPT": "2026-11-22 10:45:00",
                "CLIENT_PROGRAM_NAME": "sqlplus.exe",
            }
        ]
        mock_ips.reset_mock()
        t_alerts, t_locked, _, _ = detector.analyze_audit_logs(
            [],
            trusted_failed,
            [],
            _make_user_map("U1"),
            state_store=trusted_store,
            policy=self.policy,
            db_client=mock_db,
            auto_block=True,
            ips_actions_module=mock_ips,
        )
        self.assertEqual(len(t_alerts), 1)
        self.assertEqual(t_alerts[0]["severity"], "CRITICAL")
        self.assertEqual(t_alerts[0]["risk_score"], 90)
        self.assertFalse(t_alerts[0]["auto_lock_exempt"])
        self.assertEqual(t_locked, ["U1"])
        mock_ips.lock_user.assert_called_once_with(mock_db, "U1")

    def test_masquerading_baseline_deviation_without_keyword(self) -> None:
        deviated_row = _make_audit_row(
            user="U1",
            event_time="2026-11-22 10:50:00",
            userhost="WORKSTATION-FIN02",
            os_username="bob",
            sql_text="SELECT hoten FROM SYS.NV WHERE manv = 'NV1'",
        )
        baseline_row = _make_audit_row(
            user="U1",
            event_time="2026-11-22 10:50:05",
            userhost="LAPTOP-R03ORTGV",
            os_username="pc",
            sql_text="SELECT hoten FROM SYS.NV WHERE manv = 'NV1'",
        )
        alerts_dev, _, _, _ = detector.analyze_audit_logs(
            [deviated_row], [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts_dev), 1)
        self.assertTrue(alerts_dev[0]["key"].startswith("MASQ|U1|"))
        self.assertEqual(alerts_dev[0]["severity"], "HIGH")
        self.assertEqual(alerts_dev[0]["risk_score"], 75)

        clean_store = StateStore(os.path.join(self._tmpdir.name, ".ids_state_masq_ok.json"))
        alerts_ok, _, _, _ = detector.analyze_audit_logs(
            [baseline_row], [], [], _make_user_map("U1"), state_store=clean_store, policy=self.policy
        )
        self.assertEqual(alerts_ok, [])

    def test_fga_non_exemption_with_count(self) -> None:
        trap_count_row = _make_audit_row(
            event_time="2026-11-22 10:52:01",
            sql_text="SELECT COUNT(*) FROM SYS.NV WHERE manv = 'NV_TRAP'",
            fga_policy="FGA_HONEYTOKEN_TRAP",
            audit_type="FineGrainedAudit",
        )
        sal_count_row = _make_audit_row(
            user="U2",
            userhost="WORKSTATION-FIN02",
            os_username="fin_u2",
            event_time="2026-11-22 10:52:02",
            sql_text="SELECT COUNT(luong) FROM SYS.NV",
            fga_policy="FGA_HIGH_SALARY_ACCESS",
            audit_type="FineGrainedAudit",
        )
        alerts, _, _, _ = detector.analyze_audit_logs(
            [trap_count_row, sal_count_row],
            [],
            [],
            _make_user_map("U1", "U2"),
            state_store=self.store,
            policy=self.policy,
        )
        keys = [a["key"] for a in alerts]
        self.assertTrue(any(k.startswith("TRAP|U1|") for k in keys))
        self.assertTrue(any(k.startswith("FGA_SAL|U2|") for k in keys))

    def test_sdb_dedup_and_stat_warn_pruning(self) -> None:
        identical_rows = [
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time=f"2026-11-22 10:55:0{i}",
                sql_text=sql,
            )
            for i, sql in enumerate(
                [
                    "SELECT COUNT(*) FROM SYS.NV",
                    "SELECT   COUNT(*)   FROM   SYS.NV",
                    "select count(*) from sys.nv",
                ]
            )
        ]
        alerts_1, _, _, _ = detector.analyze_audit_logs(
            identical_rows, [], [], _make_user_map("U3"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts_1), 1)
        self.assertTrue(alerts_1[0]["key"].startswith("STAT_WARN|U3|"))
        self.assertEqual(alerts_1[0]["risk_score"], 28)
        old_warn_key = alerts_1[0]["key"]

        escalated_rows = identical_rows + [
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:55:10",
                sql_text="SELECT SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam'",
            ),
            _make_audit_row(
                user="U3",
                userhost="ANALYST-PC03",
                os_username="stat_u3",
                event_time="2026-11-22 10:55:11",
                sql_text="SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nu'",
            ),
        ]
        alerts_2, _, _, _ = detector.analyze_audit_logs(
            escalated_rows, [], [], _make_user_map("U3"), state_store=self.store, policy=self.policy
        )
        keys_2 = [a["key"] for a in alerts_2]
        self.assertEqual(len(alerts_2), 1)
        self.assertTrue(keys_2[0].startswith("STAT_INF|U3|"))
        self.assertNotIn(old_warn_key, keys_2)
        self.assertNotIn(old_warn_key, self.store.snapshot()["alert_history"])

    def test_credential_scrubbing_in_alerts(self) -> None:
        rows = [
            _make_audit_row(
                event_time="2026-11-22 10:58:01",
                action="ALTER USER",
                object_name="",
                sql_text='ALTER USER U1 IDENTIFIED BY "MySecret!123"',
                return_code=1031,
            ),
            _make_audit_row(
                event_time="2026-11-22 10:58:02",
                action="SET ROLE",
                object_name="",
                sql_text="CONNECT U1/SecretPass",
                return_code=1031,
            ),
        ]
        alerts, _, _, _ = detector.analyze_audit_logs(
            rows, [], [], _make_user_map("U1"), state_store=self.store, policy=self.policy
        )
        self.assertEqual(len(alerts), 2)
        serialized = json.dumps(alerts, ensure_ascii=False)
        self.assertNotIn("MySecret!123", serialized)
        self.assertNotIn("SecretPass", serialized)
        self.assertIn("IDENTIFIED BY ***", serialized)
        self.assertIn("CONNECT U1/***", serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
