"""HTTP bridge authentication/validation and IPS security tests."""

from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

try:
    from oracle import bridge, detector, ips_actions
    from oracle.config import BridgeConfig
    from oracle.state_store import StateStore
except ImportError:  # pragma: no cover - direct execution inside oracle/
    _ORACLE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _ORACLE_DIR not in sys.path:
        sys.path.insert(0, _ORACLE_DIR)
    import bridge
    import detector
    import ips_actions
    from config import BridgeConfig
    from state_store import StateStore

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_POLICY_PATH = os.path.join(_REPO_ROOT, "shared", "detection_policy.json")


def _make_mock_db_client(policy_path: str = _POLICY_PATH) -> MagicMock:
    db = MagicMock()
    db.config = MagicMock()
    db.config.policy_path = policy_path

    conn = MagicMock()
    cur = MagicMock()
    cur.fetchall.return_value = []
    cur.fetchone.return_value = ("2026-11-22 12:00:00",)

    @contextmanager
    def _acquire():
        yield conn, cur

    db.acquire.side_effect = _acquire
    db._mock_conn = conn
    db._mock_cur = cur
    db.get_oracle_utc_now_str.return_value = "2026-11-22 12:00:00"
    db.flush_audit_trail.return_value = True
    db.fetch_users.return_value = [
        {
            "USERNAME": "U1",
            "ACCOUNT_STATUS": "OPEN",
            "LOCK_DATE": "",
            "DML_STATUS": "FULL DML",
            "PRIVILEGES": "DELETE, INSERT, SELECT, UPDATE",
        }
    ]
    db.fetch_audit_rows.return_value = [
        {
            "EVENT_TIMESTAMP": "2026-11-22 11:55:00",
            "DBUSERNAME": "U1",
            "ACTION_NAME": "SELECT",
            "OBJECT_SCHEMA": "SYS",
            "OBJECT_NAME": "NV",
            "SQL_TEXT": "SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP'",
            "RETURN_CODE": 0,
            "OS_USERNAME": "pc",
            "USERHOST": "LAPTOP-R03ORTGV",
            "CLIENT_PROGRAM_NAME": "SQL Developer",
            "AUDIT_TYPE": "Standard",
            "FGA_POLICY_NAME": "",
            "UNIFIED_AUDIT_POLICIES": "IDS_DML_NV_POL",
        }
    ]
    db.fetch_fga_rows.return_value = []
    db.fetch_failed_logons.return_value = [
        {
            "DBUSERNAME": "U1",
            "USERHOST": "192.168.56.109",
            "OS_USERNAME": "ext",
            "FAIL_COUNT": 3,
            "LAST_ATTEMPT": "2026-11-22 11:56:00",
            "CLIENT_PROGRAM_NAME": "sqlplus",
        }
    ]
    db.fetch_trigger_alerts.return_value = []
    db.fetch_employees.return_value = [
        {"MANV": "NV1", "HOTEN": "Nguyen Van A", "LUONG": 900, "GIOITINH": "Nam", "CMND": "001206012345"}
    ]
    return db


def _send_raw_http(host: str, port: int, raw_request: bytes) -> tuple[int, dict[str, str], bytes]:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(raw_request)
        sock.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    raw_resp = b"".join(chunks)
    head, _, body = raw_resp.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", errors="replace").split("\r\n")
    status_code = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status_code, headers, body


class TestBridgeHttpSecurity(unittest.TestCase):
    """Verify Bridge HTTP auth, redirect, body validation, and API routing."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self._tmpdir.name, ".ids_state.json")
        self.store = StateStore(self.state_file)
        self.policy = detector.load_policy(_POLICY_PATH)
        self.mock_db = _make_mock_db_client()
        self.token = "bridge-unit-test-token-9f8e7d"
        self.defense_health = {
            "trigger_ok": True,
            "fga_ok": True,
            "audit_ok": True,
            "crypto_policy_ok": True,
            "errors": [],
        }
        self.config = BridgeConfig(
            oracle_user="sys",
            oracle_password="",
            oracle_dsn="localhost:1521/FREEPDB1",
            oracle_auth_mode="sysdba",
            oracle_os_auth=True,
            oracle_client_mode="thin",
            oracle_lib_dir="",
            bridge_host="127.0.0.1",
            bridge_port=0,
            dashboard_url="http://localhost:3000",
            bridge_api_token=self.token,
            poll_interval_sec=2.0,
            monitored_users=("U1", "U2", "U3", "U4"),
            policy_path=_POLICY_PATH,
            state_file=self.state_file,
            max_request_body_bytes=2048,
        )
        self.server = bridge.create_bridge_http_server(
            self.config,
            self.mock_db,
            self.store,
            self.policy,
            self.defense_health,
        )
        self.port = self.server.server_port
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)
        self._tmpdir.cleanup()

    def _http_request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, resp_body
        finally:
            conn.close()

    def test_root_redirects_to_dashboard_without_following(self) -> None:
        status, headers, _ = self._http_request("GET", "/")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("location"), self.config.dashboard_url)

    def test_health_endpoint_returns_service_ok(self) -> None:
        status, _, body = self._http_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True, "service": "oracle-ids-bridge"})

    def test_api_endpoints_reject_missing_or_wrong_token(self) -> None:
        for method, path in (
            ("GET", "/api/data"),
            ("POST", "/api/toggle-ips"),
        ):
            status_no_hdr, _, body_no_hdr = self._http_request(method, path)
            self.assertEqual(status_no_hdr, 401)
            self.assertFalse(json.loads(body_no_hdr)["ok"])

            status_bad_tok, _, body_bad_tok = self._http_request(
                method,
                path,
                headers={"X-Bridge-Token": "wrong-token"},
            )
            self.assertEqual(status_bad_tok, 401)
            self.assertFalse(json.loads(body_bad_tok)["ok"])

    def test_api_data_with_flush_and_valid_token(self) -> None:
        status, _, body = self._http_request(
            "GET",
            "/api/data?flush=1",
            headers={"X-Bridge-Token": self.token},
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertIn("users", data)
        self.assertIn("alerts", data)
        self.assertIn("failed_logons", data)
        self.assertEqual(data["defense_health"], self.defense_health)
        self.assertGreaterEqual(len(data["alerts"]), 1)
        self.assertEqual(len(data["failed_logons"]), 1)
        self.mock_db.flush_audit_trail.assert_called_once_with(self.mock_db._mock_cur)

    def test_toggle_ips_updates_state_store(self) -> None:
        self.assertTrue(self.store.is_auto_response())
        status_off, _, body_off = self._http_request(
            "POST",
            "/api/toggle-ips",
            body=b'{"auto_response": false}',
            headers={"X-Bridge-Token": self.token, "Content-Type": "application/json"},
        )
        self.assertEqual(status_off, 200)
        self.assertEqual(json.loads(body_off), {"ok": True, "auto_response": False})
        self.assertFalse(self.store.is_auto_response())

        status_on, _, body_on = self._http_request(
            "POST",
            "/api/toggle-ips",
            body=b'{"auto_response": true}',
            headers={"X-Bridge-Token": self.token, "Content-Type": "application/json"},
        )
        self.assertEqual(status_on, 200)
        self.assertEqual(json.loads(body_on), {"ok": True, "auto_response": True})
        self.assertTrue(self.store.is_auto_response())

    def test_post_payload_too_large_returns_413(self) -> None:
        raw_req = (
            f"POST /api/toggle-ips HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"X-Bridge-Token: {self.token}\r\n"
            f"Content-Length: {self.config.max_request_body_bytes + 512}\r\n"
            f"\r\n"
        ).encode("ascii")
        status, _, body = _send_raw_http("127.0.0.1", self.port, raw_req)
        self.assertEqual(status, 413)
        self.assertFalse(json.loads(body)["ok"])

    def test_post_malformed_content_length_and_json_returns_400(self) -> None:
        for bad_cl in ("abc", "-5"):
            raw_req = (
                f"POST /api/toggle-ips HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.port}\r\n"
                f"X-Bridge-Token: {self.token}\r\n"
                f"Content-Length: {bad_cl}\r\n"
                f"\r\n"
            ).encode("ascii")
            status, _, body = _send_raw_http("127.0.0.1", self.port, raw_req)
            self.assertEqual(status, 400, f"Content-Length={bad_cl}")
            self.assertFalse(json.loads(body)["ok"])

        for bad_body in (b"{not-valid-json", b"[1, 2, 3]"):
            status, _, body = self._http_request(
                "POST",
                "/api/toggle-ips",
                body=bad_body,
                headers={"X-Bridge-Token": self.token, "Content-Type": "application/json"},
            )
            self.assertEqual(status, 400, f"body={bad_body!r}")
            self.assertFalse(json.loads(body)["ok"])

    def test_clear_alerts_forwards_fga_audit_keys_and_cutoff(self) -> None:
        # Verify argument forwarding directly into ips_actions.clear_alert_history
        with patch.object(
            ips_actions,
            "clear_alert_history",
            return_value=(True, "cleared"),
        ) as mocked_clear:
            payload = {
                "target": "single_fga",
                "fga_key": "FGA_KEY_123",
                "audit_key": "AUD_KEY_456",
                "cutoff": "2026-11-22 12:34:56",
            }
            status, _, body = self._http_request(
                "POST",
                "/api/clear-alerts",
                body=json.dumps(payload).encode("utf-8"),
                headers={"X-Bridge-Token": self.token, "Content-Type": "application/json"},
            )
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)["ok"])
            mocked_clear.assert_called_once()
            _, kwargs = mocked_clear.call_args
            self.assertEqual(kwargs["target"], "single_fga")
            self.assertEqual(kwargs["fga_key"], "FGA_KEY_123")
            self.assertEqual(kwargs["audit_key"], "AUD_KEY_456")
            self.assertEqual(kwargs["cutoff"], "2026-11-22 12:34:56")

        # Verify end-to-end persistence in state_store for single_fga, single_audit, and fga cutoff
        status, _, body = self._http_request(
            "POST",
            "/api/clear-alerts",
            body=json.dumps({"target": "single_fga", "fga_key": "FGA_E2E_1"}).encode("utf-8"),
            headers={"X-Bridge-Token": self.token, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.assertIn("FGA_E2E_1", self.store.snapshot()["dismissed_fga_keys"])

        status, _, body = self._http_request(
            "POST",
            "/api/clear-alerts",
            body=json.dumps({"target": "single_audit", "audit_key": "AUD_E2E_1"}).encode("utf-8"),
            headers={"X-Bridge-Token": self.token, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.assertIn("AUD_E2E_1", self.store.snapshot()["dismissed_audit_keys"])

        status, _, body = self._http_request(
            "POST",
            "/api/clear-alerts",
            body=json.dumps({"target": "fga", "cutoff": "2026-11-22 12:45:00"}).encode("utf-8"),
            headers={"X-Bridge-Token": self.token, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.assertEqual(self.store.snapshot()["fga_cleared_at"], "2026-11-22 12:45:00")


class TestIpsActionsSecurity(unittest.TestCase):
    """Verify identifier allowlisting, SQLi/protected-account rejection, and scoped clearing."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self._tmpdir.name, ".ids_state.json")
        self.store = StateStore(self.state_file)
        self.mock_db = _make_mock_db_client()
        self.protected = ips_actions.load_protected_accounts(_POLICY_PATH)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_validate_oracle_identifier_accepts_lab_users_and_rejects_bad_inputs(self) -> None:
        for valid_raw, expected in (
            ("U1", "U1"),
            ("u2", "U2"),
            (" U3 ", "U3"),
            ("U4", "U4"),
            ("lab_user_1", "LAB_USER_1"),
            ("APP$USER#1", "APP$USER#1"),
        ):
            self.assertEqual(
                ips_actions.validate_oracle_identifier(valid_raw, protected_accounts=self.protected),
                expected,
            )

        bad_inputs = (
            "SYS",
            "sys",
            "SYSTEM",
            "PUBLIC",
            "PDBADMIN",
            "AUDSYS",
            "DBSNMP",
            "OUTLN",
            "XDB",
            "",
            "   ",
            "1INVALID",
            "U1; DROP TABLE NV",
            "U1' OR '1'='1",
            "U1--comment",
            "A" * 129,
        )
        for bad in bad_inputs:
            with self.assertRaises(ValueError, msg=f"Should reject {bad!r}"):
                ips_actions.validate_oracle_identifier(bad, protected_accounts=self.protected)

        with self.assertRaises(ValueError):
            ips_actions.validate_oracle_identifier(123, protected_accounts=self.protected)  # type: ignore[arg-type]

    def test_ips_actions_reject_protected_accounts_and_sqli_before_db_access(self) -> None:
        rejected_inputs = (
            "SYS",
            "SYSTEM",
            "PUBLIC",
            "PDBADMIN",
            "AUDSYS",
            "U1; DROP TABLE NV",
            "U1' OR '1'='1",
        )
        for bad_user in rejected_inputs:
            ok1, _ = ips_actions.lock_user(self.mock_db, bad_user)
            ok2, _ = ips_actions.unlock_user(self.mock_db, self.store, bad_user)
            ok3, _ = ips_actions.revoke_dml_user(self.mock_db, bad_user)
            ok4, _ = ips_actions.grant_dml_user(self.mock_db, self.store, bad_user)
            self.assertFalse(ok1, f"lock_user accepted {bad_user!r}")
            self.assertFalse(ok2, f"unlock_user accepted {bad_user!r}")
            self.assertFalse(ok3, f"revoke_dml_user accepted {bad_user!r}")
            self.assertFalse(ok4, f"grant_dml_user accepted {bad_user!r}")

        self.mock_db.acquire.assert_not_called()

    def test_ips_actions_valid_user_uses_dbms_assert_bind_parameters(self) -> None:
        ok, _ = ips_actions.lock_user(self.mock_db, "u1")
        self.assertTrue(ok)
        executed_sqls = [call.args[0] for call in self.mock_db._mock_cur.execute.call_args_list]
        self.assertTrue(any("DBMS_ASSERT.SIMPLE_SQL_NAME(:u)" in sql for sql in executed_sqls))

    def test_clear_alert_history_reviewed_fga_preserves_alert_history_and_audit_trail(self) -> None:
        v = self.store.get_version()
        self.store.merge_analyzed_alerts(
            v,
            {
                "ALERT_KEEP_1": {
                    "key": "ALERT_KEEP_1",
                    "severity": "HIGH",
                    "risk_score": 65,
                    "time": "2026-11-22 11:00:00",
                    "user": "U1",
                    "attack_type": "Trigger Block",
                    "details": "Should remain untouched",
                }
            },
        )

        ok, _ = ips_actions.clear_alert_history(
            self.mock_db,
            self.store,
            target="reviewed",
            reviewed_fga_keys=["FGA_1", "FGA_2"],
        )
        self.assertTrue(ok)

        snap = self.store.snapshot()
        self.assertEqual(snap["dismissed_fga_keys"], ["FGA_1", "FGA_2"])
        self.assertIn("ALERT_KEEP_1", snap["alert_history"])
        self.assertEqual(snap["dismissed_keys"], [])
        self.assertEqual(snap["dismissed_audit_keys"], [])

        executed_sqls = " ".join(str(call.args[0]) for call in self.mock_db._mock_cur.execute.call_args_list)
        self.assertNotIn("CLEAN_AUDIT_TRAIL", executed_sqls)
        self.assertNotIn("IDS_TRIGGER_ALERTS", executed_sqls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
