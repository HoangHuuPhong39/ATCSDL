"""Unit, concurrency, and persistence tests for oracle.state_store."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest

try:
    from oracle.state_store import StateStore, sanitize_details_passwords
except ImportError:  # pragma: no cover - direct execution inside oracle/
    _ORACLE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _ORACLE_DIR not in sys.path:
        sys.path.insert(0, _ORACLE_DIR)
    from state_store import StateStore, sanitize_details_passwords


def _alert(key: str, event_time: str, user: str = "U1", score: int = 65, details: str = "test") -> dict:
    return {
        "key": key,
        "severity": "HIGH",
        "risk_score": score,
        "response_level": 2,
        "response_label": "Level 2: HIGH (Privilege Containment)",
        "time": event_time,
        "user": user,
        "attack_type": "Test Alert",
        "details": details,
    }


class TestStateStore(unittest.TestCase):
    """Verify atomic persistence, corruption recovery, concurrency, and version guards."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self._tmpdir.name, ".ids_state.json")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_missing_and_corrupt_json_recovery_and_atomic_write(self) -> None:
        # Missing file initializes clean state without crashing
        store_missing = StateStore(self.state_file)
        snap = store_missing.snapshot()
        self.assertTrue(snap["auto_response"])
        self.assertEqual(snap["alert_history"], {})
        self.assertEqual(snap["dismissed_keys"], [])

        # Corrupt JSON, empty file, and non-dict root JSON all fall back cleanly
        for bad_payload in ("{corrupt json!!!", "", "   \n  ", '["not", "a", "dict"]'):
            with open(self.state_file, "w", encoding="utf-8") as fh:
                fh.write(bad_payload)
            recovered = StateStore(self.state_file)
            r_snap = recovered.snapshot()
            self.assertTrue(r_snap["auto_response"])
            self.assertEqual(r_snap["alert_history"], {})
            self.assertEqual(r_snap["dismissed_keys"], [])

        # Atomic write leaves valid JSON on disk and zero leftover .tmp files
        recovered.set_auto_response(False)
        recovered.dismiss_alert("K_ATOMIC")
        with open(self.state_file, "r", encoding="utf-8") as fh:
            persisted = json.load(fh)
        self.assertFalse(persisted["auto_response"])
        self.assertEqual(persisted["dismissed_keys"], ["K_ATOMIC"])
        leftovers = [f for f in os.listdir(self._tmpdir.name) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_multithreaded_concurrency_stress(self) -> None:
        store = StateStore(self.state_file, max_history=100, max_dismissed=200)
        errors: list[BaseException] = []
        err_lock = threading.Lock()
        barrier = threading.Barrier(10)

        def _worker(tid: int) -> None:
            try:
                barrier.wait(timeout=5)
                for step in range(25):
                    key = f"CONC|{tid}|{step}"
                    if step % 5 == 0:
                        ver = store.get_version()
                        store.merge_analyzed_alerts(
                            expected_version=ver,
                            new_alerts={
                                key: _alert(key, f"2026-11-22 10:{tid:02d}:{step:02d}", user=f"U{(tid % 4) + 1}")
                            },
                        )
                    elif step % 5 == 1:
                        store.dismiss_alert(f"CONC|{tid}|{step - 1}")
                    elif step % 5 == 2:
                        store.set_user_cleared_at(f"U{(tid % 4) + 1}", f"2026-11-22 10:00:{step:02d}")
                    elif step % 5 == 3:
                        store.set_auto_response((tid + step) % 2 == 0)
                    else:
                        snap = store.snapshot()
                        self.assertIsInstance(snap, dict)
                        self.assertIn("alert_history", snap)
            except BaseException as exc:  # pragma: no cover - captured for assertion
                with err_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            self.assertFalse(t.is_alive(), "Worker thread timed out")

        self.assertEqual(errors, [])
        self.assertTrue(os.path.isfile(self.state_file))
        with open(self.state_file, "r", encoding="utf-8") as fh:
            disk_state = json.load(fh)
        self.assertIsInstance(disk_state, dict)
        self.assertIn("dismissed_keys", disk_state)
        self.assertIn("alert_history", disk_state)

        reloaded = StateStore(self.state_file, max_history=100, max_dismissed=200)
        self.assertIsInstance(reloaded.snapshot()["user_cleared_at"], dict)

    def test_state_version_resurrection_guard(self) -> None:
        store = StateStore(self.state_file)
        v0 = store.get_version()
        ok_initial, active_initial = store.merge_analyzed_alerts(
            expected_version=v0,
            new_alerts={"OLD|1": _alert("OLD|1", "2026-11-22 10:00:00")},
        )
        self.assertTrue(ok_initial)
        self.assertEqual(len(active_initial), 1)

        # Simulate concurrent analysis capturing version before admin calls clear_all
        stale_version = store.get_version()
        store.clear_all("2026-11-22 10:05:00", monitored_users=("U1", "U2"))
        self.assertGreater(store.get_version(), stale_version)

        merged_ok, active_after_clear_all = store.merge_analyzed_alerts(
            expected_version=stale_version,
            new_alerts={
                "OLD|1": _alert("OLD|1", "2026-11-22 10:00:00"),
                "STALE|2": _alert("STALE|2", "2026-11-22 10:01:00"),
            },
        )
        self.assertFalse(merged_ok)
        self.assertEqual(active_after_clear_all, [])
        self.assertEqual(store.snapshot()["alert_history"], {})

        # Verify clear_ids also increments version and rejects stale merges
        stale_v2 = store.get_version()
        store.clear_ids("2026-11-22 10:06:00", monitored_users=("U1",))
        self.assertGreater(store.get_version(), stale_v2)
        merged_ok_2, active_after_clear_ids = store.merge_analyzed_alerts(
            expected_version=stale_v2,
            new_alerts={"STALE|3": _alert("STALE|3", "2026-11-22 10:05:30")},
        )
        self.assertFalse(merged_ok_2)
        self.assertEqual(active_after_clear_ids, [])

    def test_ordered_fifo_dismissed_keys_trimming(self) -> None:
        store = StateStore(self.state_file, max_dismissed=3)
        for key in ("K1", "K2", "K3", "K4", "K5"):
            store.dismiss_alert(key)
        # Re-dismissing an already present key must not duplicate or reorder
        store.dismiss_alert("K4")

        self.assertEqual(store.snapshot()["dismissed_keys"], ["K3", "K4", "K5"])

        # FGA and audit dismissed lists also keep oldest-first FIFO order
        for idx in range(1, 6):
            store.dismiss_fga(f"FGA_{idx}")
            store.dismiss_audit(f"AUD_{idx}")

        reloaded = StateStore(self.state_file, max_dismissed=3)
        r_snap = reloaded.snapshot()
        self.assertEqual(r_snap["dismissed_keys"], ["K3", "K4", "K5"])
        self.assertEqual(r_snap["dismissed_fga_keys"], ["FGA_3", "FGA_4", "FGA_5"])
        self.assertEqual(r_snap["dismissed_audit_keys"], ["AUD_3", "AUD_4", "AUD_5"])

    def test_bounded_alert_history_eviction(self) -> None:
        store = StateStore(self.state_file, max_history=3)
        alerts = {
            f"A{i}": _alert(f"A{i}", f"2026-11-22 10:00:0{i}")
            for i in range(1, 6)
        }
        merged_ok, _ = store.merge_analyzed_alerts(store.get_version(), alerts)
        self.assertTrue(merged_ok)

        history = store.snapshot()["alert_history"]
        self.assertEqual(len(history), 3)
        self.assertEqual(sorted(history.keys()), ["A3", "A4", "A5"])

        reloaded = StateStore(self.state_file, max_history=3)
        self.assertEqual(sorted(reloaded.snapshot()["alert_history"].keys()), ["A3", "A4", "A5"])

    def test_cutoffs_clear_reviewed_and_credential_sanitization(self) -> None:
        store = StateStore(self.state_file)
        v = store.get_version()
        store.merge_analyzed_alerts(
            v,
            {
                "A1": _alert("A1", "2026-11-22 10:00:10", details='ALTER USER U1 IDENTIFIED BY "TopSecret!"'),
                "A2": _alert("A2", "2026-11-22 10:00:20", details="CONNECT U1/Pass123@FREEPDB1"),
            },
        )
        snap = store.snapshot()
        self.assertNotIn("TopSecret!", snap["alert_history"]["A1"]["details"])
        self.assertNotIn("Pass123", snap["alert_history"]["A2"]["details"])
        self.assertEqual(sanitize_details_passwords("CONNECT U1/SecretPass"), "CONNECT U1/***")

        remaining = store.clear_reviewed(alert_keys=["A1"], fga_keys=["FGA_X"])
        self.assertEqual(remaining, 1)
        self.assertIn("FGA_X", store.snapshot()["dismissed_fga_keys"])

        store.set_user_cleared_at("U1", "2026-11-22 10:00:15")
        self.assertFalse(store.is_event_active_for_user_risk("U1", "2026-11-22 10:00:15"))
        self.assertTrue(store.is_event_active_for_user_risk("U1", "2026-11-22 10:00:16"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
