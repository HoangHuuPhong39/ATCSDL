"""Thread-safe atomic JSON state store for the Oracle DB-IDS engine."""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import tempfile
import threading
from typing import Any, Iterable

logger = logging.getLogger(__name__)

_IDENTIFIED_BY_PATTERN = re.compile(
    r"""\bIDENTIFIED\s+BY\s+(?:VALUES\s+(?:'[^']*'|"[^"]*"|[^\s;]+)|(?:"[^"]*"|'[^']*'|[^\s;]+))(?:\s+REPLACE\s+(?:"[^"]*"|'[^']*'|[^\s;]+))?""",
    re.IGNORECASE,
)
_CONNECT_CRED_PATTERN = re.compile(
    r"""\b(CONN(?:ECT)?)\s+([A-Za-z0-9_#$.]+|"[^"]+")\s*/\s*("[^"]*"|'[^']*'|[^\s@;]+)""",
    re.IGNORECASE,
)


def sanitize_details_passwords(text: str) -> str:
    """Scrub Oracle credentials (`IDENTIFIED BY ...` and `CONNECT user/pass`) from text."""
    if text is None:
        return ""
    cleaned = str(text)
    if not cleaned:
        return ""
    cleaned = _IDENTIFIED_BY_PATTERN.sub("IDENTIFIED BY ***", cleaned)
    cleaned = _CONNECT_CRED_PATTERN.sub(r"\1 \2/***", cleaned)
    return cleaned


def _dedup_fifo(items: Iterable[Any], max_len: int) -> list[str]:
    """Deduplicate items while preserving insertion order and keeping only the latest `max_len`."""
    deduped = list(
        dict.fromkeys(str(item) for item in items if item is not None and str(item) != "")
    )
    if len(deduped) > max_len:
        return deduped[-max_len:]
    return deduped


def _append_fifo_dedup(items: list[str], key: str, max_len: int) -> None:
    """Append `key` if absent and trim oldest entries beyond `max_len`."""
    if not key or key in items:
        return
    items.append(key)
    if len(items) > max_len:
        del items[: len(items) - max_len]


class StateStore:
    """Thread-safe, versioned, and atomically persisted state container for DB-IDS."""

    def __init__(
        self,
        state_file: str,
        max_history: int = 500,
        max_dismissed: int = 1000,
    ) -> None:
        self.state_file = str(state_file)
        self.max_history = max(1, int(max_history))
        self.max_dismissed = max(1, int(max_dismissed))
        self._lock = threading.RLock()
        self._version: int = 0
        self._state: dict[str, Any] = self._default_state()
        self.load()

    @staticmethod
    def _default_state() -> dict[str, Any]:
        return {
            "auto_response": True,
            "alerts_cleared_at": "",
            "fga_cleared_at": "",
            "audit_cleared_at": "",
            "user_cleared_at": {},
            "dismissed_keys": [],
            "dismissed_fga_keys": [],
            "dismissed_audit_keys": [],
            "alert_history": {},
            "initialized_users": [],
        }

    @property
    def version(self) -> int:
        """Monotonically increasing state version incremented on every explicit state mutation."""
        with self._lock:
            return self._version

    def get_version(self) -> int:
        """Return the current state version."""
        with self._lock:
            return self._version

    def _cap_history_locked(self) -> None:
        history: dict[str, dict] = self._state["alert_history"]
        excess = len(history) - self.max_history
        if excess <= 0:
            return
        oldest_keys = sorted(
            history.keys(),
            key=lambda k: (str(history[k].get("time", "")), str(k)),
        )[:excess]
        for key in oldest_keys:
            history.pop(key, None)

    def _collect_active_alerts_locked(self) -> list[dict]:
        dismissed = set(self._state["dismissed_keys"])
        global_cut = str(self._state.get("alerts_cleared_at") or "")
        active: list[dict] = []
        for key, item in self._state["alert_history"].items():
            if key in dismissed:
                continue
            ev_time = str(item.get("time") or "")
            if global_cut and ev_time and ev_time <= global_cut:
                continue
            active.append(copy.deepcopy(item))
        active.sort(
            key=lambda x: (str(x.get("time") or ""), int(x.get("risk_score") or 0)),
            reverse=True,
        )
        return active

    def _save_locked(self) -> None:
        parent_dir = os.path.dirname(os.path.abspath(self.state_file)) or "."
        os.makedirs(parent_dir, exist_ok=True)
        payload = {
            "auto_response": bool(self._state["auto_response"]),
            "alerts_cleared_at": str(self._state["alerts_cleared_at"]),
            "fga_cleared_at": str(self._state["fga_cleared_at"]),
            "audit_cleared_at": str(self._state["audit_cleared_at"]),
            "user_cleared_at": dict(self._state["user_cleared_at"]),
            "dismissed_keys": list(self._state["dismissed_keys"][-self.max_dismissed :]),
            "dismissed_fga_keys": list(self._state["dismissed_fga_keys"][-self.max_dismissed :]),
            "dismissed_audit_keys": list(
                self._state["dismissed_audit_keys"][-self.max_dismissed :]
            ),
            "alert_history": copy.deepcopy(self._state["alert_history"]),
            "initialized_users": list(self._state["initialized_users"]),
        }

        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=parent_dir,
                prefix=".ids_state.",
                suffix=".tmp",
                delete=False,
            ) as tmp_file:
                tmp_path = tmp_file.name
                json.dump(payload, tmp_file, ensure_ascii=False, indent=2)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_path, self.state_file)
            tmp_path = None
        except Exception:
            logger.exception("Failed to atomically persist state file: %s", self.state_file)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError as exc:
                    logger.warning("Failed to remove temporary state file %s: %s", tmp_path, exc)

    def save(self) -> None:
        """Atomically persist the current state snapshot to disk."""
        with self._lock:
            self._save_locked()

    def load(self) -> None:
        """Load persisted JSON state safely; falls back to clean defaults on missing/corrupt data."""
        with self._lock:
            default_state = self._default_state()
            if not os.path.exists(self.state_file):
                self._state = default_state
                return

            try:
                with open(self.state_file, "r", encoding="utf-8") as fh:
                    raw_text = fh.read()
            except OSError as exc:
                logger.warning("Could not read state file %s (%s); using clean state.", self.state_file, exc)
                self._state = default_state
                return

            if not raw_text.strip():
                logger.warning("State file %s is empty; initializing clean state.", self.state_file)
                self._state = default_state
                return

            try:
                raw = json.loads(raw_text)
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning("Corrupted JSON in state file %s (%s); initializing clean state.", self.state_file, exc)
                self._state = default_state
                return

            if not isinstance(raw, dict):
                logger.warning("Invalid root JSON type in state file %s; initializing clean state.", self.state_file)
                self._state = default_state
                return

            user_cleared_raw = raw.get("user_cleared_at")
            user_cleared = (
                {
                    str(k).strip().upper(): str(v)
                    for k, v in user_cleared_raw.items()
                    if str(k).strip() and v is not None
                }
                if isinstance(user_cleared_raw, dict)
                else {}
            )

            history_raw = raw.get("alert_history")
            sanitized_history: dict[str, dict] = {}
            if isinstance(history_raw, dict):
                for k, val in history_raw.items():
                    if not isinstance(val, dict):
                        continue
                    ks = str(k)
                    item = copy.deepcopy(val)
                    item.setdefault("key", ks)
                    if item.get("details") is not None:
                        item["details"] = sanitize_details_passwords(str(item["details"]))
                    sanitized_history[ks] = item

            init_users_raw = raw.get("initialized_users")
            init_users = (
                list(
                    dict.fromkeys(
                        str(u).strip().upper()
                        for u in init_users_raw
                        if u is not None and str(u).strip()
                    )
                )
                if isinstance(init_users_raw, list)
                else []
            )

            dismissed_raw = raw.get("dismissed_keys")
            dismissed_fga_raw = raw.get("dismissed_fga_keys")
            dismissed_audit_raw = raw.get("dismissed_audit_keys")

            self._state = {
                "auto_response": bool(raw.get("auto_response", True)),
                "alerts_cleared_at": str(raw.get("alerts_cleared_at") or ""),
                "fga_cleared_at": str(raw.get("fga_cleared_at") or ""),
                "audit_cleared_at": str(raw.get("audit_cleared_at") or ""),
                "user_cleared_at": user_cleared,
                "dismissed_keys": _dedup_fifo(
                    dismissed_raw if isinstance(dismissed_raw, list) else (), self.max_dismissed
                ),
                "dismissed_fga_keys": _dedup_fifo(
                    dismissed_fga_raw if isinstance(dismissed_fga_raw, list) else (),
                    self.max_dismissed,
                ),
                "dismissed_audit_keys": _dedup_fifo(
                    dismissed_audit_raw if isinstance(dismissed_audit_raw, list) else (),
                    self.max_dismissed,
                ),
                "alert_history": sanitized_history,
                "initialized_users": init_users,
            }
            self._cap_history_locked()

    def snapshot(self) -> dict[str, Any]:
        """Return a deep-copied snapshot of the full persisted state and current version."""
        with self._lock:
            snap = copy.deepcopy(self._state)
            snap["version"] = self._version
            return snap

    def is_auto_response(self) -> bool:
        """Return whether automated IPS response is enabled."""
        with self._lock:
            return bool(self._state["auto_response"])

    def set_auto_response(self, enabled: bool) -> bool:
        """Enable or disable automated IPS response, bump version, and persist."""
        with self._lock:
            self._state["auto_response"] = bool(enabled)
            self._version += 1
            self._save_locked()
            return self._state["auto_response"]

    def set_user_cleared_at(self, username: str, ts_utc: str) -> None:
        """Update per-user risk cutoff timestamp, bump version, and persist."""
        uname = str(username or "").strip().upper()
        if not uname:
            return
        with self._lock:
            self._state["user_cleared_at"][uname] = str(ts_utc or "")
            self._version += 1
            self._save_locked()

    def mark_user_initialized(self, username: str) -> None:
        """Persist a monitored user as initialized, bump version, and persist."""
        uname = str(username or "").strip().upper()
        if not uname:
            return
        with self._lock:
            if uname not in self._state["initialized_users"]:
                self._state["initialized_users"].append(uname)
            self._version += 1
            self._save_locked()

    def is_user_initialized(self, username: str) -> bool:
        """Check whether a user has already been marked as initialized."""
        uname = str(username or "").strip().upper()
        if not uname:
            return False
        with self._lock:
            return uname in self._state["initialized_users"]

    def dismiss_alert(self, alert_key: str) -> None:
        """Dismiss a single IDS alert key, remove from history, bump version, and persist."""
        key = str(alert_key or "")
        if not key:
            return
        with self._lock:
            _append_fifo_dedup(self._state["dismissed_keys"], key, self.max_dismissed)
            self._state["alert_history"].pop(key, None)
            self._version += 1
            self._save_locked()

    def dismiss_fga(self, fga_key: str) -> None:
        """Dismiss a single FGA event key, bump version, and persist."""
        key = str(fga_key or "")
        if not key:
            return
        with self._lock:
            _append_fifo_dedup(self._state["dismissed_fga_keys"], key, self.max_dismissed)
            self._version += 1
            self._save_locked()

    def dismiss_audit(self, audit_key: str) -> None:
        """Dismiss a single audit log row key, bump version, and persist."""
        key = str(audit_key or "")
        if not key:
            return
        with self._lock:
            _append_fifo_dedup(self._state["dismissed_audit_keys"], key, self.max_dismissed)
            self._version += 1
            self._save_locked()

    def clear_reviewed(
        self,
        alert_keys: Iterable[str] | None = None,
        fga_keys: Iterable[str] | None = None,
        audit_keys: Iterable[str] | None = None,
    ) -> int:
        """Remove only the provided reviewed keys and return remaining non-dismissed alert count."""
        with self._lock:
            for key in alert_keys or ():
                ks = str(key)
                if not ks:
                    continue
                _append_fifo_dedup(self._state["dismissed_keys"], ks, self.max_dismissed)
                self._state["alert_history"].pop(ks, None)

            for fkey in fga_keys or ():
                fks = str(fkey)
                if fks:
                    _append_fifo_dedup(
                        self._state["dismissed_fga_keys"], fks, self.max_dismissed
                    )

            for akey in audit_keys or ():
                aks = str(akey)
                if aks:
                    _append_fifo_dedup(
                        self._state["dismissed_audit_keys"], aks, self.max_dismissed
                    )

            self._version += 1
            self._save_locked()
            dismissed = set(self._state["dismissed_keys"])
            return sum(1 for k in self._state["alert_history"] if k not in dismissed)

    def clear_ids(self, ts_utc: str, monitored_users: Iterable[str] | None = None) -> None:
        """Clear IDS alert history at `ts_utc`, bump version, and persist."""
        ts = str(ts_utc or "")
        with self._lock:
            self._state["alerts_cleared_at"] = ts
            self._state["dismissed_keys"] = []
            self._state["alert_history"] = {}
            if monitored_users is not None:
                for user in monitored_users:
                    uname = str(user or "").strip().upper()
                    if uname:
                        self._state["user_cleared_at"][uname] = ts
            self._version += 1
            self._save_locked()

    def clear_fga(self, ts_utc: str) -> None:
        """Clear FGA history at `ts_utc`, bump version, and persist."""
        with self._lock:
            self._state["fga_cleared_at"] = str(ts_utc or "")
            self._state["dismissed_fga_keys"] = []
            self._version += 1
            self._save_locked()

    def clear_audit(self, ts_utc: str) -> None:
        """Clear unified audit log history at `ts_utc`, bump version, and persist."""
        with self._lock:
            self._state["audit_cleared_at"] = str(ts_utc or "")
            self._state["dismissed_audit_keys"] = []
            self._version += 1
            self._save_locked()

    def clear_all(self, ts_utc: str, monitored_users: Iterable[str] | None = None) -> None:
        """Clear all IDS/FGA/audit histories at `ts_utc`, bump version, and persist."""
        ts = str(ts_utc or "")
        with self._lock:
            self._state["alerts_cleared_at"] = ts
            self._state["fga_cleared_at"] = ts
            self._state["audit_cleared_at"] = ts
            self._state["dismissed_keys"] = []
            self._state["dismissed_fga_keys"] = []
            self._state["dismissed_audit_keys"] = []
            self._state["alert_history"] = {}
            if monitored_users is not None:
                for user in monitored_users:
                    uname = str(user or "").strip().upper()
                    if uname:
                        self._state["user_cleared_at"][uname] = ts
            self._version += 1
            self._save_locked()

    def merge_analyzed_alerts(
        self,
        expected_version: int,
        new_alerts: dict[str, dict],
        pruned_warn_keys: set[str] | None = None,
    ) -> tuple[bool, list[dict]]:
        """
        Atomically merge newly analyzed alerts if `self._version == expected_version`.

        Prevents alert resurrection races when an admin clears or dismisses alerts
        concurrently with a background detection pass.
        """
        with self._lock:
            if self._version != expected_version:
                return False, self._collect_active_alerts_locked()

            changed = False
            history = self._state["alert_history"]

            if pruned_warn_keys:
                for warn_key in pruned_warn_keys:
                    if history.pop(str(warn_key), None) is not None:
                        changed = True

            dismissed = set(self._state["dismissed_keys"])
            global_cut = str(self._state.get("alerts_cleared_at") or "")
            for raw_key, raw_item in (new_alerts or {}).items():
                key = str(raw_key)
                if key in dismissed:
                    continue
                item = copy.deepcopy(dict(raw_item))
                item.setdefault("key", key)
                ev_time = str(item.get("time") or "")
                if global_cut and ev_time and ev_time <= global_cut:
                    continue
                if item.get("details") is not None:
                    item["details"] = sanitize_details_passwords(str(item["details"]))
                if history.get(key) != item:
                    history[key] = item
                    changed = True

            prev_len = len(history)
            self._cap_history_locked()
            if len(history) != prev_len:
                changed = True

            if changed or not os.path.exists(self.state_file):
                self._save_locked()

            return True, self._collect_active_alerts_locked()

    def is_event_cleared(self, user: str, event_time: str) -> bool:
        """Return True if the event timestamp falls on or before the global IDS clear cutoff."""
        if not event_time:
            return False
        with self._lock:
            global_cut = str(self._state.get("alerts_cleared_at") or "")
            return bool(global_cut and str(event_time) <= global_cut)

    def is_event_active_for_user_risk(self, user: str, event_time: str) -> bool:
        """Return True if an event is newer than both global clear and user-specific reset cutoffs."""
        uname = str(user or "").strip().upper()
        if not uname or not event_time:
            return False
        with self._lock:
            user_cut = str(self._state["user_cleared_at"].get(uname, ""))
            global_cut = str(self._state.get("alerts_cleared_at") or "")
            cutoff = max(user_cut, global_cut)
            if cutoff and str(event_time) <= cutoff:
                return False
            return True
