"""Slim Oracle 23ai IDS Telemetry & Active IPS Bridge Orchestrator."""

from __future__ import annotations

import hmac
import json
import logging
import os
import sys
import threading
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

try:
    from oracle import detector, ips_actions
    from oracle.config import BridgeConfig, load_config
    from oracle.db_client import OracleDbClient, sanitize_sql_credentials
    from oracle.detector import is_benign_ide_metadata_query, load_policy
    from oracle.state_store import StateStore
except ImportError:  # pragma: no cover - direct execution inside oracle/
    import detector
    import ips_actions
    from config import BridgeConfig, load_config
    from db_client import OracleDbClient, sanitize_sql_credentials
    from detector import is_benign_ide_metadata_query, load_policy
    from state_store import StateStore

logger = logging.getLogger("oracle_ids.bridge")
_MAX_EXECUTED_CMD_CACHE = 500
_MAX_BACKOFF_SEC = 30.0


def configure_logging(level: int = logging.INFO) -> None:
    """Reconfigure stdio to UTF-8 safely and initialize structured logging."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:
                pass
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _fga_key(r: dict[str, Any]) -> str:
    return f"{r.get('EVENT_TIMESTAMP')}_{r.get('DBUSERNAME')}_{r.get('FGA_POLICY_NAME')}_{r.get('SQL_TEXT') or ''}"


def _audit_key(r: dict[str, Any]) -> str:
    return f"{r.get('EVENT_TIMESTAMP')}_{r.get('DBUSERNAME')}_{r.get('ACTION_NAME')}_{(r.get('SQL_TEXT') or '')[:40]}"


def _coerce_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _safe_call(label: str, fn: Callable[..., list[dict[str, Any]]], *args: Any) -> list[dict[str, Any]]:
    try:
        return fn(*args)
    except Exception as exc:
        logger.warning("Failed fetching %s: %s", label, exc)
        return []


def _supplement_fga_rows(
    fga_rows: list[dict[str, Any]],
    trig_rows: list[dict[str, Any]],
    fga_cutoff: str,
    dismissed_fga: set[str],
) -> list[dict[str, Any]]:
    """Supplement FGA records with blocked ORA-20003 rows from IDS_TRIGGER_ALERTS."""
    existing_sigs = {f"{r.get('EVENT_TIMESTAMP')}_{r.get('DBUSERNAME')}_{r.get('FGA_POLICY_NAME')}" for r in fga_rows}
    for tr in trig_rows:
        t_type = str(tr.get("ATTACK_TYPE") or "").upper()
        t_time, t_user = str(tr.get("EVENT_TIME") or ""), str(tr.get("DB_USER") or "")
        t_sql = sanitize_sql_credentials(str(tr.get("DETAILS") or ""))
        if ("HONEYTOKEN" in t_type or "SQL_INJECTION" in t_type) and (not fga_cutoff or t_time > fga_cutoff):
            sig = f"{t_time}_{t_user}_FGA_HONEYTOKEN_TRAP"
            if sig not in existing_sigs and f"{sig}_{t_sql}" not in dismissed_fga:
                fga_rows.append({
                    "EVENT_TIMESTAMP": t_time, "DBUSERNAME": t_user,
                    "ACTION_NAME": "SELECT (BLOCKED ORA-20003)", "OBJECT_SCHEMA": "SYS", "OBJECT_NAME": "NV",
                    "FGA_POLICY_NAME": "FGA_HONEYTOKEN_TRAP", "AUDIT_TYPE": "FineGrainedAudit",
                    "SQL_TEXT": t_sql, "OS_USERNAME": "—", "USERHOST": "SYS.IDS_FGA_TRAP_HANDLER",
                    "CLIENT_PROGRAM_NAME": "SQL Developer (Blocked)", "RETURN_CODE": 20003,
                })
                existing_sigs.add(sig)
    fga_rows.sort(key=lambda x: str(x.get("EVENT_TIMESTAMP") or ""), reverse=True)
    return fga_rows


class BridgeService:
    """Orchestrates Oracle telemetry collection, detection analysis, and IPS actions."""

    def __init__(
        self,
        config: BridgeConfig,
        db_client: Any = None,
        state_store: Any = None,
        policy: dict[str, Any] | None = None,
        defense_health: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.db_client = db_client
        self.state_store = state_store
        self.policy = policy
        self.defense_health = defense_health
        self._collect_lock = threading.Lock()

    def attach_runtime(
        self, db_client: Any, state_store: Any, policy: dict[str, Any], defense_health: dict[str, Any] | None
    ) -> None:
        """Attach runtime dependencies after HTTP port ownership is secured."""
        self.db_client, self.state_store, self.policy, self.defense_health = (
            db_client, state_store, policy, defense_health
        )

    def collect_dashboard_data(self, do_flush: bool = False) -> dict[str, Any]:
        """Collect Oracle telemetry, evaluate IDS policies, and return dashboard JSON."""
        with self._collect_lock:
            return self._collect_locked(do_flush=do_flush)

    def _collect_locked(self, do_flush: bool = False) -> dict[str, Any]:
        auto_response = bool(self.state_store.is_auto_response()) if self.state_store is not None else True
        try:
            if self.db_client is None or self.state_store is None:
                raise RuntimeError("Bridge runtime dependencies are not initialized.")
            snap = self.state_store.snapshot()
            auto_response = bool(snap.get("auto_response", auto_response))
            cutoff_utc = str(snap.get("alerts_cleared_at") or "1970-01-01 00:00:00")
            fga_cutoff = max(cutoff_utc, str(snap.get("fga_cleared_at") or ""))
            dismissed_fga = set(snap.get("dismissed_fga_keys", []))
            policy = self.policy if self.policy is not None else {}

            with self.db_client.acquire() as (_conn, cur):
                if do_flush:
                    self.db_client.flush_audit_trail(cur)
                initial_users = self.db_client.fetch_users(cur, self.config.monitored_users)
                user_info_map: dict[str, dict[str, Any]] = {}
                for row in initial_users:
                    uname = str(row.get("USERNAME") or "").strip().upper()
                    if uname:
                        row["USERNAME"] = uname
                        row.setdefault("DML_STATUS", "READ-ONLY")
                        row.setdefault("PRIVILEGES", "NONE")
                        user_info_map[uname] = row

                monitored = list(user_info_map.keys()) or [
                    str(u).strip().upper() for u in self.config.monitored_users if str(u).strip()
                ]
                audit_rows = self.db_client.fetch_audit_rows(cur, monitored, cutoff_utc)
                raw_fga = _safe_call("FGA rows", self.db_client.fetch_fga_rows, cur, monitored, fga_cutoff)
                fga_rows = [r for r in raw_fga if _fga_key(r) not in dismissed_fga]

                bf_win = int(((policy.get("brute_force") or {}).get("window_minutes", 15)))
                failed_rows = (
                    self.db_client.fetch_failed_logons(cur, monitored, cutoff_utc, window_minutes=bf_win)
                    if bf_win != 15
                    else self.db_client.fetch_failed_logons(cur, monitored, cutoff_utc)
                )
                trig_rows = _safe_call("trigger alerts", self.db_client.fetch_trigger_alerts, cur)
                fga_rows = _supplement_fga_rows(fga_rows, trig_rows, fga_cutoff, dismissed_fga)

                alerts, auto_locked, auto_revoked, risk_summary = detector.analyze_audit_logs(
                    audit_rows, failed_rows, trig_rows, user_info_map,
                    state_store=self.state_store, policy=policy, db_client=self.db_client,
                    auto_block=self.state_store.is_auto_response(), ips_actions_module=ips_actions,
                )
                user_rows = (
                    self.db_client.fetch_users(cur, self.config.monitored_users)
                    if (auto_locked or auto_revoked) else initial_users
                )
                employees = _safe_call("employees", self.db_client.fetch_employees, cur)

            default_lvl0 = str(((policy.get("thresholds") or {}).get("level_0") or {}).get("label", "Level 0: Normal (An toàn)"))
            for u_row in user_rows:
                uname = str(u_row.get("USERNAME") or "").strip().upper()
                u_row["USERNAME"] = uname
                r_sum = risk_summary.get(uname, {})
                u_row["RISK_SCORE"] = r_sum.get("risk_score", 0)
                u_row["RESPONSE_LEVEL"] = r_sum.get("response_level", 0)
                u_row["RESPONSE_LABEL"] = r_sum.get("response_label", default_lvl0)

            audit_cutoff = max(cutoff_utc, str(snap.get("audit_cleared_at") or ""))
            dismissed_audit = set(snap.get("dismissed_audit_keys", []))
            display_audit_rows = [
                r for r in audit_rows
                if (not audit_cutoff or str(r.get("EVENT_TIMESTAMP") or "") > audit_cutoff)
                and not is_benign_ide_metadata_query(r, policy)
                and _audit_key(r) not in dismissed_audit
            ]
            return {
                "ok": True, "timestamp": _utc_now_str(), "dsn": self.config.oracle_dsn,
                "auto_response": auto_response, "alerts_cleared_at": str(snap.get("alerts_cleared_at") or ""),
                "auto_locked": auto_locked, "auto_revoked": auto_revoked, "defense_health": self.defense_health,
                "metrics": {
                    "audit_count": len(display_audit_rows), "alert_count": len(alerts),
                    "trigger_count": len(trig_rows), "fga_count": len(fga_rows),
                    "locked_count": sum(1 for u in user_rows if "LOCK" in str(u.get("ACCOUNT_STATUS", "")).upper()),
                    "readonly_count": sum(1 for u in user_rows if str(u.get("DML_STATUS", "")).upper() == "READ-ONLY"),
                    "max_risk": max((int(u.get("RISK_SCORE", 0)) for u in user_rows), default=0),
                },
                "users": user_rows, "alerts": alerts, "fga_events": fga_rows, "triggers": trig_rows,
                "audit_logs": display_audit_rows, "failed_logons": failed_rows, "employees": employees,
            }
        except Exception as exc:
            logger.warning("Failed collecting dashboard data: %s", exc)
            return {
                "ok": False, "error": str(exc), "timestamp": _utc_now_str(),
                "dsn": self.config.oracle_dsn, "auto_response": auto_response,
            }

    def execute_user_action(self, username: str, action: str) -> tuple[bool, str]:
        """Dispatch a manual IPS user action ('lock', 'unlock', 'revoke_dml', 'grant_dml')."""
        if self.db_client is None:
            return False, "Bridge DB client is not initialized."
        dispatch: dict[str, Callable[[], tuple[bool, str]]] = {
            "lock": lambda: ips_actions.lock_user(self.db_client, username),
            "unlock": lambda: ips_actions.unlock_user(self.db_client, self.state_store, username),
            "revoke_dml": lambda: ips_actions.revoke_dml_user(self.db_client, username),
            "grant_dml": lambda: ips_actions.grant_dml_user(self.db_client, self.state_store, username),
        }
        handler = dispatch.get(str(action or "").strip().lower())
        return handler() if handler else (False, f"Hành động không hợp lệ: {action!r}")

    def execute_clear_alerts(self, payload: dict[str, Any]) -> tuple[bool, str]:
        """Clear selected or scoped IDS/FGA/Trigger/Audit history via ips_actions."""
        if self.db_client is None:
            return False, "Bridge DB client is not initialized."
        if not isinstance(payload, dict):
            return False, "Invalid clear-alerts payload."
        return ips_actions.clear_alert_history(
            self.db_client, self.state_store, target=payload.get("target", "all"),
            alert_id=payload.get("alert_id"), alert_key=payload.get("alert_key"),
            fga_key=payload.get("fga_key"), audit_key=payload.get("audit_key"),
            reviewed_keys=payload.get("reviewed_keys"), reviewed_fga_keys=payload.get("reviewed_fga_keys"),
            reviewed_trigger_ids=payload.get("reviewed_trigger_ids"),
            reviewed_audit_keys=payload.get("reviewed_audit_keys"),
            cutoff=payload.get("cutoff"), monitored_users=self.config.monitored_users,
        )

    def toggle_ips(self, auto_response: bool) -> bool:
        """Persist and return the automated IPS response state."""
        if self.state_store is None:
            raise RuntimeError("StateStore is not initialized.")
        return bool(self.state_store.set_auto_response(bool(auto_response)))


class BridgeHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying BridgeConfig and BridgeService."""

    allow_reuse_address = os.name != "nt"
    daemon_threads = True

    def __init__(
        self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler],
        config: BridgeConfig, service: BridgeService,
    ) -> None:
        self.config, self.service = config, service
        super().__init__(server_address, RequestHandlerClass)


class IDSRequestHandler(BaseHTTPRequestHandler):
    """Authenticated JSON API and dashboard redirect handler for the Oracle Bridge."""

    server: BridgeHTTPServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("%s - %s", self.address_string(), format % args)

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, message: str, status: int = 400) -> None:
        self._send_json({"ok": False, "error": message}, status=status)
        return None

    def _require_api_auth(self) -> bool:
        expected = str(self.server.config.bridge_api_token or "")
        provided = self.headers.get("X-Bridge-Token")
        if expected and provided and hmac.compare_digest(
            provided.encode("utf-8", errors="replace"), expected.encode("utf-8")
        ):
            return True
        self._fail("Unauthorized", status=401)
        return False

    def _read_json_body(self) -> dict[str, Any] | None:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self._fail("Chunked Transfer-Encoding is not supported", 400)
        cl_headers = self.headers.get_all("Content-Length") or []
        if len(cl_headers) > 1:
            return self._fail("Multiple Content-Length headers", 400)
        raw_len = cl_headers[0].strip() if cl_headers else "0"
        if not raw_len or not raw_len.lstrip("-").isdigit():
            return self._fail("Invalid Content-Length header", 400)
        try:
            length = int(raw_len)
        except ValueError:
            return self._fail("Invalid Content-Length header", 400)
        if length < 0:
            return self._fail("Content-Length must be non-negative", 400)
        if length > self.server.config.max_request_body_bytes:
            self.close_connection = True
            return self._fail("Payload Too Large", 413)

        raw_bytes = self.rfile.read(length) if length > 0 else b""
        if len(raw_bytes) != length:
            return self._fail("Incomplete request body", 400)
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            return self._fail("Request body must be valid UTF-8", 400)
        except (json.JSONDecodeError, ValueError):
            return self._fail("Invalid JSON request body", 400)
        return payload if isinstance(payload, dict) else self._fail("JSON body must be an object", 400)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(302)
            self.send_header("Location", self.server.config.dashboard_url.replace("\r", "").replace("\n", ""))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/health":
            self._send_json({"ok": True, "service": "oracle-ids-bridge"}, status=200)
            return
        if parsed.path == "/api" or parsed.path.startswith("/api/"):
            if not self._require_api_auth():
                return
            if parsed.path == "/api/data":
                do_flush = parse_qs(parsed.query).get("flush", ["0"])[0] == "1"
                self._send_json(self.server.service.collect_dashboard_data(do_flush=do_flush), status=200)
                return
        self._fail("Not Found", status=404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not (path == "/api" or path.startswith("/api/")):
            self._fail("Not Found", status=404)
            return
        if not self._require_api_auth():
            return
        if path not in ("/api/user-action", "/api/clear-alerts", "/api/toggle-ips"):
            self._fail("Not Found", status=404)
            return
        payload = self._read_json_body()
        if payload is None:
            return

        if path == "/api/user-action":
            username, action = payload.get("username", ""), payload.get("action", "")
            if not isinstance(username, str) or not isinstance(action, str):
                self._fail("Invalid 'username' or 'action'", status=400)
                return
            ok, msg = self.server.service.execute_user_action(username, action)
            self._send_json({"ok": ok, "message": msg, **({} if ok else {"error": msg})}, status=200 if ok else 400)
            return
        if path == "/api/clear-alerts":
            ok, msg = self.server.service.execute_clear_alerts(payload)
            self._send_json({"ok": ok, "message": msg, **({} if ok else {"error": msg})}, status=200 if ok else 400)
            return

        enabled = self.server.service.toggle_ips(_coerce_bool(payload.get("auto_response", True), True))
        self._send_json({"ok": True, "auto_response": enabled}, status=200)


def create_bridge_http_server(
    config: BridgeConfig, db_client: Any = None, state_store: Any = None,
    policy: dict[str, Any] | None = None, defense_health: dict[str, Any] | None = None,
) -> BridgeHTTPServer:
    """Create and bind a BridgeHTTPServer using the provided config and dependencies."""
    service = BridgeService(config, db_client, state_store, policy, defense_health)
    return BridgeHTTPServer((config.bridge_host, config.bridge_port), IDSRequestHandler, config=config, service=service)


def _execute_dashboard_command(service: BridgeService, cmd: dict[str, Any]) -> None:
    c_type = str(cmd.get("type") or "").strip()
    payload = cmd.get("payload") if isinstance(cmd.get("payload"), dict) else {}
    if c_type == "user_action":
        ok, msg = service.execute_user_action(str(payload.get("username") or ""), str(payload.get("action") or ""))
        (logger.info if ok else logger.warning)("Dashboard user_action '%s': %s", payload.get("action"), msg)
    elif c_type == "clear_alerts":
        ok, msg = service.execute_clear_alerts(payload)
        (logger.info if ok else logger.warning)("Dashboard clear_alerts: %s", msg)
    elif c_type == "toggle_ips":
        logger.info("Dashboard toggled auto_response -> %s", service.toggle_ips(_coerce_bool(payload.get("auto_response", True), True)))
    else:
        logger.warning("Ignoring unknown dashboard pending command type: %r", c_type)


def sync_with_web_dashboard(service: BridgeService, stop_event: threading.Event) -> None:
    """Push Oracle telemetry to the Node SOC server and execute queued commands with ACK tracking."""
    dashboard_url = service.config.dashboard_url.rstrip("/")
    if urlparse(dashboard_url).scheme.lower() not in ("http", "https"):
        logger.error("Refusing sync to unsupported dashboard URL scheme: %s", dashboard_url)
        return

    sync_endpoint = f"{dashboard_url}/api/oracle-sync"
    base_interval = max(0.5, float(service.config.poll_interval_sec))
    backoff = base_interval
    pending_ack_ids: list[str] = []
    executed_cmd_ids: OrderedDict[str, None] = OrderedDict()
    last_alerts, last_triggers, connected_once = 0, 0, False

    logger.info("Starting live telemetry sync to Web Dashboard: %s", sync_endpoint)
    while not stop_event.is_set():
        try:
            data = service.collect_dashboard_data(do_flush=True)
            if not data.get("ok"):
                backoff = min(_MAX_BACKOFF_SEC, backoff * 2.0)
                logger.warning("Telemetry collection error: %s; retrying in %.1fs.", data.get("error", "unknown"), backoff)
                stop_event.wait(backoff)
                continue

            cur_alerts, cur_trigs = len(data.get("alerts", [])), len(data.get("triggers", []))
            if last_alerts > 0 and cur_alerts > last_alerts:
                logger.warning("Detected %d new IDS/FGA anomaly alert(s).", cur_alerts - last_alerts)
            if last_triggers > 0 and cur_trigs > last_triggers:
                logger.warning("Trigger/FGA handler blocked %d violation(s).", cur_trigs - last_triggers)
            last_alerts, last_triggers = cur_alerts, cur_trigs

            ack_batch = list(pending_ack_ids)
            req = urllib.request.Request(
                sync_endpoint,
                data=json.dumps({**data, "ack_command_ids": ack_batch}, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json; charset=utf-8", "X-Bridge-Token": service.config.bridge_api_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                status_code = getattr(resp, "status", None) or (resp.getcode() if hasattr(resp, "getcode") else 200)
                if int(status_code) != 200:
                    raise RuntimeError(f"Dashboard sync HTTP status {status_code}")
                raw_reply = resp.read().decode("utf-8")

            if ack_batch:
                ack_set = set(ack_batch)
                pending_ack_ids = [cid for cid in pending_ack_ids if cid not in ack_set]
            backoff = base_interval
            if not connected_once:
                logger.info("Connected to Web Dashboard live sync (%s).", dashboard_url)
                connected_once = True

            reply = json.loads(raw_reply) if raw_reply.strip() else {}
            for cmd in (reply.get("pending_commands", []) or []) if isinstance(reply, dict) else ():
                if not isinstance(cmd, dict):
                    continue
                cmd_id = str(cmd.get("id") or "").strip()
                if cmd_id and cmd_id in executed_cmd_ids:
                    if cmd_id not in pending_ack_ids:
                        pending_ack_ids.append(cmd_id)
                    continue
                try:
                    _execute_dashboard_command(service, cmd)
                except Exception as cmd_exc:
                    logger.warning("Error executing command %r: %s", cmd_id or cmd.get("type"), cmd_exc)
                    continue
                if cmd_id:
                    executed_cmd_ids[cmd_id] = None
                    if len(executed_cmd_ids) > _MAX_EXECUTED_CMD_CACHE:
                        executed_cmd_ids.popitem(last=False)
                    if cmd_id not in pending_ack_ids:
                        pending_ack_ids.append(cmd_id)
        except Exception as exc:
            backoff = min(_MAX_BACKOFF_SEC, backoff * 2.0)
            logger.warning("Web Dashboard sync failed (%s); retrying in %.1fs.", exc, backoff)
        stop_event.wait(backoff)


def main() -> int:
    """Bind bridge HTTP port first, initialize Oracle runtime, and run sync + server."""
    configure_logging()
    try:
        config = load_config(require_db_credentials=True)
    except Exception as exc:
        logger.error("Failed loading bridge configuration: %s", exc)
        return 1

    try:
        server = create_bridge_http_server(config)
    except OSError as exc:
        logger.warning("Port %s on %s is already in use (%s); exiting cleanly.", config.bridge_port, config.bridge_host, exc)
        return 0

    stop_event, db_client = threading.Event(), None
    try:
        db_client = OracleDbClient(config)
        state_store = StateStore(config.state_file)
        policy = load_policy(config.policy_path)
        defense_health = db_client.verify_and_sync_defense_objects()
        server.service.attach_runtime(db_client, state_store, policy, defense_health)

        logger.info("Oracle IDS Bridge listening on http://%s:%s", config.bridge_host, server.server_port)
        logger.info("Dashboard redirect: %s | Oracle DSN: %s (User: %s)", config.dashboard_url, config.oracle_dsn, config.oracle_user.upper())
        logger.info("Defense-in-Depth health: %s", defense_health)

        threading.Thread(target=sync_with_web_dashboard, args=(server.service, stop_event), name="oracle-dashboard-sync", daemon=True).start()
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Oracle IDS Bridge...")
    finally:
        stop_event.set()
        server.server_close()
        if db_client is not None:
            db_client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
