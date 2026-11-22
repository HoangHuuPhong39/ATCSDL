"""Centralized configuration loader and environment contracts for the Oracle SOC Bridge."""

from __future__ import annotations

import os
import secrets
import tempfile
from dataclasses import dataclass

try:
    from dotenv import load_dotenv as _dotenv_load_dotenv
except ImportError:  # pragma: no cover - optional dependency fallback
    _dotenv_load_dotenv = None

DEFAULT_MONITORED_USERS: tuple[str, ...] = ("U1", "U2", "U3", "U4")


@dataclass(frozen=True)
class BridgeConfig:
    """Immutable runtime configuration for the Oracle SOC Bridge."""

    oracle_user: str
    oracle_password: str
    oracle_dsn: str
    oracle_auth_mode: str
    oracle_os_auth: bool
    oracle_client_mode: str
    oracle_lib_dir: str
    bridge_host: str
    bridge_port: int
    dashboard_url: str
    bridge_api_token: str
    poll_interval_sec: float
    monitored_users: tuple[str, ...]
    policy_path: str
    state_file: str
    max_request_body_bytes: int


def _parse_env_value(raw_value: str) -> str:
    """Parse an unquoted or single/double-quoted .env value."""
    value = raw_value.lstrip()
    if not value:
        return ""

    quote = value[0]
    if quote in ('"', "'"):
        escaped = False
        chars: list[str] = []
        for idx in range(1, len(value)):
            ch = value[idx]
            if quote == '"' and not escaped and ch == "\\":
                escaped = True
                continue
            if escaped:
                escape_map = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
                chars.append(escape_map.get(ch, "\\" + ch))
                escaped = False
                continue
            if ch == quote:
                return "".join(chars)
            chars.append(ch)
        return value.strip()

    if value.startswith("#"):
        return ""

    for sep in (" #", "\t#"):
        comment_idx = value.find(sep)
        if comment_idx != -1:
            value = value[:comment_idx]
    return value.strip()


def _load_env_file_fallback(env_path: str) -> None:
    """Pure-Python .env loader that never overwrites existing os.environ entries."""
    with open(env_path, "r", encoding="utf-8-sig") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export ") and "=" in line[7:]:
                line = line[7:].lstrip()
            if "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if not key or any(ch.isspace() for ch in key):
                continue
            if key in os.environ:
                continue
            os.environ[key] = _parse_env_value(raw_value)


def _load_env_files(oracle_dir: str, repo_root: str) -> None:
    """Load .env files with precedence: process env > oracle/.env > root .env.local > root .env."""
    candidates = (
        os.path.join(oracle_dir, ".env"),
        os.path.join(repo_root, ".env.local"),
        os.path.join(repo_root, ".env"),
    )
    for path in candidates:
        if not os.path.isfile(path):
            continue
        if _dotenv_load_dotenv is not None:
            _dotenv_load_dotenv(dotenv_path=path, override=False)
        else:
            _load_env_file_fallback(path)


def _env_str(name: str, default: str, allow_empty: bool = False) -> str:
    """Read a string environment variable with optional empty-string fallback."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    stripped = raw.strip()
    if not stripped and not allow_empty:
        return default
    return stripped


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable ('1'/'true' => True)."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true")


def _env_int(name: str, default: int) -> int:
    """Read and parse an integer environment variable."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    """Read and parse a float environment variable."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be a number, got {raw!r}") from exc


def _env_csv_upper(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Read a comma-separated uppercase tuple from an environment variable."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    items = tuple(part.strip().upper() for part in raw.split(",") if part.strip())
    return items if items else default


def get_or_create_bridge_token(repo_root: str) -> str:
    """Return BRIDGE_API_TOKEN from env or persist a generated secret in <repo_root>/.bridge_secret."""
    env_token = os.environ.get("BRIDGE_API_TOKEN", "").strip()
    if env_token:
        return env_token

    secret_path = os.path.join(repo_root, ".bridge_secret")
    if os.path.isfile(secret_path):
        try:
            with open(secret_path, "r", encoding="utf-8") as fh:
                existing = fh.read().strip()
            if existing:
                return existing
        except OSError:
            pass

    token = secrets.token_hex(32)
    os.makedirs(repo_root, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=repo_root,
            prefix=".bridge_secret.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(token + "\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, secret_path)
        tmp_path = None
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    return token


def load_config(require_db_credentials: bool = False) -> BridgeConfig:
    """Load, validate, and return immutable BridgeConfig from environment and .env files."""
    oracle_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(oracle_dir)
    _load_env_files(oracle_dir=oracle_dir, repo_root=repo_root)

    oracle_user = _env_str("ORACLE_USER", "sys")
    oracle_password = os.environ.get("ORACLE_PASSWORD", "")
    oracle_dsn = _env_str("ORACLE_DSN", "localhost:1521/FREEPDB1")
    oracle_auth_mode = _env_str("ORACLE_AUTH_MODE", "sysdba").lower()
    oracle_os_auth = _env_bool("ORACLE_OS_AUTH", False)
    oracle_client_mode = _env_str("ORACLE_CLIENT_MODE", "thin").lower()
    oracle_lib_dir = _env_str("ORACLE_LIB_DIR", "", allow_empty=True)
    bridge_host = _env_str("BRIDGE_HOST", "127.0.0.1")
    bridge_port = _env_int("BRIDGE_PORT", 8050)
    dashboard_url = _env_str("DASHBOARD_URL", "http://localhost:3000")
    poll_interval_sec = _env_float("POLL_INTERVAL_SEC", 2.0)
    monitored_users = _env_csv_upper("MONITORED_USERS", DEFAULT_MONITORED_USERS)
    policy_path = _env_str(
        "DETECTION_POLICY_PATH",
        os.path.join(repo_root, "shared", "detection_policy.json"),
    )
    state_file = _env_str(
        "IDS_STATE_FILE",
        os.path.join(oracle_dir, ".ids_state.json"),
    )
    max_request_body_bytes = _env_int("MAX_REQUEST_BODY_BYTES", 1048576)

    if oracle_auth_mode not in ("sysdba", "normal"):
        raise ValueError(
            f"Invalid ORACLE_AUTH_MODE={oracle_auth_mode!r}; expected 'sysdba' or 'normal'."
        )
    if oracle_client_mode not in ("thin", "thick"):
        raise ValueError(
            f"Invalid ORACLE_CLIENT_MODE={oracle_client_mode!r}; expected 'thin' or 'thick'."
        )
    if not (1 <= bridge_port <= 65535):
        raise ValueError(f"Invalid BRIDGE_PORT={bridge_port}; must be between 1 and 65535.")
    if poll_interval_sec < 0.5:
        raise ValueError(
            f"Invalid POLL_INTERVAL_SEC={poll_interval_sec}; must be >= 0.5 seconds."
        )
    if max_request_body_bytes < 1024:
        raise ValueError(
            f"Invalid MAX_REQUEST_BODY_BYTES={max_request_body_bytes}; must be >= 1024 bytes."
        )

    if require_db_credentials and not oracle_password and not oracle_os_auth:
        raise RuntimeError(
            "Thiếu mật khẩu Oracle (ORACLE_PASSWORD). Vui lòng cấu hình ORACLE_PASSWORD trong file .env "
            "hoặc bật ORACLE_OS_AUTH=1. / Missing Oracle DB credentials: set ORACLE_PASSWORD in .env "
            "(or set ORACLE_OS_AUTH=1)."
        )

    bridge_api_token = get_or_create_bridge_token(repo_root)

    return BridgeConfig(
        oracle_user=oracle_user,
        oracle_password=oracle_password,
        oracle_dsn=oracle_dsn,
        oracle_auth_mode=oracle_auth_mode,
        oracle_os_auth=oracle_os_auth,
        oracle_client_mode=oracle_client_mode,
        oracle_lib_dir=oracle_lib_dir,
        bridge_host=bridge_host,
        bridge_port=bridge_port,
        dashboard_url=dashboard_url,
        bridge_api_token=bridge_api_token,
        poll_interval_sec=poll_interval_sec,
        monitored_users=monitored_users,
        policy_path=policy_path,
        state_file=state_file,
        max_request_body_bytes=max_request_body_bytes,
    )
