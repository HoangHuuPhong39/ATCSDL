"""Policy-driven multi-layer SQL/Audit detection and risk-scoring engine."""

from __future__ import annotations

import inspect
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Sequence

try:
    from oracle.state_store import StateStore, sanitize_details_passwords
except ImportError:  # pragma: no cover - direct execution inside oracle/
    from state_store import StateStore, sanitize_details_passwords

logger = logging.getLogger(__name__)

_DEFAULT_POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "shared",
    "detection_policy.json",
)

_DEFAULT_PATTERNS: dict[str, str] = {
    "sqli": (
        r"(\bOR\b\s*\(?\s*(?:['\"]?[0-9]+['\"]?\s*(?:=|!=|<>|<|>)\s*['\"]?[0-9]+['\"]?|"
        r"['\"][A-Za-z0-9_]+['\"]\s*=\s*['\"][A-Za-z0-9_]+['\"])|"
        r"\bUNION\b\s+(?:ALL\s+)?\(?\s*\bSELECT\b|"
        r"(?:^|\n)[ \t]*(?!--|/\*)\S[^\r\n]*?(?:--|/\*)|"
        r"\bDBMS_PIPE\b|\bDBMS_LOCK\.SLEEP\b|\bUTL_HTTP\b|\bUTL_INADDR\b|"
        r"\bUTL_FILE\b|\bDBMS_LDAP\b|\bXMLTYPE\b|\bEXTRACTVALUE\b|\bEXECUTE\s+IMMEDIATE\b)"
    ),
    "honeytoken": r"(NV_TRAP|001099000000)",
    "stat_funcs": (
        r"\b(COUNT|SUM|AVG|MAX|MIN|MEDIAN|STDDEV|VARIANCE|STATS_MODE|LISTAGG|PERCENTILE_CONT)\s*\("
    ),
    "crypto_direct": (
        r"(?:\b(?:V\$ENCRYPTION_KEYS|V\$ENCRYPTION_WALLET|V_\$ENCRYPTION_KEYS|"
        r"V_\$ENCRYPTION_WALLET|DBA_ENCRYPTED_COLUMNS|USER_ENCRYPTED_COLUMNS)\b|"
        r"\bENC\$(?![A-Za-z0-9_]))"
    ),
    "crypto_indirect": r"\b(DBMS_CRYPTO|ADMINISTER\s+KEY\s+MANAGEMENT|UTL_I18N\.STRING_TO_RAW)\b",
    "suspicious_clients": (
        r"(sqlmap|hydra|nikto|burp|nmap|\bnc\b|netcat|curl|wget|powershell|pwsh|cmd\.exe|metasploit)"
    ),
    "masquerade_hosts": r"(kali|parrot|attacker|rogue|unknown|tor-exit|vpn-ext)",
    "nv_table": r"\b(?:SYS\.|SYSTEM\.)?NV\b",
}

_DEFAULT_THRESHOLDS: dict[str, dict[str, Any]] = {
    "level_0": {"min": 0, "max": 19, "label": "Level 0: Normal (An toàn)"},
    "level_1": {"min": 20, "max": 49, "label": "Level 1: LOW/MED (Warning & Monitor)"},
    "level_2": {"min": 50, "max": 79, "label": "Level 2: HIGH (Privilege Containment)"},
    "level_3": {"min": 80, "max": 100, "label": "Level 3: CRITICAL (Full Isolation)"},
}

_WHERE_CLAUSE_PATTERN = re.compile(r"\bWHERE\b\s+(.+)$", re.IGNORECASE | re.DOTALL)
_UNION_KEYWORD_PATTERN = re.compile(r"\bUNION\b", re.IGNORECASE)
_COUNT_FUNC_PATTERN = re.compile(r"\bCOUNT\s*\(", re.IGNORECASE)
_SUM_AVG_FUNC_PATTERN = re.compile(r"\b(?:SUM|AVG)\s*\(", re.IGNORECASE)
_TRACKER_OP_PATTERN = re.compile(r"(?:\bOR\b|!=|<>|\bNOT\b)", re.IGNORECASE)
_ABSENT_VALUES = {"", "—"}

_CRYPTO_DIRECT_OBJECTS = {
    "V$ENCRYPTION_KEYS",
    "V_$ENCRYPTION_KEYS",
    "V$ENCRYPTION_WALLET",
    "V_$ENCRYPTION_WALLET",
    "DBA_ENCRYPTED_COLUMNS",
    "USER_ENCRYPTED_COLUMNS",
    "ENC$",
}
_METADATA_NOISE_SNIPPETS = (
    "ALL_OBJECTS",
    "DBA_",
    "USER$",
    "_CURRENT_EDITION_OBJ",
    "FROM DUAL",
    "FROM SYS.DUAL",
)

_CACHED_DEFAULT_POLICY: dict[str, Any] | None = None


def load_policy(policy_path: str | None = None) -> dict[str, Any]:
    """Load detection policy JSON from `policy_path` (defaults to shared/detection_policy.json)."""
    target_path = policy_path or _DEFAULT_POLICY_PATH
    with open(target_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Detection policy must be a JSON object, got {type(data).__name__}")
    return data


def _get_effective_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    global _CACHED_DEFAULT_POLICY
    if policy is not None:
        return policy
    if _CACHED_DEFAULT_POLICY is None:
        try:
            _CACHED_DEFAULT_POLICY = load_policy()
        except Exception as exc:
            logger.warning("Unable to load default policy (%s); using built-in defaults.", exc)
            _CACHED_DEFAULT_POLICY = {
                "thresholds": _DEFAULT_THRESHOLDS,
                "scoring": {"bonus_per_extra_alert": 4, "bonus_cap": 20, "clamp_by_tier": False},
                "patterns": _DEFAULT_PATTERNS,
            }
    return _CACHED_DEFAULT_POLICY


def _compile_patterns(policy: dict[str, Any]) -> dict[str, re.Pattern[str]]:
    raw_patterns = policy.get("patterns", {})
    compiled: dict[str, re.Pattern[str]] = {}
    for name, default_regex in _DEFAULT_PATTERNS.items():
        regex_text = raw_patterns.get(name, default_regex)
        compiled[name] = re.compile(regex_text, re.IGNORECASE)
    return compiled


def sanitize_sql_credentials(sql: str) -> str:
    """Scrub `IDENTIFIED BY ...` and `CONNECT user/pass` credentials from SQL text."""
    return sanitize_details_passwords(sql)


def classify_response_level(score: int, policy: dict[str, Any] | None = None) -> tuple[int, str]:
    """Map a risk score (0-100) to (response_level, label) using policy thresholds."""
    eff_policy = _get_effective_policy(policy)
    thresholds = eff_policy.get("thresholds", _DEFAULT_THRESHOLDS)
    clamped = int(max(0, min(100, int(score))))

    for lvl in (3, 2, 1, 0):
        cfg = thresholds.get(f"level_{lvl}") or _DEFAULT_THRESHOLDS[f"level_{lvl}"]
        min_v = int(cfg.get("min", 0))
        max_v = int(cfg.get("max", 100))
        if min_v <= clamped <= max_v:
            return lvl, str(cfg.get("label", _DEFAULT_THRESHOLDS[f"level_{lvl}"]["label"]))

    for lvl in (3, 2, 1, 0):
        cfg = thresholds.get(f"level_{lvl}") or _DEFAULT_THRESHOLDS[f"level_{lvl}"]
        if clamped >= int(cfg.get("min", 0)):
            return lvl, str(cfg.get("label", _DEFAULT_THRESHOLDS[f"level_{lvl}"]["label"]))

    lvl0 = _DEFAULT_THRESHOLDS["level_0"]
    return 0, str(lvl0["label"])


def compute_user_risk_score(
    alerts_or_scores: Sequence[dict[str, Any] | int | float],
    policy: dict[str, Any] | None = None,
) -> int:
    """Compute aggregated user risk score using policy bonus and optional tier-clamping."""
    scores: list[int] = []
    for entry in alerts_or_scores:
        if isinstance(entry, dict):
            scores.append(int(entry.get("risk_score") or 0))
        else:
            scores.append(int(entry))

    if not scores:
        return 0

    eff_policy = _get_effective_policy(policy)
    scoring = eff_policy.get("scoring", {})
    bonus_per_extra = int(scoring.get("bonus_per_extra_alert", 4))
    bonus_cap = int(scoring.get("bonus_cap", 20))
    clamp_by_tier = bool(scoring.get("clamp_by_tier", False))

    max_score = max(scores)
    bonus = min(bonus_cap, max(0, len(scores) - 1) * bonus_per_extra)
    raw_total = max_score + bonus

    if not clamp_by_tier:
        return int(max(0, min(100, raw_total)))

    thresholds = eff_policy.get("thresholds", _DEFAULT_THRESHOLDS)
    lvl2_min = int((thresholds.get("level_2") or _DEFAULT_THRESHOLDS["level_2"]).get("min", 50))
    lvl3_min = int((thresholds.get("level_3") or _DEFAULT_THRESHOLDS["level_3"]).get("min", 80))
    lvl1_max = int((thresholds.get("level_1") or _DEFAULT_THRESHOLDS["level_1"]).get("max", 49))
    lvl2_max = int((thresholds.get("level_2") or _DEFAULT_THRESHOLDS["level_2"]).get("max", 79))

    if max_score < lvl2_min:
        return int(max(0, min(lvl1_max, raw_total)))
    if max_score < lvl3_min:
        return int(max(0, min(lvl2_max, raw_total)))
    return int(max(0, min(100, raw_total)))


def is_benign_ide_metadata_query(row: dict[str, Any], policy: dict[str, Any]) -> bool:
    """
    Return True ONLY when an audit record is a harmless IDE/JDBC dictionary lookup.

    Prevents attackers from bypassing detection by appending `FROM DUAL` or `FROM ALL_OBJECTS`.
    """
    action = str(row.get("ACTION_NAME") or "").strip().upper()
    try:
        return_code = int(row.get("RETURN_CODE") or 0)
    except (TypeError, ValueError):
        return False

    if action != "SELECT" or return_code != 0:
        return False

    if str(row.get("FGA_POLICY_NAME") or "").strip():
        return False

    obj_schema = str(row.get("OBJECT_SCHEMA") or "").strip().upper()
    if obj_schema not in ("SYS", "PUBLIC", ""):
        return False

    obj_name = str(row.get("OBJECT_NAME") or "").strip().upper()
    ide_objects = {str(item).strip().upper() for item in policy.get("ide_metadata_objects", ())}
    if obj_name not in ide_objects:
        return False

    sql_text = str(row.get("SQL_TEXT") or "").strip()
    if not sql_text:
        return True

    if _UNION_KEYWORD_PATTERN.search(sql_text):
        return False

    patterns = _compile_patterns(policy)
    for key in ("nv_table", "sqli", "honeytoken", "crypto_direct", "crypto_indirect"):
        if patterns[key].search(sql_text):
            return False

    return True


def detect_masquerading(row: dict[str, Any], user: str, policy: dict[str, Any]) -> tuple[bool, str]:
    """Detect host/OS masquerading via regex signatures and per-user trusted baseline deviations."""
    uname = str(user or "").strip().upper()
    userhost = str(row.get("USERHOST") or "").strip()
    os_username = str(row.get("OS_USERNAME") or "").strip()
    client_prog = str(row.get("CLIENT_PROGRAM_NAME") or "").strip()

    patterns = _compile_patterns(policy)
    reasons: list[str] = []

    if (userhost and patterns["masquerade_hosts"].search(userhost)) or (
        os_username and patterns["masquerade_hosts"].search(os_username)
    ):
        reasons.append(
            f"Host/OS trùng mẫu giả mạo ({os_username or '—'}@{userhost or '—'})"
        )

    baselines = policy.get("user_baselines", {})
    baseline = baselines.get(uname)
    if isinstance(baseline, dict) and baseline:
        trusted_hosts = {
            str(h).strip().upper() for h in baseline.get("trusted_hosts", ()) if str(h).strip()
        }
        trusted_os_users = {
            str(o).strip().upper()
            for o in baseline.get("trusted_os_users", ())
            if str(o).strip()
        }
        trusted_clients = {
            str(c).strip().lower() for c in baseline.get("trusted_clients", ()) if str(c).strip()
        }

        host_deviated = bool(
            trusted_hosts and userhost not in _ABSENT_VALUES and userhost.upper() not in trusted_hosts
        )
        os_deviated = bool(
            trusted_os_users
            and os_username not in _ABSENT_VALUES
            and os_username.upper() not in trusted_os_users
        )

        if host_deviated:
            reasons.append(
                f"USERHOST '{userhost}' ngoài baseline cho phép của {uname} ({', '.join(sorted(trusted_hosts))})"
            )
        if os_deviated:
            reasons.append(
                f"OS_USERNAME '{os_username}' ngoài baseline cho phép của {uname} ({', '.join(sorted(trusted_os_users))})"
            )
        if (host_deviated or os_deviated) and trusted_clients and client_prog not in _ABSENT_VALUES:
            if not any(tc in client_prog.lower() for tc in trusted_clients):
                reasons.append(f"Client '{client_prog}' không nằm trong baseline trusted_clients")

    if not reasons:
        return False, ""
    return True, "; ".join(reasons)


def format_context_str(row: dict[str, Any]) -> str:
    """Format client program, OS username, and host for alert display."""
    prog = str(row.get("CLIENT_PROGRAM_NAME") or "").strip() or "Unknown Client"
    host = str(row.get("USERHOST") or "").strip() or "Unknown Host"
    os_user = str(row.get("OS_USERNAME") or "").strip()
    if os_user and os_user != "—":
        return f"{prog} ({os_user}@{host})"
    return f"{prog} ({host})"


def make_alert_item(
    key: str,
    severity: str,
    risk_score: int,
    event_time: str,
    user: str,
    attack_type: str,
    details: str,
    row: dict[str, Any] | None = None,
    *,
    policy: dict[str, Any] | None = None,
    auto_lock_exempt: bool = False,
) -> dict[str, Any]:
    """Construct a normalized AlertItem dictionary matching the Dashboard API contract."""
    row = row or {}
    lvl_num, lvl_label = classify_response_level(risk_score, policy=policy)
    return {
        "key": key,
        "severity": severity,
        "risk_score": int(risk_score),
        "response_level": lvl_num,
        "response_label": lvl_label,
        "time": event_time,
        "user": user,
        "attack_type": attack_type,
        "details": sanitize_sql_credentials(details),
        "client_program": str(row.get("CLIENT_PROGRAM_NAME") or "—"),
        "userhost": str(row.get("USERHOST") or "—"),
        "os_username": str(row.get("OS_USERNAME") or "—"),
        "fga_policy": str(row.get("FGA_POLICY_NAME") or ""),
        "audit_type": str(row.get("AUDIT_TYPE") or "Standard"),
        "context": format_context_str(row) if row else "Oracle Session",
        "auto_lock_exempt": bool(auto_lock_exempt),
    }


def _invoke_ips_action(fn: Any, db_client: Any, username: str) -> tuple[bool, str]:
    """Invoke an IPS action module helper flexibly across explicit or mocked signatures."""
    try:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        param_names = [p.name for p in params]

        has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
        if not has_varargs:
            kwargs: dict[str, Any] = {}
            if "db_client" in param_names:
                kwargs["db_client"] = db_client
            elif "db" in param_names:
                kwargs["db"] = db_client

            if "username" in param_names:
                kwargs["username"] = username
            elif "user" in param_names:
                kwargs["user"] = username

            if len(kwargs) == len(param_names) or (
                len(kwargs) > 0 and all(
                    p.name in kwargs or p.default is not inspect.Parameter.empty for p in params
                )
            ):
                res = fn(**kwargs)
            elif len(params) == 1:
                res = fn(username)
            else:
                res = fn(db_client, username)
        else:
            res = fn(db_client, username)

        if isinstance(res, tuple):
            return bool(res[0]), str(res[1]) if len(res) > 1 else ""
        return bool(res), ""
    except Exception as exc:
        logger.exception("IPS action %r failed for user %s: %s", fn, username, exc)
        return False, str(exc)


def _map_trigger_alert(
    t_row: dict[str, Any],
    attack_scores: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    t_id = t_row.get("ALERT_ID")
    t_time = str(t_row.get("EVENT_TIME") or t_row.get("EVENT_TIMESTAMP") or "").strip()
    t_user = str(t_row.get("DB_USER") or "UNKNOWN").strip().upper()
    t_type = str(t_row.get("ATTACK_TYPE") or "TRIGGER_BLOCK").strip().upper()
    t_details = sanitize_sql_credentials(str(t_row.get("DETAILS") or "").strip())
    alert_key = f"TRIG|{t_id}|{t_user}|{t_time}"

    if "HONEYTOKEN" in t_type or "FGA_HONEYTOKEN" in t_type or "FGA_TRAP_BLOCK" in t_type:
        vn_label = "SDB Direct Attack & Honeytoken Trap (Chặn tức thời ORA-20003)"
        t_sev = "CRITICAL"
        t_score = int(attack_scores.get("honeytoken_trap", 95))
        t_meta = {
            "CLIENT_PROGRAM_NAME": "FGA Handler Block (ORA-20003)",
            "USERHOST": "SYS.IDS_FGA_TRAP_HANDLER",
            "FGA_POLICY_NAME": "FGA_HONEYTOKEN_TRAP",
            "AUDIT_TYPE": "FineGrainedAudit",
        }
    elif "SQL_INJECTION" in t_type or "SQLI" in t_type:
        vn_label = "SQL Injection Attack (Chặn tức thời ORA-20003)"
        t_sev = "CRITICAL"
        t_score = int(attack_scores.get("sql_injection", 95))
        t_meta = {
            "CLIENT_PROGRAM_NAME": "FGA Handler Block (ORA-20003)",
            "USERHOST": "SYS.IDS_FGA_TRAP_HANDLER",
            "FGA_POLICY_NAME": "FGA_HONEYTOKEN_TRAP",
            "AUDIT_TYPE": "FineGrainedAudit",
        }
    elif "UNAUTHORIZED_DML_INTEGRITY" in t_type or "DML_INTEGRITY" in t_type or "20004" in t_type:
        vn_label = "Trigger Block: Vi phạm toàn vẹn dữ liệu / PII (ORA-20004)"
        t_sev = "HIGH"
        t_score = int(attack_scores.get("trigger_block", 65))
        t_meta = {"CLIENT_PROGRAM_NAME": "Database Trigger", "USERHOST": "SYS.TRG_PROTECT_NV"}
    elif "ABNORMAL_SALARY_MODIFICATION" in t_type or "SALARY" in t_type:
        vn_label = "Trigger Block: Gian lận tăng lương > 50% / Salami Attack (ORA-20002)"
        t_sev = "HIGH"
        t_score = int(attack_scores.get("trigger_block", 65))
        t_meta = {"CLIENT_PROGRAM_NAME": "Database Trigger", "USERHOST": "SYS.TRG_PROTECT_NV"}
    elif "UNAUTHORIZED_DELETE" in t_type or "DELETE" in t_type:
        vn_label = "Trigger Block: Xóa nhân viên trái phép (ORA-20001)"
        t_sev = "HIGH"
        t_score = int(attack_scores.get("trigger_block", 65))
        t_meta = {"CLIENT_PROGRAM_NAME": "Database Trigger", "USERHOST": "SYS.TRG_PROTECT_NV"}
    else:
        vn_label = f"Trigger Block: Hành vi bị chặn ({t_type})"
        t_sev = "HIGH"
        t_score = int(attack_scores.get("trigger_block", 65))
        t_meta = {"CLIENT_PROGRAM_NAME": "Database Trigger", "USERHOST": "SYS.TRG_PROTECT_NV"}

    return make_alert_item(
        key=alert_key,
        severity=t_sev,
        risk_score=t_score,
        event_time=t_time,
        user=t_user,
        attack_type=vn_label,
        details=t_details,
        row=t_meta,
        policy=policy,
    )


def _analyze_sdb_user_queries(
    user: str,
    q_list: list[tuple[str, str, str, dict[str, Any]]],
    attack_scores: dict[str, Any],
    policy: dict[str, Any],
    snap_history: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Deduplicate identical normalized stat queries and classify SDB inference attacks."""
    seen_pairs: set[tuple[str, str]] = set()
    unique_stat: list[tuple[str, str, str, dict[str, Any]]] = []
    for ev_time, sql_txt, where_txt, r_obj in q_list:
        sql_norm = re.sub(r"\s+", " ", sql_txt).strip().upper()
        where_norm = re.sub(r"\s+", " ", where_txt).strip().upper()
        pair = (sql_norm, where_norm)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        unique_stat.append((ev_time, sql_txt, where_txt, r_obj))

    if not unique_stat:
        return {}, set()

    stat_count = len(unique_stat)
    latest_time, latest_sql, _, latest_row = max(unique_stat, key=lambda item: item[0])
    distinct_wheres = {re.sub(r"\s+", " ", w).strip().upper() for _, _, w, _ in unique_stat}
    upper_sqls = [re.sub(r"\s+", " ", s).strip().upper() for _, s, _, _ in unique_stat]
    upper_wheres = [re.sub(r"\s+", " ", w).strip().upper() for _, _, w, _ in unique_stat]

    has_single_combined_count_sum = any(
        bool(_COUNT_FUNC_PATTERN.search(s) and _SUM_AVG_FUNC_PATTERN.search(s)) for s in upper_sqls
    )
    has_count = any(bool(_COUNT_FUNC_PATTERN.search(s)) for s in upper_sqls)
    has_sum_or_avg = any(bool(_SUM_AVG_FUNC_PATTERN.search(s)) for s in upper_sqls)
    has_two_query_count_sum = (
        stat_count == 2 and has_count and has_sum_or_avg and len(distinct_wheres) == 1
    )
    has_tracker_logic = any(bool(_TRACKER_OP_PATTERN.search(w)) for w in upper_wheres)
    sum_query_count = sum(1 for s in upper_sqls if _SUM_AVG_FUNC_PATTERN.search(s))

    emitted: dict[str, dict[str, Any]] = {}
    pruned: set[str] = set()
    warn_prefix = f"STAT_WARN|{user}|"

    if stat_count >= 3:
        sample_queries = " ; ".join(s for _, s, _, _ in unique_stat[:4])
        if has_tracker_logic:
            sdb_type = "SDB Tracker Attack (Tấn công trình theo dõi lách Query-Set-Size)"
            sdb_score = int(attack_scores.get("sdb_tracker", 72))
            sdb_desc = (
                f"Thực hiện {stat_count} truy vấn thống kê sử dụng biểu thức phần bù/Tracker "
                f"(OR/!=/NOT) trên {len(distinct_wheres)} tập con để cô lập hồ sơ cá nhân: {sample_queries}"
            )
        elif sum_query_count >= 3 and len(distinct_wheres) >= 3:
            sdb_type = "SDB Linear System Attack (Tấn công giải hệ phương trình tuyến tính A*X=B)"
            sdb_score = int(attack_scores.get("sdb_linear_system", 78))
            sdb_desc = (
                f"Thiết lập hệ phương trình tuyến tính từ {sum_query_count} truy vấn SUM/AVG chồng lấp "
                f"trên {len(distinct_wheres)} tập con (Khử Gauss tìm toàn bộ LUONG): {sample_queries}"
            )
        else:
            sdb_type = "SDB Count-based & Statistical Inference Attack (Tấn công suy diễn thống kê)"
            sdb_score = int(attack_scores.get("sdb_count_based", 65))
            sdb_desc = (
                f"Thực hiện liên tiếp {stat_count} truy vấn thống kê (COUNT/SUM/AVG) "
                f"với {len(distinct_wheres)} điều kiện lọc: {sample_queries}"
            )

        alert_key = f"STAT_INF|{user}|{latest_time}|{stat_count}"
        emitted[alert_key] = make_alert_item(
            key=alert_key,
            severity="HIGH",
            risk_score=sdb_score,
            event_time=latest_time,
            user=user,
            attack_type=sdb_type,
            details=sdb_desc,
            row=latest_row,
            policy=policy,
        )
        pruned.update(k for k in snap_history if k.startswith(warn_prefix))
    elif has_single_combined_count_sum or has_two_query_count_sum:
        sample_queries = " ; ".join(s for _, s, _, _ in unique_stat[:2])
        alert_key = f"STAT_COUNT_SUM|{user}|{latest_time}"
        emitted[alert_key] = make_alert_item(
            key=alert_key,
            severity="HIGH",
            risk_score=int(attack_scores.get("sdb_count_based", 65)),
            event_time=latest_time,
            user=user,
            attack_type="SDB Count-based Attack (Tấn công dựa vào đếm COUNT=1 & SUM)",
            details=(
                "Kết hợp truy vấn đếm COUNT(*) và tính tổng/trung bình SUM/AVG trên cùng điều kiện lọc "
                f"để suy diễn chính xác lương cá nhân: {sample_queries}"
            ),
            row=latest_row,
            policy=policy,
        )
        pruned.update(k for k in snap_history if k.startswith(warn_prefix))
    elif 1 <= stat_count <= 2:
        alert_key = f"STAT_WARN|{user}|{latest_time}|{stat_count}"
        emitted[alert_key] = make_alert_item(
            key=alert_key,
            severity="LOW",
            risk_score=int(attack_scores.get("sdb_probe_low", 28)),
            event_time=latest_time,
            user=user,
            attack_type="Suspicious Statistical Probe (Thăm dò thống kê SDB 1-2 lần)",
            details=f"Phát hiện {stat_count} truy vấn hàm thống kê trên bảng nhạy cảm: {latest_sql}",
            row=latest_row,
            policy=policy,
        )
        pruned.update(
            k for k in snap_history if k.startswith(warn_prefix) and k != alert_key
        )

    return emitted, pruned


def _detect_bulk_query_burst(
    user: str,
    q_events: list[tuple[str, str, dict[str, Any]]],
    policy: dict[str, Any],
) -> dict[str, Any] | None:
    """Detect >= threshold NV queries within `window_seconds` using an ascending sliding window."""
    bulk_cfg = policy.get("bulk_query", {})
    threshold = max(1, int(bulk_cfg.get("threshold_count", 10)))
    window_seconds = float(bulk_cfg.get("window_seconds", 5))

    parsed: list[tuple[datetime, str, dict[str, Any]]] = []
    for ev_time, _, row in q_events:
        if len(ev_time) < 19:
            continue
        try:
            dt = datetime.strptime(ev_time[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        parsed.append((dt, ev_time, row))

    if len(parsed) < threshold:
        return None

    parsed.sort(key=lambda item: item[0])
    attack_scores = policy.get("attack_scores", {})
    for idx in range(len(parsed) - threshold + 1):
        span = (parsed[idx + threshold - 1][0] - parsed[idx][0]).total_seconds()
        if span <= window_seconds:
            _, latest_time, latest_row = parsed[idx + threshold - 1]
            alert_key = f"BULK|{user}|{latest_time[:16]}|{threshold}"
            return make_alert_item(
                key=alert_key,
                severity="MEDIUM",
                risk_score=int(attack_scores.get("bulk_querying", 42)),
                event_time=latest_time,
                user=user,
                attack_type="Behavioral Anomaly: Tần suất truy vấn đột biến (Bulk Querying)",
                details=(
                    f"Thực hiện dồn dập {threshold} truy vấn trên bảng NV trong vòng "
                    f"{int(span)}s (nguy cơ Data Exfiltration)"
                ),
                row=latest_row,
                policy=policy,
            )
    return None


def analyze_audit_logs(
    audit_rows: Sequence[dict[str, Any]],
    failed_rows: Sequence[dict[str, Any]],
    trig_rows: Sequence[dict[str, Any]],
    user_info_map: dict[str, dict[str, Any]],
    *,
    state_store: StateStore,
    policy: dict[str, Any],
    db_client: Any = None,
    auto_block: bool = False,
    ips_actions_module: Any = None,
) -> tuple[list[dict[str, Any]], list[str], list[str], dict[str, dict[str, Any]]]:
    """
    Analyze trigger alerts, failed logins, and unified audit rows using `policy`,
    atomically merge results into `state_store`, and return alerts + graduated IPS actions.
    """
    policy = _get_effective_policy(policy)
    expected_version = state_store.get_version()
    snap = state_store.snapshot()
    dismissed_keys = set(snap.get("dismissed_keys", []))
    alerts_cleared_at = str(snap.get("alerts_cleared_at") or "")
    snap_history = snap.get("alert_history", {})

    def _is_cleared_snap(event_time: str) -> bool:
        return bool(alerts_cleared_at and event_time and event_time <= alerts_cleared_at)

    patterns = _compile_patterns(policy)
    attack_scores = policy.get("attack_scores", {})
    protected_accounts = {
        str(u).strip().upper() for u in policy.get("protected_accounts", ("SYS", "SYSTEM"))
    }
    priv_abuse_actions = {
        str(a).strip().upper() for a in policy.get("priv_abuse_actions", ())
    }
    ddl_destructive_actions = {
        str(a).strip().upper()
        for a in policy.get("ddl_destructive_actions", ("DROP TABLE", "TRUNCATE TABLE"))
    }
    ddl_modify_actions = {
        str(a).strip().upper()
        for a in policy.get("ddl_modify_actions", ("ALTER TABLE", "CREATE TABLE"))
    }

    monitored_set = (
        {str(u).strip().upper() for u in user_info_map.keys()}
        | {str(u).strip().upper() for u in policy.get("user_baselines", {}).keys()}
        | {"U1", "U2", "U3", "U4"}
    ) - protected_accounts

    new_alerts: dict[str, dict[str, Any]] = {}
    pruned_warn_keys: set[str] = set()
    stat_queries_by_user: dict[str, list[tuple[str, str, str, dict[str, Any]]]] = {
        u: [] for u in monitored_set
    }
    query_times_by_user: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
        u: [] for u in monitored_set
    }
    suspicious_client_by_user: dict[str, tuple[str, str, str, dict[str, Any]]] = {}

    # 0. Trigger & FGA Handler Alerts
    for t_row in trig_rows or ():
        t_time = str(t_row.get("EVENT_TIME") or t_row.get("EVENT_TIMESTAMP") or "").strip()
        t_user = str(t_row.get("DB_USER") or "UNKNOWN").strip().upper()
        if t_user in protected_accounts or _is_cleared_snap(t_time):
            continue
        item = _map_trigger_alert(t_row, attack_scores, policy)
        if item["key"] not in dismissed_keys:
            new_alerts[item["key"]] = item

    # 1. Brute-Force ORA-01017 Anti-DoS
    bf_cfg = policy.get("brute_force", {})
    ext_threshold = int(bf_cfg.get("external_threshold", 3))
    int_threshold = int(bf_cfg.get("internal_lock_threshold", 5))
    user_baselines = policy.get("user_baselines", {})

    for row in failed_rows or ():
        fail_count = int(row.get("FAIL_COUNT") or 0)
        last_attempt = str(row.get("LAST_ATTEMPT") or "").strip()
        user = str(row.get("DBUSERNAME") or "").strip().upper()
        if not user or user in protected_accounts or _is_cleared_snap(last_attempt):
            continue

        userhost = str(row.get("USERHOST") or "").strip() or "UNKNOWN"
        baseline = user_baselines.get(user, {})
        trusted_hosts = {
            str(h).strip().upper()
            for h in (baseline.get("trusted_hosts", ()) if isinstance(baseline, dict) else ())
            if str(h).strip()
        }
        is_trusted_host = bool(trusted_hosts and userhost.upper() in trusted_hosts)

        if is_trusted_host:
            if fail_count < int_threshold:
                continue
            bf_severity = "CRITICAL"
            bf_score = int(attack_scores.get("brute_force_internal", 90))
            auto_lock_exempt = False
            host_note = f"từ Trusted Host '{userhost}' (ngưỡng nội bộ >= {int_threshold})"
        else:
            if fail_count < ext_threshold:
                continue
            bf_severity = "HIGH"
            bf_score = int(attack_scores.get("brute_force_external", 70))
            auto_lock_exempt = True
            host_note = f"từ External/Untrusted Host '{userhost}' (Anti-DoS: miễn tự khóa)"

        alert_key = f"BF|{user}|{userhost}|{last_attempt[:16]}"
        if alert_key not in dismissed_keys:
            new_alerts[alert_key] = make_alert_item(
                key=alert_key,
                severity=bf_severity,
                risk_score=bf_score,
                event_time=last_attempt,
                user=user,
                attack_type="Tấn công đăng nhập thất bại / Brute-Force Logon (ORA-01017)",
                details=(
                    f"Dò quét mật khẩu / đăng nhập thất bại {fail_count} lần liên tiếp {host_note}"
                ),
                row=row,
                policy=policy,
                auto_lock_exempt=auto_lock_exempt,
            )

    # 2. Per-row Audit Inspection
    for row in audit_rows or ():
        raw_user = str(row.get("DBUSERNAME") or "").strip().upper()
        if not raw_user or raw_user in protected_accounts:
            continue
        user = raw_user
        event_time = str(row.get("EVENT_TIMESTAMP") or "").strip()
        if _is_cleared_snap(event_time):
            continue

        if is_benign_ide_metadata_query(row, policy):
            continue

        raw_sql = str(row.get("SQL_TEXT") or "").strip()
        sql_text = sanitize_sql_credentials(raw_sql)
        norm_sql = re.sub(r"\s+", " ", sql_text).strip().upper()
        action = str(row.get("ACTION_NAME") or "").strip().upper()
        fga_policy = str(row.get("FGA_POLICY_NAME") or "").strip().upper()
        unified_pols = str(row.get("UNIFIED_AUDIT_POLICIES") or "").strip().upper()
        obj_name = str(row.get("OBJECT_NAME") or "").strip().upper()
        client_prog = str(row.get("CLIENT_PROGRAM_NAME") or "").strip()
        userhost = str(row.get("USERHOST") or "").strip()
        os_username = str(row.get("OS_USERNAME") or "").strip()
        try:
            return_code = int(row.get("RETURN_CODE") or 0)
        except (TypeError, ValueError):
            return_code = 0

        # 2.1 Honeytoken (NO statistical exemption!)
        has_honeytoken_sql = bool(sql_text and patterns["honeytoken"].search(sql_text))
        has_sqli_sql = bool(sql_text and patterns["sqli"].search(sql_text))
        if has_honeytoken_sql or (fga_policy == "FGA_HONEYTOKEN_TRAP" and not has_sqli_sql):
            alert_key = f"TRAP|{user}|{event_time}|{norm_sql[:60]}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=int(attack_scores.get("honeytoken_trap", 95)),
                    event_time=event_time,
                    user=user,
                    attack_type="SDB Direct Attack & Honeytoken Trap (Tấn công trực tiếp)",
                    details=sql_text or "Truy vấn trực tiếp dữ liệu nhạy cảm chạm bẫy MANV = 'NV_TRAP'",
                    row=row,
                    policy=policy,
                )
            continue

        # 2.2 Crypto Key Access
        is_crypto_direct = bool(
            (sql_text and patterns["crypto_direct"].search(sql_text))
            or obj_name in _CRYPTO_DIRECT_OBJECTS
        )
        is_crypto_indirect = bool(
            (sql_text and patterns["crypto_indirect"].search(sql_text))
            or obj_name == "DBMS_CRYPTO"
        )
        is_crypto_pol = "IDS_CRYPTO_KEY_POL" in unified_pols
        if is_crypto_direct or is_crypto_indirect or is_crypto_pol:
            if is_crypto_direct:
                sub_label = "Truy cập trực tiếp bảng/kho khóa TDE"
            elif is_crypto_indirect:
                sub_label = "Truy cập gián tiếp qua DBMS_CRYPTO / dịch vụ giải mã"
            else:
                sub_label = "Vi phạm chính sách kiểm toán khóa mã hóa (IDS_CRYPTO_KEY_POL)"
            alert_key = f"CRYPTO|{user}|{event_time}|{norm_sql[:60] or obj_name or action}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=int(attack_scores.get("crypto_key_access", 92)),
                    event_time=event_time,
                    user=user,
                    attack_type=f"Unauthorized Encryption Key Access ({sub_label})",
                    details=sql_text or f"{action} on {obj_name or 'TDE Keystore'}",
                    row=row,
                    policy=policy,
                )
            continue

        # 2.3 SQL Injection
        if has_sqli_sql:
            alert_key = f"SQLI|{user}|{event_time}|{norm_sql[:60]}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=int(attack_scores.get("sql_injection", 95)),
                    event_time=event_time,
                    user=user,
                    attack_type="SQL Injection Attack (Chèn mã độc SQL)",
                    details=sql_text,
                    row=row,
                    policy=policy,
                )
            continue

        # 2.4 Masquerading (baseline + signature regex; no continue so action inside session is also inspected)
        is_masq, masq_reason = detect_masquerading(row, user, policy)
        if is_masq:
            alert_key = f"MASQ|{user}|{event_time[:16]}|{userhost or '—'}|{os_username or '—'}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="HIGH",
                    risk_score=int(attack_scores.get("masquerading", 75)),
                    event_time=event_time,
                    user=user,
                    attack_type="Masquerading Attack (Giả mạo / Giả danh tài khoản hợp pháp)",
                    details=(
                        f"Phiên của {user} có dấu hiệu giả mạo ({masq_reason}): {sql_text or action}"
                    ),
                    row=row,
                    policy=policy,
                )

        # 2.5 Privilege Escalation (MUST run BEFORE Read-Only DML check!)
        if action in priv_abuse_actions:
            alert_key = f"PRIV|{user}|{event_time}|{action}|{norm_sql[:40]}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=int(attack_scores.get("privilege_escalation", 88)),
                    event_time=event_time,
                    user=user,
                    attack_type=f"Privilege Escalation / Leo thang đặc quyền ({action})",
                    details=sql_text
                    or f"Thực thi lệnh đặc quyền hệ thống vượt mức được cấp: {action} (ORA-{return_code})",
                    row=row,
                    policy=policy,
                )
            continue

        # 2.6 Read-Only DML Violation (strictly DML action + ORA-1031 / 2004 / 41900)
        if action in ("INSERT", "UPDATE", "DELETE") and return_code in (1031, 2004, 41900):
            if action == "DELETE":
                dml_action_vn = "Xóa nhân viên (DELETE)"
            elif action == "UPDATE":
                dml_action_vn = "Sửa lương / Cập nhật dữ liệu (UPDATE)"
            else:
                dml_action_vn = "Thêm nhân viên (INSERT)"

            err_code_str = f"ORA-{return_code}" if return_code in (1031, 41900) else "ORA-41900"
            alert_key = f"DML_RO|{user}|{event_time}|{norm_sql[:50]}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="HIGH",
                    risk_score=int(attack_scores.get("dml_readonly_violation", 65)),
                    event_time=event_time,
                    user=user,
                    attack_type=f"Vi phạm Read-Only (Hạ quyền Level 2): Cố tình {dml_action_vn} ({err_code_str})",
                    details=sql_text
                    or f"Tài khoản đang ở chế độ Read-Only nhưng vẫn cố tình thực hiện {dml_action_vn}",
                    row=row,
                    policy=policy,
                )
            continue

        # 2.7 Dangerous DDL
        if action in ddl_destructive_actions:
            alert_key = f"DDL|{user}|{event_time}|{action}|{norm_sql[:40]}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=int(attack_scores.get("ddl_destructive", 85)),
                    event_time=event_time,
                    user=user,
                    attack_type=f"Unauthorized DDL Modification ({action})",
                    details=sql_text or action,
                    row=row,
                    policy=policy,
                )
            continue

        if action in ddl_modify_actions:
            alert_key = f"DDL|{user}|{event_time}|{action}|{norm_sql[:40]}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="HIGH",
                    risk_score=int(attack_scores.get("ddl_modify", 65)),
                    event_time=event_time,
                    user=user,
                    attack_type=f"Unauthorized DDL Modification ({action})",
                    details=sql_text or action,
                    row=row,
                    policy=policy,
                )
            continue

        # 2.8 FGA Sensitive Access (NO statistical exemption!)
        if fga_policy == "FGA_HIGH_SALARY_ACCESS":
            alert_key = f"FGA_SAL|{user}|{event_time}|{norm_sql[:60]}"
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = make_alert_item(
                    key=alert_key,
                    severity="MEDIUM",
                    risk_score=int(attack_scores.get("fga_sensitive_access", 35)),
                    event_time=event_time,
                    user=user,
                    attack_type="SDB Direct Attack (FGA_HIGH_SALARY_ACCESS)",
                    details=sql_text or "Truy vấn trực tiếp cột nhạy cảm (LUONG, CMND)",
                    row=row,
                    policy=policy,
                )

        # 2.9 Collect Statistical Inference & NV Table Queries
        has_nv_table = bool(sql_text and patterns["nv_table"].search(sql_text))
        is_dictionary_noise = not has_nv_table and any(
            meta in norm_sql for meta in _METADATA_NOISE_SNIPPETS
        )
        if action == "SELECT" and return_code == 0 and not is_dictionary_noise:
            if sql_text and patterns["stat_funcs"].search(sql_text):
                m_where = _WHERE_CLAUSE_PATTERN.search(sql_text)
                where_cond = re.sub(r"\s+", " ", m_where.group(1)).strip() if m_where else "(ALL_ROWS)"
                stat_queries_by_user.setdefault(user, []).append(
                    (event_time, sql_text, where_cond, row)
                )
            elif has_nv_table:
                query_times_by_user.setdefault(user, []).append((event_time, norm_sql, row))

        # 2.10 Suspicious Client
        if client_prog and patterns["suspicious_clients"].search(client_prog):
            if user not in suspicious_client_by_user:
                suspicious_client_by_user[user] = (event_time, client_prog, sql_text or action, row)

    # 3. SDB Inference Engine
    for user, q_list in stat_queries_by_user.items():
        if not q_list:
            continue
        emitted_sdb, pruned_sdb = _analyze_sdb_user_queries(
            user, q_list, attack_scores, policy, snap_history
        )
        pruned_warn_keys.update(pruned_sdb)
        for alert_key, item in emitted_sdb.items():
            if alert_key not in dismissed_keys:
                new_alerts[alert_key] = item

    # 4. Bulk Querying Sliding Window
    for user, q_events in query_times_by_user.items():
        bulk_item = _detect_bulk_query_burst(user, q_events, policy)
        if bulk_item and bulk_item["key"] not in dismissed_keys:
            new_alerts[bulk_item["key"]] = bulk_item

    for user, (ev_time, c_prog, sql_txt, r_obj) in suspicious_client_by_user.items():
        alert_key = f"CLIENT|{user}|{c_prog}|{ev_time[:16]}"
        if alert_key not in dismissed_keys:
            new_alerts[alert_key] = make_alert_item(
                key=alert_key,
                severity="MEDIUM",
                risk_score=int(attack_scores.get("suspicious_client", 38)),
                event_time=ev_time,
                user=user,
                attack_type="Contextual Anomaly: Công cụ kết nối bất thường",
                details=(
                    f"Kết nối từ công cụ nghi vấn '{c_prog}' tại "
                    f"{r_obj.get('USERHOST', 'Unknown')}: {sql_txt}"
                ),
                row=r_obj,
                policy=policy,
            )

    # 5. Atomic Merge + Risk Summary + Graduated Active IPS
    merged_ok, alerts = state_store.merge_analyzed_alerts(
        expected_version,
        new_alerts,
        pruned_warn_keys=pruned_warn_keys or None,
    )

    auto_locked: list[str] = []
    auto_revoked: list[str] = []
    user_risk_summary: dict[str, dict[str, Any]] = {}

    for user in sorted(user_info_map.keys()):
        uname = str(user).strip().upper()
        u_info = user_info_map[user]
        active_user_alerts = [
            a
            for a in alerts
            if str(a.get("user") or "").upper() == uname
            and state_store.is_event_active_for_user_risk(uname, str(a.get("time") or ""))
        ]

        total_score = compute_user_risk_score(active_user_alerts, policy=policy)
        lvl_num, lvl_label = classify_response_level(total_score, policy=policy)

        non_exempt_alerts = [a for a in active_user_alerts if not a.get("auto_lock_exempt", False)]
        non_exempt_score = compute_user_risk_score(non_exempt_alerts, policy=policy)
        non_exempt_level, _ = classify_response_level(non_exempt_score, policy=policy)

        effective_ips_level = lvl_num
        if lvl_num == 3 and non_exempt_level < 3:
            # Cap automated IPS escalation below Level 3 lock when only auto_lock_exempt alerts push over threshold
            effective_ips_level = 2

        acct_status = str(u_info.get("ACCOUNT_STATUS") or "OPEN").upper()
        dml_status = str(u_info.get("DML_STATUS") or "FULL DML").upper()

        if (
            merged_ok
            and auto_block
            and db_client is not None
            and ips_actions_module is not None
        ):
            if effective_ips_level == 3 and "LOCK" not in acct_status:
                lock_fn = getattr(ips_actions_module, "lock_user", None)
                if callable(lock_fn):
                    ok, _ = _invoke_ips_action(lock_fn, db_client, uname)
                    if ok:
                        u_info["ACCOUNT_STATUS"] = "LOCKED"
                        auto_locked.append(uname)
            elif (
                effective_ips_level == 2
                and "LOCK" not in acct_status
                and dml_status == "FULL DML"
            ):
                revoke_fn = getattr(ips_actions_module, "revoke_dml_user", None)
                if callable(revoke_fn):
                    ok, _ = _invoke_ips_action(revoke_fn, db_client, uname)
                    if ok:
                        u_info["DML_STATUS"] = "READ-ONLY"
                        auto_revoked.append(uname)

        user_risk_summary[uname] = {
            "risk_score": total_score,
            "response_level": lvl_num,
            "response_label": lvl_label,
            "active_alerts": len(active_user_alerts),
        }

    return alerts, sorted(set(auto_locked)), sorted(set(auto_revoked)), user_risk_summary
