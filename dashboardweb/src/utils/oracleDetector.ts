import policy from '../../../shared/detection_policy.json' with { type: 'json' };
import { INITIAL_EMPLOYEES } from '../data/initialData.ts';
import type {
  AlertItem,
  AuditLogRow,
  DbUser,
  Employee,
  FgaEvent,
  Severity,
  TriggerAlert,
} from '../types/ids.ts';
import { classifyResponseLevel, computeUserRiskScore } from './analytics.ts';
import { sanitizeSqlCredentials } from './privacy.ts';

const SQLI_REGEX = new RegExp(policy.patterns.sqli, 'i');
const HONEYTOKEN_REGEX = new RegExp(policy.patterns.honeytoken, 'i');
const STAT_FUNC_REGEX = new RegExp(policy.patterns.stat_funcs, 'i');
const CRYPTO_DIRECT_REGEX = new RegExp(policy.patterns.crypto_direct, 'i');
const CRYPTO_INDIRECT_REGEX = new RegExp(policy.patterns.crypto_indirect, 'i');
const SUSPICIOUS_CLIENTS_REGEX = new RegExp(policy.patterns.suspicious_clients, 'i');
const MASQUERADE_HOSTS_REGEX = new RegExp(policy.patterns.masquerade_hosts, 'i');
const NV_TABLE_REGEX = new RegExp(policy.patterns.nv_table, 'i');

function buildKeywordAlternation(actions: string[]): string {
  return actions
    .map((act) => act.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'))
    .join('|');
}

const PRIV_ABUSE_REGEX = new RegExp(
  `^\\s*(${buildKeywordAlternation(policy.priv_abuse_actions)})\\b`,
  'i'
);
const DDL_DESTRUCTIVE_REGEX = new RegExp(
  `^\\s*(${buildKeywordAlternation(policy.ddl_destructive_actions)})\\b`,
  'i'
);
const DDL_MODIFY_REGEX = new RegExp(
  `^\\s*(${buildKeywordAlternation(policy.ddl_modify_actions)})\\b`,
  'i'
);

const IDE_METADATA_OBJECTS = policy.ide_metadata_objects.map((obj) => obj.toUpperCase());

type UserBaseline = {
  trusted_hosts: string[];
  trusted_os_users: string[];
  trusted_clients: string[];
};

const USER_BASELINES = policy.user_baselines as Record<string, UserBaseline>;

export interface OracleExecutionOutcome {
  newAlerts: AlertItem[];
  newTriggers: TriggerAlert[];
  newFgaEvents: FgaEvent[];
  newAuditLogs: AuditLogRow[];
  updatedUsers: DbUser[];
  oracleOutputs: string[];
}

function formatUtcTimestamp(date: Date): string {
  return date.toISOString().replace('T', ' ').substring(0, 19);
}

/**
 * Quote-aware and comment-aware SQL statement splitter.
 * - Ignores standalone `-- ...` line comments and standalone `/* ... * /` block comments between statements.
 * - Preserves inline `--` and `/* ... * /` comments inside executable SQL statements (for SQLi detection).
 * - Respects semicolons inside `'...'` string literals, `"..."` identifiers, and comments.
 */
export function splitSqlStatements(sqlScript: string): string[] {
  if (!sqlScript) return [];

  const statements: string[] = [];
  let buffer = '';
  let hasCodeToken = false;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < sqlScript.length; i++) {
    const ch = sqlScript[i];
    const next = i + 1 < sqlScript.length ? sqlScript[i + 1] : '';

    if (inSingleQuote) {
      buffer += ch;
      if (ch === "'") {
        if (next === "'") {
          buffer += next;
          i++;
        } else {
          inSingleQuote = false;
        }
      }
      continue;
    }

    if (inDoubleQuote) {
      buffer += ch;
      if (ch === '"') {
        if (next === '"') {
          buffer += next;
          i++;
        } else {
          inDoubleQuote = false;
        }
      }
      continue;
    }

    if (inLineComment) {
      if (ch === '\n' || ch === '\r') {
        inLineComment = false;
        if (hasCodeToken) {
          buffer += ch;
        }
      } else if (hasCodeToken) {
        buffer += ch;
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        if (hasCodeToken) {
          buffer += '*/';
        }
        i++;
      } else if (hasCodeToken) {
        buffer += ch;
      }
      continue;
    }

    if (ch === '-' && next === '-') {
      inLineComment = true;
      if (hasCodeToken) {
        buffer += '--';
      }
      i++;
      continue;
    }

    if (ch === '/' && next === '*') {
      inBlockComment = true;
      if (hasCodeToken) {
        buffer += '/*';
      }
      i++;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      hasCodeToken = true;
      buffer += ch;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      hasCodeToken = true;
      buffer += ch;
      continue;
    }

    if (ch === ';') {
      if (hasCodeToken) {
        const trimmed = buffer.trim();
        if (trimmed.length > 0) {
          statements.push(trimmed);
        }
      }
      buffer = '';
      hasCodeToken = false;
      continue;
    }

    if (!/\s/.test(ch)) {
      hasCodeToken = true;
    }
    if (hasCodeToken) {
      buffer += ch;
    }
  }

  if (hasCodeToken) {
    const trimmed = buffer.trim();
    if (trimmed.length > 0) {
      statements.push(trimmed);
    }
  }

  return statements;
}

/**
 * Safely evaluates simple SQL arithmetic expressions (e.g. `5000`, `luong * 2`, `(luong + 100) * 1.5`)
 * without `eval` or `Function`. Returns `null` for SQL `NULL` or unparseable expressions.
 */
function evaluateArithmeticExpression(rawExpr: string, oldLuong: number): number | null {
  const trimmed = rawExpr.trim();
  if (!trimmed || /^NULL$/i.test(trimmed)) {
    return null;
  }

  type Token =
    | { type: 'num'; value: number }
    | { type: 'op'; value: '+' | '-' | '*' | '/' | '(' | ')' };

  const tokens: Token[] = [];
  let i = 0;
  while (i < trimmed.length) {
    const ch = trimmed[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '+' || ch === '-' || ch === '*' || ch === '/' || ch === '(' || ch === ')') {
      tokens.push({ type: 'op', value: ch });
      i++;
      continue;
    }
    const numMatch = trimmed.slice(i).match(/^(?:\d+(?:\.\d+)?|\.\d+)/);
    if (numMatch) {
      tokens.push({ type: 'num', value: Number(numMatch[0]) });
      i += numMatch[0].length;
      continue;
    }
    const idMatch = trimmed.slice(i).match(/^[A-Za-z_][A-Za-z0-9_$.]*/);
    if (idMatch) {
      const idUpper = idMatch[0].toUpperCase();
      if (idUpper === 'LUONG' || idUpper.endsWith('.LUONG')) {
        tokens.push({ type: 'num', value: oldLuong });
        i += idMatch[0].length;
        continue;
      }
      return null;
    }
    return null;
  }

  let pos = 0;

  function parseExpression(): number | null {
    let left = parseTerm();
    if (left === null) return null;
    while (pos < tokens.length) {
      const tok = tokens[pos];
      if (tok.type === 'op' && (tok.value === '+' || tok.value === '-')) {
        pos++;
        const right = parseTerm();
        if (right === null) return null;
        left = tok.value === '+' ? left + right : left - right;
      } else {
        break;
      }
    }
    return left;
  }

  function parseTerm(): number | null {
    let left = parseFactor();
    if (left === null) return null;
    while (pos < tokens.length) {
      const tok = tokens[pos];
      if (tok.type === 'op' && (tok.value === '*' || tok.value === '/')) {
        pos++;
        const right = parseFactor();
        if (right === null) return null;
        if (tok.value === '/' && right === 0) return null;
        left = tok.value === '*' ? left * right : left / right;
      } else {
        break;
      }
    }
    return left;
  }

  function parseFactor(): number | null {
    if (pos >= tokens.length) return null;
    const tok = tokens[pos];
    if (tok.type === 'op' && (tok.value === '+' || tok.value === '-')) {
      pos++;
      const inner = parseFactor();
      if (inner === null) return null;
      return tok.value === '-' ? -inner : inner;
    }
    if (tok.type === 'op' && tok.value === '(') {
      pos++;
      const inner = parseExpression();
      if (inner === null || pos >= tokens.length) return null;
      const close = tokens[pos];
      if (close.type !== 'op' || close.value !== ')') return null;
      pos++;
      return inner;
    }
    if (tok.type === 'num') {
      pos++;
      return tok.value;
    }
    return null;
  }

  const result = parseExpression();
  if (result === null || pos !== tokens.length || !Number.isFinite(result)) {
    return null;
  }
  return result;
}

function splitTopLevelCommas(input: string): string[] {
  const parts: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let parenDepth = 0;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const next = i + 1 < input.length ? input[i + 1] : '';
    if (inSingle) {
      current += ch;
      if (ch === "'") {
        if (next === "'") {
          current += next;
          i++;
        } else {
          inSingle = false;
        }
      }
      continue;
    }
    if (inDouble) {
      current += ch;
      if (ch === '"') inDouble = false;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      current += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      current += ch;
      continue;
    }
    if (ch === '(') parenDepth++;
    else if (ch === ')' && parenDepth > 0) parenDepth--;

    if (ch === ',' && parenDepth === 0) {
      parts.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function extractTopLevelWhere(sql: string): { beforeWhere: string; whereClause: string } {
  let inSingle = false;
  let inDouble = false;
  let parenDepth = 0;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = i + 1 < sql.length ? sql[i + 1] : '';
    if (inSingle) {
      if (ch === "'") {
        if (next === "'") i++;
        else inSingle = false;
      }
      continue;
    }
    if (inDouble) {
      if (ch === '"') inDouble = false;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }
    if (ch === '(') {
      parenDepth++;
      continue;
    }
    if (ch === ')' && parenDepth > 0) {
      parenDepth--;
      continue;
    }

    if (parenDepth === 0) {
      const rest = sql.slice(i);
      const match = rest.match(/^WHERE\b\s*/i);
      if (match && (i === 0 || /\s/.test(sql[i - 1]))) {
        return {
          beforeWhere: sql.slice(0, i).trim(),
          whereClause: rest.slice(match[0].length).trim(),
        };
      }
    }
  }

  return { beforeWhere: sql, whereClause: '' };
}

function parseSqlStringLiteral(rawValue: string): string | null {
  const trimmed = rawValue.trim();
  if (/^NULL$/i.test(trimmed)) return null;
  if (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  return trimmed;
}

function parseUpdateAssignments(setClause: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of splitTopLevelCommas(setClause)) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const col = part
      .slice(0, eqIdx)
      .replace(/^["`\s]+|["`\s]+$/g, '')
      .toUpperCase();
    const val = part.slice(eqIdx + 1).trim();
    if (col) {
      result[col] = val;
    }
  }
  return result;
}

function isPureIdeMetadataQuery(normSql: string): boolean {
  if (NV_TABLE_REGEX.test(normSql)) return false;
  const upper = normSql.toUpperCase();
  return IDE_METADATA_OBJECTS.some((obj) => upper.includes(obj));
}

function extractWhereNormalized(sql: string): string {
  const { whereClause } = extractTopLevelWhere(sql);
  if (!whereClause) return '(ALL_ROWS)';
  return whereClause.replace(/\s+/g, ' ').trim().toUpperCase();
}

function makeAlert(
  key: string,
  severity: Severity,
  riskScore: number,
  time: string,
  user: string,
  attackType: string,
  details: string,
  clientProgram: string,
  userhost: string,
  osUsername: string,
  context: string,
  auditType: string = 'Standard',
  fgaPolicy?: string
): AlertItem {
  const { level, label } = classifyResponseLevel(riskScore);
  return {
    key,
    severity,
    risk_score: riskScore,
    response_level: level,
    response_label: label,
    time,
    user,
    attack_type: attackType,
    details,
    client_program: clientProgram,
    userhost,
    os_username: osUsername,
    ...(fgaPolicy !== undefined ? { fga_policy: fgaPolicy } : {}),
    audit_type: auditType,
    context,
  };
}

function detectMasquerading(
  user: string,
  customHost: string,
  customOsUser: string,
  customClient: string
): { isMasquerading: boolean; reason: string } {
  const baseline = USER_BASELINES[user];
  const host = (customHost || '').trim();
  const osUser = (customOsUser || '').trim();
  const client = (customClient || '').trim();
  const reasons: string[] = [];

  if (
    (host && MASQUERADE_HOSTS_REGEX.test(host)) ||
    (osUser && MASQUERADE_HOSTS_REGEX.test(osUser))
  ) {
    reasons.push(`Host/OS trùng mẫu giả mạo (${osUser || '—'}@${host || '—'})`);
  }

  if (baseline) {
    const hostDeviated =
      Boolean(baseline.trusted_hosts.length && host && host !== '—') &&
      !baseline.trusted_hosts.some((h) => h.toLowerCase() === host.toLowerCase());
    const osDeviated =
      Boolean(baseline.trusted_os_users.length && osUser && osUser !== '—') &&
      !baseline.trusted_os_users.some((o) => o.toLowerCase() === osUser.toLowerCase());

    if (hostDeviated) {
      reasons.push(
        `USERHOST '${host}' ngoài baseline cho phép của ${user} (${baseline.trusted_hosts.join(', ')})`
      );
    }
    if (osDeviated) {
      reasons.push(
        `OS_USERNAME '${osUser}' ngoài baseline cho phép của ${user} (${baseline.trusted_os_users.join(', ')})`
      );
    }
    if (
      (hostDeviated || osDeviated) &&
      baseline.trusted_clients.length > 0 &&
      client &&
      client !== '—'
    ) {
      const clientMatchesTrusted = baseline.trusted_clients.some((tc) =>
        client.toLowerCase().includes(tc.toLowerCase())
      );
      if (!clientMatchesTrusted) {
        reasons.push(`Client '${client}' không nằm trong baseline trusted_clients`);
      }
    }
  }

  return {
    isMasquerading: reasons.length > 0,
    reason: reasons.join('; '),
  };
}

/**
 * Evaluates one or more Oracle SQL statements executed from SQL Developer / SQL*Plus
 * against the 5-layer Defense-in-Depth engine (Trigger -> FGA -> Unified Audit -> IDS -> Active IPS),
 * synchronized with `shared/detection_policy.json`.
 */
export function evaluateOracleSqlBatch(
  sqlScript: string,
  dbUser: string,
  currentUsers: DbUser[],
  currentAlerts: AlertItem[],
  currentTriggers: TriggerAlert[],
  autoResponse: boolean,
  customHost: string = 'LAPTOP-R03ORTGV',
  customOsUser: string = 'pc',
  customClient: string = 'SQL Developer',
  employees: Employee[] = INITIAL_EMPLOYEES,
  userClearedAt: Record<string, string> = {}
): OracleExecutionOutcome {
  const statements = splitSqlStatements(sqlScript);
  const user = dbUser.trim().toUpperCase() || 'U1';
  const nowBase = new Date();
  const baseNowStr = formatUtcTimestamp(nowBase);
  const ctx = `${customClient} (${customOsUser}@${customHost})`;

  const newAlerts: AlertItem[] = [];
  const newTriggers: TriggerAlert[] = [];
  const newFgaEvents: FgaEvent[] = [];
  const newAuditLogs: AuditLogRow[] = [];
  const oracleOutputs: string[] = [];

  let nextTrigId =
    currentTriggers.reduce((max, t) => Math.max(max, Number(t.ALERT_ID) || 0), 100) + 1;

  const targetUserObj = currentUsers.find((u) => u.USERNAME.toUpperCase() === user);
  const isCurrentlyLocked = targetUserObj?.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
  const isCurrentlyReadOnly = targetUserObj?.DML_STATUS.toUpperCase() === 'READ-ONLY';

  if (isCurrentlyLocked) {
    statements.forEach(() => {
      oracleOutputs.push(
        `ORA-28000: the account ${user} is locked (Phiên kết nối bị từ chối bởi Active IPS Level 3)`
      );
    });
    return {
      newAlerts,
      newTriggers,
      newFgaEvents,
      newAuditLogs,
      updatedUsers: currentUsers,
      oracleOutputs,
    };
  }

  // Session-level contextual checks (Masquerading & Suspicious Client)
  if (statements.length > 0) {
    const masqResult = detectMasquerading(user, customHost, customOsUser, customClient);
    if (masqResult.isMasquerading) {
      const masqScore = policy.attack_scores.masquerading;
      newAlerts.push(
        makeAlert(
          `MASQ|${user}|${baseNowStr}|${customHost}|${customOsUser}`,
          'HIGH',
          masqScore,
          baseNowStr,
          user,
          '[DBMS - Masquerading Attack] Giả mạo / Giả danh tài khoản hợp pháp từ ngữ cảnh bất thường',
          `Phiên đăng nhập ${user} từ ${ctx} lệch chuẩn baseline (${masqResult.reason})`,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'Standard'
        )
      );
      oracleOutputs.push(
        `[IDS Masquerading Guard] Cảnh báo HIGH (${masqScore}/100): Ngữ cảnh phiên ${ctx} sai lệch baseline của ${user}.`
      );
    }

    if (customClient && SUSPICIOUS_CLIENTS_REGEX.test(customClient)) {
      const clientScore = policy.attack_scores.suspicious_client;
      newAlerts.push(
        makeAlert(
          `CLIENT|${user}|${customClient}|${baseNowStr}`,
          'MEDIUM',
          clientScore,
          baseNowStr,
          user,
          '[DBMS - Contextual Anomaly] Phát hiện công cụ kết nối bất thường',
          `Kết nối bằng công cụ nghi vấn '${customClient}' từ ${customOsUser}@${customHost}`,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'Standard'
        )
      );
      oracleOutputs.push(
        `[IDS Client Watch] Cảnh báo MEDIUM (${clientScore}/100): Phát hiện công cụ kết nối '${customClient}'.`
      );
    }
  }

  const statQueriesInBatch: string[] = [];
  let nvSelectCount = 0;

  const emitFgaHighSalaryAccess = (
    actionName: string,
    nowStr: string,
    safeSql: string,
    idx: number
  ) => {
    const fgaScore = policy.attack_scores.fga_sensitive_access;
    newFgaEvents.push({
      EVENT_TIMESTAMP: nowStr,
      DBUSERNAME: user,
      ACTION_NAME: actionName,
      OBJECT_SCHEMA: 'SYS',
      OBJECT_NAME: 'NV',
      FGA_POLICY_NAME: 'FGA_HIGH_SALARY_ACCESS',
      AUDIT_TYPE: 'FineGrainedAudit',
      SQL_TEXT: safeSql,
      OS_USERNAME: customOsUser,
      USERHOST: customHost,
      CLIENT_PROGRAM_NAME: customClient,
      RETURN_CODE: 0,
    });
    newAlerts.push(
      makeAlert(
        `FGA_SAL|${user}|${nowStr}|${idx}`,
        'MEDIUM',
        fgaScore,
        nowStr,
        user,
        '[SDB - Direct Attack] Truy cập cột nhạy cảm LUONG/CMND trên bảng NV (FGA_HIGH_SALARY_ACCESS)',
        safeSql,
        customClient,
        customHost,
        customOsUser,
        ctx,
        'FineGrainedAudit',
        'FGA_HIGH_SALARY_ACCESS'
      )
    );
    oracleOutputs.push(
      `[DBMS_FGA] Truy vấn chạm chính sách FGA_HIGH_SALARY_ACCESS (Score ${fgaScore}/100).`
    );
  };

  statements.forEach((rawStmt, idx) => {
    const tsDate = new Date(nowBase.getTime() + idx * 1000);
    const nowStr = formatUtcTimestamp(tsDate);
    const normSql = rawStmt.replace(/\s+/g, ' ').trim();
    const safeSql = sanitizeSqlCredentials(normSql);
    const upperSql = normSql.toUpperCase();

    // 1. Check Honeytoken Trap (NV_TRAP / 001099000000) — highest precedence (95 CRITICAL)
    if (HONEYTOKEN_REGEX.test(normSql)) {
      const trapScore = policy.attack_scores.honeytoken_trap;
      const actionName = upperSql.split(/\s+/)[0] || 'SELECT';
      newFgaEvents.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: actionName,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
        AUDIT_TYPE: 'FineGrainedAudit',
        SQL_TEXT: safeSql,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        RETURN_CODE: policy.trigger_codes.FGA_TRAP_BLOCK,
      });

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: actionName,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: safeSql,
        RETURN_CODE: policy.trigger_codes.FGA_TRAP_BLOCK,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'FineGrainedAudit',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
      });

      newAlerts.push(
        makeAlert(
          `TRAP|${user}|${nowStr}|${idx}`,
          'CRITICAL',
          trapScore,
          nowStr,
          user,
          '[SDB - Direct Attack & Honeytoken] Truy cập trực tiếp dữ liệu cá nhân & chạm bẫy NV_TRAP',
          safeSql,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'FineGrainedAudit',
          'FGA_HONEYTOKEN_TRAP'
        )
      );

      oracleOutputs.push(
        `[DBMS_FGA] Kích hoạt bẫy FGA_HONEYTOKEN_TRAP (ORA-20003)! Cảnh báo CRITICAL (Risk ${trapScore}/100) đã gửi về Dashboard.`
      );
      return;
    }

    // 2. Check SQL Injection (canonical policy.patterns.sqli) — precedes DML_RO & Triggers (95 CRITICAL)
    if (SQLI_REGEX.test(normSql)) {
      const sqliScore = policy.attack_scores.sql_injection;
      const actionName = upperSql.split(/\s+/)[0] || 'SELECT';
      newFgaEvents.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: actionName,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
        AUDIT_TYPE: 'FineGrainedAudit',
        SQL_TEXT: safeSql,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        RETURN_CODE: 0,
      });

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: actionName,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: safeSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'FineGrainedAudit',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
      });

      newAlerts.push(
        makeAlert(
          `SQLI|${user}|${nowStr}|${idx}`,
          'CRITICAL',
          sqliScore,
          nowStr,
          user,
          '[DBMS - SQL Injection] Chèn mã độc làm thay đổi cấu trúc câu lệnh SQL',
          safeSql,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'FineGrainedAudit',
          'FGA_HONEYTOKEN_TRAP'
        )
      );

      oracleOutputs.push(
        `[IDS SQLi Engine] Phát hiện mẫu SQL Injection (${safeSql})! Điểm rủi ro: ${sqliScore}/100 (Level 3 Full Isolation).`
      );
      return;
    }

    // 3. Check DML when user is already downgraded to READ-ONLY (Level 2)
    const isDml = /^(UPDATE|DELETE|INSERT)\b/i.test(normSql);
    if (isDml && isCurrentlyReadOnly) {
      const verb = upperSql.split(/\s+/)[0];
      const roScore = policy.attack_scores.dml_readonly_violation;
      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: verb,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: safeSql,
        RETURN_CODE: 41900,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
      });
      newAlerts.push(
        makeAlert(
          `DML_RO|${user}|${nowStr}|${idx}`,
          'HIGH',
          roScore,
          nowStr,
          user,
          `Vi phạm Read-Only (Hạ quyền Level 2): Cố tình thực thi ${verb} (ORA-41900)`,
          safeSql,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'Standard'
        )
      );
      oracleOutputs.push(
        `ORA-41900: missing ${verb} privilege on "SYS"."NV" (Tài khoản ${user} đang bị cô lập READ-ONLY)`
      );
      return;
    }

    // 2. Check Trigger Block: DELETE FROM SYS.NV (ORA-20001)
    if (/^DELETE\s+(?:FROM\s+)?(?:SYS\.|SYSTEM\.)?NV\b/i.test(normSql)) {
      const manvMatch = normSql.match(/\bMANV\s*=\s*['"]([^'"]+)['"]/i);
      const targetManv = manvMatch ? manvMatch[1].toUpperCase() : 'NV2';
      const trigDetails = `Cố tình xóa nhân viên mã: ${targetManv}`;
      const trigId = nextTrigId++;
      const trigScore = policy.attack_scores.trigger_block;

      newTriggers.push({
        ALERT_ID: trigId,
        EVENT_TIME: nowStr,
        DB_USER: user,
        ATTACK_TYPE: 'UNAUTHORIZED_DELETE',
        DETAILS: trigDetails,
      });

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'DELETE',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: safeSql,
        RETURN_CODE: policy.trigger_codes.UNAUTHORIZED_DELETE,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
      });

      newAlerts.push(
        makeAlert(
          `TRIG|${trigId}|${user}|${nowStr}`,
          'HIGH',
          trigScore,
          nowStr,
          user,
          'Trigger Block: Xóa nhân viên trái phép (ORA-20001)',
          `${trigDetails} · SQL: ${safeSql}`,
          'Database Trigger',
          'SYS.TRG_PROTECT_NV',
          customOsUser,
          'Database Trigger (SYS.TRG_PROTECT_NV)',
          'Standard'
        )
      );

      oracleOutputs.push(
        `ORA-20001: IDS BLOCK: Ban khong duoc phep xoa du lieu nhan vien! (${targetManv}) — Đã ghi log tự trị SYS.IDS_TRIGGER_ALERTS #${trigId}`
      );
      return;
    }

    // 2b. Check Trigger Block: INSERT INTO SYS.NV integrity check (ORA-20004)
    if (/^INSERT\s+INTO\s+(?:SYS\.|SYSTEM\.)?NV\b/i.test(normSql)) {
      const valuesMatch = normSql.match(/\bVALUES\s*\(([\s\S]+)\)/i);
      if (valuesMatch) {
        const vals = splitTopLevelCommas(valuesMatch[1]);
        const rawManv = vals[0] ? parseSqlStringLiteral(vals[0]) : null;
        const rawLuong = vals[2] ? evaluateArithmeticExpression(vals[2], 0) : null;
        const isTrapInsert = rawManv !== null && rawManv.toUpperCase() === 'NV_TRAP';
        const isBadLuong =
          vals.length >= 3 && (rawLuong === null || rawLuong <= 0 || rawLuong > 5000);

        if (isTrapInsert || isBadLuong) {
          const trigId = nextTrigId++;
          const trigScore = policy.attack_scores.trigger_block;
          const trigDetails = `Từ chối INSERT vi phạm toàn vẹn dữ liệu: manv=${rawManv ?? 'NULL'}, luong=${rawLuong ?? 'NULL'}`;

          newTriggers.push({
            ALERT_ID: trigId,
            EVENT_TIME: nowStr,
            DB_USER: user,
            ATTACK_TYPE: 'UNAUTHORIZED_DML_INTEGRITY',
            DETAILS: trigDetails,
          });
          newAuditLogs.push({
            EVENT_TIMESTAMP: nowStr,
            DBUSERNAME: user,
            ACTION_NAME: 'INSERT',
            OBJECT_SCHEMA: 'SYS',
            OBJECT_NAME: 'NV',
            SQL_TEXT: safeSql,
            RETURN_CODE: policy.trigger_codes.UNAUTHORIZED_DML_INTEGRITY,
            OS_USERNAME: customOsUser,
            USERHOST: customHost,
            CLIENT_PROGRAM_NAME: customClient,
            AUDIT_TYPE: 'Standard',
            UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
          });
          newAlerts.push(
            makeAlert(
              `TRIG|${trigId}|${user}|${nowStr}`,
              'HIGH',
              trigScore,
              nowStr,
              user,
              'Trigger Block: Vi phạm tính toàn vẹn dữ liệu DML (ORA-20004)',
              `${trigDetails} · SQL: ${safeSql}`,
              'Database Trigger',
              'SYS.TRG_PROTECT_NV',
              customOsUser,
              'Database Trigger (SYS.TRG_PROTECT_NV)',
              'Standard'
            )
          );
          oracleOutputs.push(
            `ORA-20004: IDS BLOCK (ORA-20004): Tu choi INSERT vi pham tinh toan ven du lieu / luong bat thuong! — SYS.IDS_TRIGGER_ALERTS #${trigId}`
          );
          return;
        }
      }
    }

    // 3. Check Trigger Block: UPDATE SYS.NV SET ... (multi-column, arithmetic, ORA-20002 & ORA-20004)
    const updateMatch = normSql.match(/^UPDATE\s+(?:SYS\.|SYSTEM\.)?NV\s+SET\s+([\s\S]+)$/i);
    if (updateMatch) {
      const { beforeWhere: setClause, whereClause } = extractTopLevelWhere(updateMatch[1]);
      const assignments = parseUpdateAssignments(setClause);
      const manvMatch = whereClause.match(/\bMANV\s*=\s*['"]([^'"]+)['"]/i);
      const targetManv = manvMatch ? manvMatch[1].toUpperCase() : undefined;
      const emp = targetManv
        ? employees.find((e) => e.MANV.toUpperCase() === targetManv)
        : undefined;
      const oldLuong = emp ? Number(emp.LUONG) : 900;
      const isTrapEmployee = targetManv === 'NV_TRAP';
      const trigScore = policy.attack_scores.trigger_block;

      if ('LUONG' in assignments) {
        const newLuong = evaluateArithmeticExpression(assignments.LUONG, oldLuong);
        const salaryViolated =
          newLuong === null ||
          !Number.isFinite(newLuong) ||
          newLuong <= 0 ||
          newLuong > oldLuong * 1.5 ||
          newLuong < oldLuong * 0.5 ||
          (!isTrapEmployee && newLuong > 5000);

        if (salaryViolated) {
          const trigDetails = `Thay đổi lương bất thường từ ${oldLuong} lên ${newLuong ?? 'NULL'}${targetManv ? ` (manv: ${targetManv})` : ''}`;
          const trigId = nextTrigId++;

          newTriggers.push({
            ALERT_ID: trigId,
            EVENT_TIME: nowStr,
            DB_USER: user,
            ATTACK_TYPE: 'ABNORMAL_SALARY_MODIFICATION',
            DETAILS: trigDetails,
          });
          newAuditLogs.push({
            EVENT_TIMESTAMP: nowStr,
            DBUSERNAME: user,
            ACTION_NAME: 'UPDATE',
            OBJECT_SCHEMA: 'SYS',
            OBJECT_NAME: 'NV',
            SQL_TEXT: safeSql,
            RETURN_CODE: policy.trigger_codes.ABNORMAL_SALARY_MODIFICATION,
            OS_USERNAME: customOsUser,
            USERHOST: customHost,
            CLIENT_PROGRAM_NAME: customClient,
            AUDIT_TYPE: 'Standard',
            UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
          });
          newAlerts.push(
            makeAlert(
              `TRIG|${trigId}|${user}|${nowStr}`,
              'HIGH',
              trigScore,
              nowStr,
              user,
              'Trigger Block: Gian lận thay đổi lương vượt ngưỡng (ORA-20002)',
              `${trigDetails} · SQL: ${safeSql}`,
              'Database Trigger',
              'SYS.TRG_PROTECT_NV',
              customOsUser,
              'Database Trigger (SYS.TRG_PROTECT_NV)',
              'Standard'
            )
          );
          oracleOutputs.push(
            `ORA-20002: IDS BLOCK: Phat hien hanh vi gian lan thay doi luong vuot nguong! (${oldLuong} -> ${newLuong ?? 'NULL'}) — Đã ghi log tự trị SYS.IDS_TRIGGER_ALERTS #${trigId}`
          );
          return;
        }
      }

      const manvTampered =
        'MANV' in assignments &&
        (() => {
          const parsedManv = parseSqlStringLiteral(assignments.MANV);
          return parsedManv === null || !targetManv || parsedManv.toUpperCase() !== targetManv;
        })();

      const cmndTampered =
        'CMND' in assignments &&
        (() => {
          const parsedCmnd = parseSqlStringLiteral(assignments.CMND);
          return (
            parsedCmnd === null ||
            parsedCmnd.trim().length < 9 ||
            !emp ||
            parsedCmnd.trim() !== emp.CMND
          );
        })();

      const hotenTampered =
        'HOTEN' in assignments &&
        (() => {
          const parsedHoten = parseSqlStringLiteral(assignments.HOTEN);
          return (
            parsedHoten === null ||
            parsedHoten.trim().length < 2 ||
            !emp ||
            parsedHoten.trim().toLowerCase() !== emp.HOTEN.trim().toLowerCase()
          );
        })();

      if (manvTampered || cmndTampered || hotenTampered) {
        const trigDetails = `Cố tình sửa đổi/giả mạo thông tin định danh (MANV/CMND/HOTEN)${targetManv ? ` của nhân viên mã: ${targetManv}` : ''}`;
        const trigId = nextTrigId++;

        newTriggers.push({
          ALERT_ID: trigId,
          EVENT_TIME: nowStr,
          DB_USER: user,
          ATTACK_TYPE: 'UNAUTHORIZED_DML_INTEGRITY',
          DETAILS: trigDetails,
        });
        newAuditLogs.push({
          EVENT_TIMESTAMP: nowStr,
          DBUSERNAME: user,
          ACTION_NAME: 'UPDATE',
          OBJECT_SCHEMA: 'SYS',
          OBJECT_NAME: 'NV',
          SQL_TEXT: safeSql,
          RETURN_CODE: policy.trigger_codes.UNAUTHORIZED_DML_INTEGRITY,
          OS_USERNAME: customOsUser,
          USERHOST: customHost,
          CLIENT_PROGRAM_NAME: customClient,
          AUDIT_TYPE: 'Standard',
          UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
        });
        newAlerts.push(
          makeAlert(
            `TRIG|${trigId}|${user}|${nowStr}`,
            'HIGH',
            trigScore,
            nowStr,
            user,
            'Trigger Block: Giả mạo thông tin định danh CMND/HOTEN/MANV (ORA-20004)',
            `${trigDetails} · SQL: ${safeSql}`,
            'Database Trigger',
            'SYS.TRG_PROTECT_NV',
            customOsUser,
            'Database Trigger (SYS.TRG_PROTECT_NV)',
            'Standard'
          )
        );
        oracleOutputs.push(
          `ORA-20004: IDS BLOCK (ORA-20004): Khong duoc phep thay doi / gia mao thong tin dinh danh (CMND/HOTEN/MANV)! — SYS.IDS_TRIGGER_ALERTS #${trigId}`
        );
        return;
      }
    }

    // 4. Check Unauthorized Encryption Key Access
    if (CRYPTO_DIRECT_REGEX.test(normSql) || CRYPTO_INDIRECT_REGEX.test(normSql)) {
      const isDirect = CRYPTO_DIRECT_REGEX.test(normSql);
      const cryptoScore = policy.attack_scores.crypto_key_access;

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: upperSql.split(/\s+/)[0] || 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: isDirect ? 'V$ENCRYPTION_KEYS' : 'DBMS_CRYPTO',
        SQL_TEXT: safeSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_CRYPTO_KEY_POL',
      });

      newAlerts.push(
        makeAlert(
          `CRYPTO|${user}|${nowStr}|${idx}`,
          'CRITICAL',
          cryptoScore,
          nowStr,
          user,
          `[DBMS - Key Access] Truy cập khóa mã hóa trái phép (${
            isDirect ? 'Trực tiếp kho khóa TDE' : 'Gián tiếp qua DBMS_CRYPTO'
          })`,
          safeSql,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'Standard'
        )
      );

      oracleOutputs.push(
        `[IDS Crypto Guard] Phát hiện truy cập khóa mã hóa trái phép (Risk ${cryptoScore}/100 - Level 3).`
      );
      return;
    }

    // 7. Check Privilege Escalation (policy.priv_abuse_actions)
    const privMatch = normSql.match(PRIV_ABUSE_REGEX);
    if (privMatch) {
      const actionVerb = privMatch[1].replace(/\s+/g, ' ').toUpperCase();
      const privScore = policy.attack_scores.privilege_escalation;

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: actionVerb,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'DBA',
        SQL_TEXT: safeSql,
        RETURN_CODE: 1031,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_PRIV_ABUSE_POL',
      });

      newAlerts.push(
        makeAlert(
          `PRIV|${user}|${nowStr}|${idx}`,
          'CRITICAL',
          privScore,
          nowStr,
          user,
          `[DBMS - Privilege Escalation] Leo thang đặc quyền vượt mức được cấp (${actionVerb})`,
          safeSql,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'Standard'
        )
      );

      oracleOutputs.push(
        `[IDS Privilege Watch] Phát hiện hành vi leo thang đặc quyền (${actionVerb})! Điểm rủi ro: ${privScore}/100.`
      );
      return;
    }

    // 7b. Check Dangerous DDL (DROP TABLE / TRUNCATE TABLE -> 85 CRITICAL, ALTER TABLE / CREATE TABLE -> 65 HIGH)
    const ddlDestructiveMatch = normSql.match(DDL_DESTRUCTIVE_REGEX);
    const ddlModifyMatch = !ddlDestructiveMatch ? normSql.match(DDL_MODIFY_REGEX) : null;
    if (ddlDestructiveMatch || ddlModifyMatch) {
      const isDestructive = Boolean(ddlDestructiveMatch);
      const actionVerb = (ddlDestructiveMatch || ddlModifyMatch)![1]
        .replace(/\s+/g, ' ')
        .toUpperCase();
      const ddlScore = isDestructive
        ? policy.attack_scores.ddl_destructive
        : policy.attack_scores.ddl_modify;
      const ddlSeverity: Severity = isDestructive ? 'CRITICAL' : 'HIGH';

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: actionVerb,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: safeSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_DDL_POL',
      });

      newAlerts.push(
        makeAlert(
          `DDL|${user}|${nowStr}|${idx}`,
          ddlSeverity,
          ddlScore,
          nowStr,
          user,
          `[DBMS - Unauthorized DDL] Thực thi lệnh DDL ${isDestructive ? 'phá hủy dữ liệu' : 'thay đổi cấu trúc'} (${actionVerb})`,
          safeSql,
          customClient,
          customHost,
          customOsUser,
          ctx,
          'Standard'
        )
      );

      oracleOutputs.push(
        `[IDS DDL Guard] Phát hiện lệnh DDL nguy hiểm (${actionVerb})! Điểm rủi ro: ${ddlScore}/100 (${ddlSeverity}).`
      );
      return;
    }

    // Skip harmless IDE dictionary/metadata queries (DUAL, ALL_OBJECTS, ...)
    if (isPureIdeMetadataQuery(normSql)) {
      oracleOutputs.push(`Bỏ qua câu lệnh metadata nội bộ IDE: ${safeSql}`);
      return;
    }

    // 8. Check Statistical Queries (COUNT, SUM, AVG, ...)
    if (STAT_FUNC_REGEX.test(normSql)) {
      statQueriesInBatch.push(safeSql);
      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: safeSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
      });
      if (NV_TABLE_REGEX.test(normSql) && /\b(?:LUONG|CMND)\b/i.test(normSql)) {
        emitFgaHighSalaryAccess('SELECT', nowStr, safeSql, idx);
      }
      return;
    }

    // 9. Standard SQL / FGA_HIGH_SALARY_ACCESS
    const actionVerb = upperSql.split(/\s+/)[0] || 'SELECT';
    if (actionVerb === 'SELECT' && NV_TABLE_REGEX.test(normSql)) {
      nvSelectCount++;
    }

    newAuditLogs.push({
      EVENT_TIMESTAMP: nowStr,
      DBUSERNAME: user,
      ACTION_NAME: actionVerb,
      OBJECT_SCHEMA: 'SYS',
      OBJECT_NAME: 'NV',
      SQL_TEXT: safeSql,
      RETURN_CODE: 0,
      OS_USERNAME: customOsUser,
      USERHOST: customHost,
      CLIENT_PROGRAM_NAME: customClient,
      AUDIT_TYPE: 'Standard',
      UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
    });

    const touchesSensitiveCols =
      NV_TABLE_REGEX.test(normSql) &&
      (/\b(LUONG|CMND)\b/i.test(normSql) || /^\s*SELECT\s+\*\s+FROM\b/i.test(normSql));

    if (touchesSensitiveCols) {
      emitFgaHighSalaryAccess(actionVerb, nowStr, safeSql, idx);
    } else {
      oracleOutputs.push(
        `Thực thi thành công câu lệnh chuẩn: ${safeSql} (Đã ghi nhận vào UNIFIED_AUDIT_TRAIL).`
      );
    }
  });

  // Bulk Querying anomaly detection (threshold from policy.bulk_query)
  if (nvSelectCount >= policy.bulk_query.threshold_count) {
    const bulkScore = policy.attack_scores.bulk_querying;
    const bulkTime = formatUtcTimestamp(new Date(nowBase.getTime() + statements.length * 1000));
    newAlerts.push(
      makeAlert(
        `BULK|${user}|${bulkTime}|${nvSelectCount}`,
        'MEDIUM',
        bulkScore,
        bulkTime,
        user,
        '[DBMS - Behavioral Anomaly] Tần suất truy vấn đột biến trên bảng NV (Bulk Querying)',
        `Thực hiện dồn dập ${nvSelectCount} truy vấn SELECT trên bảng SYS.NV trong cùng một phiên (nguy cơ Data Exfiltration)`,
        customClient,
        customHost,
        customOsUser,
        ctx,
        'Standard'
      )
    );
    oracleOutputs.push(
      `[IDS Bulk Watch] Phát hiện tần suất truy vấn đột biến (${nvSelectCount} SELECT liên tiếp)! Điểm rủi ro: ${bulkScore}/100.`
    );
  }

  // Evaluate collected Statistical Queries (SDB Inference Engine)
  if (statQueriesInBatch.length > 0) {
    const nowStr = formatUtcTimestamp(new Date(nowBase.getTime() + statements.length * 1000));
    const joinedSql = statQueriesInBatch.join(' ; ');
    const statCount = statQueriesInBatch.length;
    const distinctWheres = new Set(statQueriesInBatch.map(extractWhereNormalized));
    const hasCount = statQueriesInBatch.some((s) => /\bCOUNT\s*\(/i.test(s));
    const hasSumOrAvg = statQueriesInBatch.some((s) => /\b(SUM|AVG)\s*\(/i.test(s));
    const hasSingleCombinedCountAndSum = statQueriesInBatch.some(
      (s) => /\bCOUNT\s*\(/i.test(s) && /\b(SUM|AVG)\s*\(/i.test(s)
    );
    const hasTracker = statQueriesInBatch.some((s) =>
      /\bOR\b|!=|<>|\bNOT\b/i.test(extractWhereNormalized(s))
    );
    const sumCount = statQueriesInBatch.filter((s) => /\b(SUM|AVG)\s*\(/i.test(s)).length;

    let alertKey = `STAT_INF|${user}|${nowStr}|${statCount}`;
    let sdbSeverity: Severity = 'HIGH';
    let sdbScore = policy.attack_scores.sdb_count_based;
    let sdbType =
      '[SDB - Count-based Attack] Tấn công suy diễn thống kê kết hợp COUNT và SUM/AVG';
    let sdbDetails = `Phát hiện ${statCount} truy vấn hàm thống kê SDB: ${joinedSql}`;

    if (statCount >= 3) {
      if (hasTracker) {
        sdbType =
          '[SDB - Tracker Attack] Tấn công trình theo dõi lách kiểm soát kích cỡ tập truy vấn';
        sdbScore = policy.attack_scores.sdb_tracker;
      } else if (sumCount >= 3 && distinctWheres.size >= 3) {
        sdbType =
          '[SDB - Linear System Attack] Thiết lập hệ phương trình tuyến tính A*X = B từ chuỗi SUM/AVG';
        sdbScore = policy.attack_scores.sdb_linear_system;
      } else {
        sdbType =
          '[SDB - Count-based Attack] Thực hiện chuỗi truy vấn thống kê liên tiếp suy diễn dữ liệu cá nhân';
        sdbScore = policy.attack_scores.sdb_count_based;
      }
    } else if (
      hasSingleCombinedCountAndSum ||
      (statCount === 2 && hasCount && hasSumOrAvg && distinctWheres.size === 1)
    ) {
      alertKey = `STAT_COUNT_SUM|${user}|${nowStr}`;
      sdbType =
        '[SDB - Count-based Attack] Tấn công dựa vào đếm kết hợp COUNT và SUM/AVG trên cùng tập lọc';
      sdbScore = policy.attack_scores.sdb_count_based;
      sdbSeverity = 'HIGH';
    } else {
      alertKey = `STAT_WARN|${user}|${nowStr}|${statCount}`;
      sdbType =
        '[SDB - Statistical Probe] Thăm dò thống kê SDB mức độ thấp (1-2 truy vấn)';
      sdbScore = policy.attack_scores.sdb_probe_low;
      sdbSeverity = 'LOW';
      sdbDetails = `Phát hiện ${statCount} truy vấn hàm thống kê thăm dò trên bảng nhạy cảm: ${joinedSql}`;
    }

    newAlerts.push(
      makeAlert(
        alertKey,
        sdbSeverity,
        sdbScore,
        nowStr,
        user,
        sdbType,
        sdbDetails,
        customClient,
        customHost,
        customOsUser,
        ctx,
        'Standard'
      )
    );

    oracleOutputs.push(
      `[IDS SDB Inference Engine] Phát hiện ${sdbType} (${statCount} truy vấn thống kê)! Điểm rủi ro: ${sdbScore}/100.`
    );
  }

  // Recalculate User Risk & Apply Active IPS Response via shared policy engine
  const clearedCutoff = userClearedAt[user] ?? userClearedAt[dbUser.trim()] ?? '';
  const updatedUsers = currentUsers.map((u) => {
    if (u.USERNAME.toUpperCase() !== user) return u;
    const activeNewAlerts = newAlerts.filter((a) => a.user.toUpperCase() === user);
    const activeHistoryAlerts = currentAlerts.filter(
      (a) => a.user.toUpperCase() === user && (!clearedCutoff || a.time > clearedCutoff)
    );
    const userAlerts = [...activeNewAlerts, ...activeHistoryAlerts];
    if (userAlerts.length === 0) return u;

    const totalScore = computeUserRiskScore(userAlerts.map((a) => a.risk_score));
    const { level, label } = classifyResponseLevel(totalScore);

    let acctStatus = u.ACCOUNT_STATUS;
    let dmlStatus = u.DML_STATUS;
    let privs = u.PRIVILEGES;
    let lockDate = u.LOCK_DATE;

    if (autoResponse) {
      if (level === 3) {
        acctStatus = 'LOCKED';
        dmlStatus = 'READ-ONLY';
        privs = 'SELECT';
        lockDate = lockDate || baseNowStr;
      } else if (level === 2 && !acctStatus.toUpperCase().includes('LOCK')) {
        dmlStatus = 'READ-ONLY';
        privs = 'SELECT';
      }
    }

    return {
      ...u,
      RISK_SCORE: totalScore,
      RESPONSE_LEVEL: level,
      RESPONSE_LABEL: label,
      ACCOUNT_STATUS: acctStatus,
      DML_STATUS: dmlStatus,
      PRIVILEGES: privs,
      LOCK_DATE: lockDate,
    };
  });

  return {
    newAlerts,
    newTriggers,
    newFgaEvents,
    newAuditLogs,
    updatedUsers,
    oracleOutputs,
  };
}
