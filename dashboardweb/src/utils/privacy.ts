/**
 * Utility functions for redacting passwords, credentials, usernames,
 * hostnames, and sensitive PII (CMND/CCCD) in the Oracle DB-IDS monitoring system.
 */

const PASSWORD_REGEX =
  /\b(IDENTIFIED\s+BY)\s+(?:VALUES\s+)?(?:"[^"]*"|'[^']*'|[^\s;]+)(?:\s+REPLACE\s+(?:"[^"]*"|'[^']*'|[^\s;]+))?/gi;
const USER_IDENTIFIED_REGEX =
  /\b((?:CREATE|ALTER)\s+USER\s+)("?)([A-Za-z0-9_#$]+)(\2)(\s+IDENTIFIED\b)/gi;
const CONNECT_CRED_REGEX =
  /\b(CONN(?:ECT)?\s+)([A-Za-z0-9_#$]+)\/(?:"[^"]*"|'[^']*'|[^\s@;]+)(@[A-Za-z0-9_.:/-]+)?/gi;
const OS_HOST_DETAIL_REGEX =
  /(^|[\s(,:='"])([A-Za-z0-9_.-]+)@([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)/g;
const IPV4_REGEX =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const CMND_LITERAL_REGEX = /\b\d{9,12}\b/g;
const EMPLOYEE_ID_EXCLUSION_REGEX = /^NV(?:\d+|_TRAP)$/i;

/**
 * Always strips any database password from SQL text or logs, regardless of toggle state.
 */
export function sanitizeSqlCredentials(sql: string, maskUsernames: boolean = false): string {
  if (!sql) return '';
  let result = sql.replace(PASSWORD_REGEX, '$1 "••••••••"');
  if (maskUsernames) {
    result = result.replace(
      USER_IDENTIFIED_REGEX,
      (_match: string, prefix: string, quote: string, user: string, closeQuote: string, suffix: string) =>
        `${prefix}${quote}${maskUsername(user, true)}${closeQuote}${suffix}`
    );
  }
  result = result.replace(
    CONNECT_CRED_REGEX,
    (_match: string, prefix: string, user: string, dsn?: string) => {
      const safeUser = maskUsernames ? maskUsername(user) : user;
      return `${prefix}${safeUser}/••••••••${dsn || ''}`;
    }
  );
  return result;
}

/**
 * Redacts SQL credentials unconditionally and, when privacyMode is active, masks
 * CMND/CCCD literals, osUser@host pairs, IPv4 addresses, and known usernames
 * (while preserving employee IDs like NV1..NV4 and NV_TRAP).
 */
export function redactSensitiveDetails(
  text: string,
  privacyMode: boolean,
  knownUsers: string[] = []
): string {
  if (!text) return '';
  let result = sanitizeSqlCredentials(text, privacyMode);
  if (!privacyMode) return result;

  result = result.replace(
    OS_HOST_DETAIL_REGEX,
    (_match: string, prefix: string, osUser: string, host: string) =>
      `${prefix}${maskOsUser(osUser, true)}@${maskHost(host, true)}`
  );

  result = result.replace(IPV4_REGEX, (ip: string) => maskHost(ip, true));
  result = result.replace(CMND_LITERAL_REGEX, (cmnd: string) => maskCmnd(cmnd, true));

  const targetUsers = Array.from(
    new Set(
      knownUsers
        .map((u) => u.trim())
        .filter((u) => u.length > 0 && !EMPLOYEE_ID_EXCLUSION_REGEX.test(u))
    )
  ).sort((a, b) => b.length - a.length);

  if (targetUsers.length > 0) {
    const escapedUsers = targetUsers.map((u) => u.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const userTokenRegex = new RegExp(`\\b(?:${escapedUsers.join('|')})\\b`, 'gi');
    result = result.replace(userTokenRegex, (token: string) => maskUsername(token, true));
  }

  return result;
}

/**
 * Masks a database username (e.g., U1 -> U•••1, ADMIN -> AD•••N) when privacy mode is active.
 */
export function maskUsername(username: string, enabled: boolean = true): string {
  if (!username) return '—';
  if (!enabled) return username;
  const clean = username.trim();
  if (clean.length <= 2) {
    return `${clean[0]}••${clean.slice(1)}`;
  }
  return `${clean[0]}•••${clean[clean.length - 1]}`;
}

/**
 * Masks OS username and host context (e.g. "SQL Developer (pc@LAPTOP-R03ORTGV)" -> "SQL Developer (•••@HOST-••••GV)")
 */
export function maskContextString(context: string, enabled: boolean = true): string {
  if (!context) return '—';
  if (!enabled) return context;
  return context.replace(
    /\(([^@)]+)@([^)]+)\)/g,
    (_m: string, osUser: string, host: string) => {
      const maskedOs = osUser.length > 1 ? `${osUser[0]}•••` : '•••';
      const maskedHost =
        host.length > 4 ? `${host.slice(0, 3)}••••${host.slice(-2)}` : 'HOST-••••';
      return `(${maskedOs}@${maskedHost})`;
    }
  );
}

/**
 * Masks OS username directly
 */
export function maskOsUser(osUser?: string, enabled: boolean = true): string {
  if (!osUser || osUser === '—') return '—';
  if (!enabled) return osUser;
  return osUser.length > 1 ? `${osUser[0]}•••` : '•••';
}

/**
 * Masks Hostname / IP address
 */
export function maskHost(host?: string, enabled: boolean = true): string {
  if (!host || host === '—') return '—';
  if (!enabled) return host;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const parts = host.split('.');
    return `${parts[0]}.•••.•••.${parts[3]}`;
  }
  return host.length > 4 ? `${host.slice(0, 3)}••••${host.slice(-2)}` : '••••';
}

/**
 * Masks Citizen ID (CMND / CCCD) e.g. "001206012345" -> "0012••••••45"
 */
export function maskCmnd(cmnd: string, enabled: boolean = true): string {
  if (!cmnd) return '—';
  if (!enabled) return cmnd;
  const clean = cmnd.trim();
  if (clean.length <= 4) return '••••••••';
  return `${clean.slice(0, 3)}••••••${clean.slice(-2)}`;
}

/**
 * Masks employee full name e.g. "Nguyen Van A" -> "Nguyen •••• A"
 */
export function maskEmployeeName(name: string, enabled: boolean = true): string {
  if (!name) return '—';
  if (!enabled) return name;
  const clean = name.trim();
  const parts = clean.split(/\s+/);
  if (parts.length <= 1) return `${clean[0]}••••`;
  return `${parts[0]} •••• ${parts[parts.length - 1]}`;
}

/**
 * Masks salary e.g. 900 -> "••••••"
 */
export function maskSalary(salary: number | string, enabled: boolean = true): string {
  if (salary === undefined || salary === null) return '—';
  if (!enabled) return typeof salary === 'number' ? salary.toLocaleString() : String(salary);
  return '••••••';
}
