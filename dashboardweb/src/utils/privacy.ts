/**
 * Utility functions for redacting passwords, credentials, usernames,
 * hostnames, and sensitive PII (CMND/CCCD) in the Oracle DB-IDS monitoring system.
 */

const PASSWORD_REGEX = /\b(IDENTIFIED\s+BY)\s+(['"]?[A-Za-z0-9_@#$%^&*!]+['"]?)/gi;
const CONNECT_CRED_REGEX = /\b(CONNECT\s+)([A-Za-z0-9_#$]+)\/([^\s@]+)(@[A-Za-z0-9_.:/]+)?/gi;

/**
 * Always strips any database password from SQL text or logs, regardless of toggle state.
 */
export function sanitizeSqlCredentials(sql: string, maskUsernames: boolean = false): string {
  if (!sql) return '';
  let result = sql.replace(PASSWORD_REGEX, '$1 "••••••••"');
  result = result.replace(
    CONNECT_CRED_REGEX,
    (_match, prefix, user, _pass, dsn) => {
      const safeUser = maskUsernames ? maskUsername(user) : user;
      return `${prefix}${safeUser}/••••••••${dsn || ''}`;
    }
  );
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
    (_m, osUser: string, host: string) => {
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
