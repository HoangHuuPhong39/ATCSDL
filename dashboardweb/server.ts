import crypto from 'crypto';
import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import http from 'http';
import net from 'net';
import path from 'path';
import zlib from 'zlib';
import { spawn, type ChildProcess } from 'child_process';
import { fileURLToPath } from 'url';
import policy from '../shared/detection_policy.json' with { type: 'json' };
import {
  INITIAL_ALERTS,
  INITIAL_AUDIT_LOGS,
  INITIAL_EMPLOYEES,
  INITIAL_FGA_EVENTS,
  INITIAL_TRIGGERS,
  INITIAL_USERS,
} from './src/data/initialData.ts';
import {
  getAuditKey,
  getFgaKey,
  type AlertItem,
  type AuditLogRow,
  type DataSourceMode,
  type DbUser,
  type DefenseHealth,
  type Employee,
  type FailedLogon,
  type FgaEvent,
  type TriggerAlert,
} from './src/types/ids.ts';
import {
  calculateSystemMetrics,
  recalculateUsersAfterReset,
} from './src/utils/analytics.ts';
import { evaluateOracleSqlBatch } from './src/utils/oracleDetector.ts';
import { maskCmnd, sanitizeSqlCredentials } from './src/utils/privacy.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

// Load local overrides first, then root .env (process.env always takes precedence)
dotenv.config({ path: path.join(__dirname, '.env'), override: false });
dotenv.config({ path: path.join(DEFAULT_REPO_ROOT, '.env'), override: false });

export type ActiveMode = 'oracle_live' | 'simulation';

export interface DashboardAppOptions {
  port?: number;
  host?: string;
  stateFile?: string;
  repoRoot?: string;
  bridgeUrl?: string;
  bridgeToken?: string;
  socAdminToken?: string;
  allowedOrigins?: string[];
  enableBridgeWatcher?: boolean;
  bridgeManagedExternally?: boolean;
  initialMode?: ActiveMode;
  oracleDsn?: string;
}

export interface DashboardRuntimeInfo {
  port: number;
  host: string;
  stateFile: string;
  repoRoot: string;
  bridgeUrl: string;
  bridgeToken: string;
  socAdminToken: string;
  allowedOrigins: string[];
  activeMode: ActiveMode;
  bridgeManagedExternally: boolean;
}

interface PendingOracleCommand {
  id: string;
  type: 'user_action' | 'clear_alerts' | 'toggle_ips';
  payload: Record<string, unknown>;
  createdAt: string;
}

interface TelemetryState {
  users: DbUser[];
  alerts: AlertItem[];
  fgaEvents: FgaEvent[];
  triggers: TriggerAlert[];
  auditLogs: AuditLogRow[];
  employees: Employee[];
  failedLogons: FailedLogon[];
  defenseHealth?: DefenseHealth;
  simUserClearedAt?: Record<string, string>;
}

interface SessionRecord {
  csrfToken: string;
  createdAt: number;
  expiresAt: number;
}

interface BridgeForwardResult {
  ok: boolean;
  status?: number;
  error?: string;
  networkError?: boolean;
}

const VALID_USER_ACTIONS = new Set(['lock', 'unlock', 'revoke_dml', 'grant_dml']);
const VALID_CLEAR_TARGETS = new Set([
  'single_ids',
  'single_trigger',
  'single_fga',
  'single_audit',
  'reviewed',
  'ids',
  'fga',
  'triggers',
  'audit',
  'all',
]);
const ORACLE_IDENTIFIER_RE = /^[A-Z][A-Z0-9_#$]{0,127}$/;
const PROTECTED_ACCOUNTS = new Set(
  (policy.protected_accounts || []).map((a) => String(a).trim().toUpperCase())
);
const CUTOFF_TIMESTAMP_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?Z?$/;
const MAX_PENDING_COMMANDS = 200;
const MAX_ACTIVE_SESSIONS = 200;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const SESSION_PRUNE_INTERVAL_MS = 10 * 60 * 1000;
const ORACLE_BRIDGE_BUNDLE_FILES = [
  'oracle/config.py',
  'oracle/db_client.py',
  'oracle/ips_actions.py',
  'oracle/state_store.py',
  'oracle/detector.py',
  'oracle/bridge.py',
  'oracle/requirements.txt',
  'oracle/SYS_FREEPDB1.sql',
  'oracle/DEMO_COMMANDS.sql',
  'shared/detection_policy.json',
  '.env.example',
] as const;

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function computeCrc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function toDosDateTime(date: Date): { dosTime: number; dosDate: number } {
  const year = Math.max(1980, date.getUTCFullYear());
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();
  const hours = date.getUTCHours();
  const minutes = date.getUTCMinutes();
  const seconds = Math.floor(date.getUTCSeconds() / 2);
  return {
    dosTime: ((hours & 0x1f) << 11) | ((minutes & 0x3f) << 5) | (seconds & 0x1f),
    dosDate: (((year - 1980) & 0x7f) << 9) | ((month & 0x0f) << 5) | (day & 0x1f),
  };
}

function buildZipBuffer(entries: Array<{ name: string; data: Buffer; mtime?: Date }>): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name.replace(/\\/g, '/'), 'utf8');
    const crc = computeCrc32(entry.data);
    const compressed = zlib.deflateRawSync(entry.data);
    const { dosTime, dosDate } = toDosDateTime(entry.mtime ?? new Date());

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(entry.data.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);
    localParts.push(localHeader, nameBuf, compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(entry.data.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralParts.push(centralHeader, nameBuf);

    offset += localHeader.length + nameBuf.length + compressed.length;
  }

  const centralDir = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDir, eocd]);
}

function normalizeCutoffTimestamp(rawCutoff: unknown): string | null {
  if (typeof rawCutoff !== 'string') return null;
  const match = rawCutoff.trim().match(CUTOFF_TIMESTAMP_RE);
  if (!match) return null;
  const [, datePart, timePart] = match;
  const parsed = new Date(`${datePart}T${timePart}Z`);
  if (Number.isNaN(parsed.getTime())) return null;
  if (!parsed.toISOString().startsWith(`${datePart}T${timePart}`)) return null;
  return `${datePart} ${timePart}`;
}

function getUtcTimestamp(date: Date = new Date()): string {
  return date.toISOString().replace('T', ' ').substring(0, 19);
}

function parseBoolEnv(raw: string | undefined, defaultVal: boolean): boolean {
  if (!raw || !raw.trim()) return defaultVal;
  return ['1', 'true', 'yes'].includes(raw.trim().toLowerCase());
}

function parseAllowedOrigins(raw: string | undefined, port: number): string[] {
  if (raw && raw.trim()) {
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return [`http://localhost:${port}`, `http://127.0.0.1:${port}`];
}

function safeTokenEquals(provided: string | undefined | null, expected: string): boolean {
  if (!provided || !expected) return false;
  const aDigest = crypto.createHash('sha256').update(provided, 'utf8').digest();
  const bDigest = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(aDigest, bDigest);
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();
    const rawVal = part.slice(eqIdx + 1).trim();
    if (!key) continue;
    try {
      cookies[key] = decodeURIComponent(rawVal);
    } catch {
      cookies[key] = rawVal;
    }
  }
  return cookies;
}

function writeFileAtomic(targetPath: string, content: string, mode?: number): void {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, { encoding: 'utf-8', ...(mode ? { mode } : {}) });
    fs.renameSync(tmpPath, targetPath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {
      // Best-effort cleanup
    }
    throw err;
  }
}

function getOrCreateBridgeToken(repoRoot: string, explicitToken?: string): string {
  if (explicitToken && explicitToken.trim()) {
    return explicitToken.trim();
  }
  const envToken = process.env.BRIDGE_API_TOKEN?.trim();
  if (envToken) {
    return envToken;
  }
  const secretPath = path.join(repoRoot, '.bridge_secret');
  try {
    if (fs.existsSync(secretPath)) {
      const existing = fs.readFileSync(secretPath, 'utf-8').trim();
      if (existing) return existing;
    }
  } catch {
    // Fall through to generation
  }
  const generated = crypto.randomBytes(32).toString('hex');
  try {
    writeFileAtomic(secretPath, `${generated}\n`, 0o600);
  } catch {
    // Non-fatal in read-only environments
  }
  return generated;
}

function cloneInitialSimState(): TelemetryState {
  return {
    users: INITIAL_USERS.map((u) => ({ ...u })),
    alerts: INITIAL_ALERTS.map((a) => ({ ...a })),
    fgaEvents: INITIAL_FGA_EVENTS.map((f) => ({ ...f })),
    triggers: INITIAL_TRIGGERS.map((t) => ({ ...t })),
    auditLogs: INITIAL_AUDIT_LOGS.map((r) => ({ ...r })),
    employees: INITIAL_EMPLOYEES.map((e) => ({ ...e })),
    failedLogons: [],
    defenseHealth: undefined,
    simUserClearedAt: {},
  };
}

function createEmptyLiveState(): TelemetryState {
  return {
    users: [],
    alerts: [],
    fgaEvents: [],
    triggers: [],
    auditLogs: [],
    employees: [],
    failedLogons: [],
    defenseHealth: undefined,
  };
}

function scrubAlerts(items: AlertItem[]): AlertItem[] {
  return items.slice(0, 100).map((a) => ({
    ...a,
    details: sanitizeSqlCredentials(a.details || ''),
  }));
}

function scrubFgaEvents(items: FgaEvent[]): FgaEvent[] {
  return items.slice(0, 50).map((f) => ({
    ...f,
    SQL_TEXT: sanitizeSqlCredentials(f.SQL_TEXT || ''),
  }));
}

function scrubTriggers(items: TriggerAlert[]): TriggerAlert[] {
  return items.slice(0, 50).map((t) => ({
    ...t,
    DETAILS: sanitizeSqlCredentials(t.DETAILS || ''),
  }));
}

function scrubAuditLogs(items: AuditLogRow[]): AuditLogRow[] {
  return items.slice(0, 100).map((r) => ({
    ...r,
    SQL_TEXT: sanitizeSqlCredentials(r.SQL_TEXT || ''),
  }));
}

function maskEmployeesCmnd(items: Employee[]): Employee[] {
  return items.map((e) => ({
    ...e,
    CMND: maskCmnd(e.CMND || '', true),
  }));
}

function scrubStateForPersistence(state: TelemetryState): TelemetryState {
  return {
    users: state.users,
    alerts: scrubAlerts(state.alerts),
    fgaEvents: scrubFgaEvents(state.fgaEvents),
    triggers: scrubTriggers(state.triggers),
    auditLogs: scrubAuditLogs(state.auditLogs),
    employees: maskEmployeesCmnd(state.employees),
    failedLogons: state.failedLogons,
    defenseHealth: state.defenseHealth,
    ...(state.simUserClearedAt ? { simUserClearedAt: { ...state.simUserClearedAt } } : {}),
  };
}

function isPortListening(port: number, host: string = '127.0.0.1'): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(800);
    sock.once('connect', () => {
      sock.destroy();
      resolve(true);
    });
    sock.once('error', () => {
      sock.destroy();
      resolve(false);
    });
    sock.once('timeout', () => {
      sock.destroy();
      resolve(false);
    });
    sock.connect(port, host);
  });
}

function requireJsonContentType(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  const rawCt = String(req.headers['content-type'] || '').toLowerCase();
  const mime = rawCt.split(';')[0].trim();
  if (mime !== 'application/json' && !mime.endsWith('+json')) {
    res.status(415).json({
      ok: false,
      error: 'Unsupported Media Type: Content-Type must be application/json',
    });
    return;
  }
  next();
}

export function createDashboardApp(options?: DashboardAppOptions): {
  app: express.Express;
  getRuntimeInfo: () => DashboardRuntimeInfo;
} {
  const port = options?.port ?? (Number(process.env.PORT) || 3000);
  const host = options?.host || process.env.DASHBOARD_HOST || '127.0.0.1';
  const repoRoot = options?.repoRoot ? path.resolve(options.repoRoot) : DEFAULT_REPO_ROOT;
  const stateFile = options?.stateFile
    ? path.resolve(options.stateFile)
    : path.join(__dirname, '.dashboard_state.json');
  const bridgePort = Number(process.env.BRIDGE_PORT) || 8050;
  const bridgeHost = process.env.BRIDGE_HOST || '127.0.0.1';
  const bridgeUrl = options?.bridgeUrl ?? `http://${bridgeHost}:${bridgePort}`;
  const bridgeManagedExternally =
    options?.bridgeManagedExternally ?? parseBoolEnv(process.env.BRIDGE_MANAGED_EXTERNALLY, false);
  const oracleDsn = options?.oracleDsn || process.env.ORACLE_DSN || 'localhost:1521/FREEPDB1';

  const bridgeToken = getOrCreateBridgeToken(repoRoot, options?.bridgeToken);
  const envSocToken = process.env.SOC_ADMIN_TOKEN?.trim();
  const socAdminToken =
    options?.socAdminToken && options.socAdminToken.trim()
      ? options.socAdminToken.trim()
      : envSocToken || crypto.randomBytes(24).toString('hex');

  const allowedOrigins =
    options?.allowedOrigins ?? parseAllowedOrigins(process.env.ALLOWED_ORIGINS, port);
  const allowedOriginSet = new Set(allowedOrigins);

  let activeMode: ActiveMode = options?.initialMode ?? 'oracle_live';
  let liveState: TelemetryState = createEmptyLiveState();
  let simState: TelemetryState = cloneInitialSimState();
  let autoResponse = true;
  let lastOracleSyncAt: string | null = null;
  let auditClearedAt: string | null = null;
  let fgaClearedAt: string | null = null;
  let pendingCommands: PendingOracleCommand[] = [];

  let reviewedAlertKeys = new Set<string>();
  let reviewedFgaKeys = new Set<string>();
  let reviewedTriggerIds = new Set<number>();
  let reviewedAuditKeys = new Set<string>();

  const sessions = new Map<string, SessionRecord>();

  function pruneSessions(now: number = Date.now(), reserveSlot: boolean = false): void {
    for (const [sid, rec] of sessions.entries()) {
      if (rec.expiresAt <= now) {
        sessions.delete(sid);
      }
    }
    const maxAllowed = reserveSlot ? MAX_ACTIVE_SESSIONS - 1 : MAX_ACTIVE_SESSIONS;
    while (sessions.size > maxAllowed) {
      const oldestKey = sessions.keys().next().value;
      if (oldestKey === undefined) break;
      sessions.delete(oldestKey);
    }
  }

  const sessionPruneTimer = setInterval(() => {
    pruneSessions();
  }, SESSION_PRUNE_INTERVAL_MS);
  sessionPruneTimer.unref();

  function enqueuePendingCommand(cmd: PendingOracleCommand): void {
    pendingCommands.push(cmd);
    if (pendingCommands.length > MAX_PENDING_COMMANDS) {
      pendingCommands.splice(0, pendingCommands.length - MAX_PENDING_COMMANDS);
    }
  }

  function getActiveState(): TelemetryState {
    return activeMode === 'simulation' ? simState : liveState;
  }

  function loadPersistedState(): void {
    try {
      if (!fs.existsSync(stateFile)) return;
      const raw = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
      if (typeof raw.autoResponse === 'boolean') autoResponse = raw.autoResponse;
      if (typeof raw.lastOracleSyncAt === 'string') lastOracleSyncAt = raw.lastOracleSyncAt;
      if (typeof raw.auditClearedAt === 'string') auditClearedAt = raw.auditClearedAt;
      if (typeof raw.fgaClearedAt === 'string') fgaClearedAt = raw.fgaClearedAt;
      if (Array.isArray(raw.reviewedAlertKeys)) {
        reviewedAlertKeys = new Set(raw.reviewedAlertKeys.map(String));
      }
      if (Array.isArray(raw.reviewedFgaKeys)) {
        reviewedFgaKeys = new Set(raw.reviewedFgaKeys.map(String));
      }
      if (Array.isArray(raw.reviewedTriggerIds)) {
        reviewedTriggerIds = new Set(raw.reviewedTriggerIds.map(Number));
      }
      if (Array.isArray(raw.reviewedAuditKeys)) {
        reviewedAuditKeys = new Set(raw.reviewedAuditKeys.map(String));
      }
      if (Array.isArray(raw.pendingCommands)) {
        pendingCommands = raw.pendingCommands
          .filter(
            (c: unknown): c is PendingOracleCommand =>
              Boolean(
                c &&
                  typeof c === 'object' &&
                  typeof (c as PendingOracleCommand).id === 'string' &&
                  typeof (c as PendingOracleCommand).type === 'string'
              )
          )
          .slice(-MAX_PENDING_COMMANDS);
      }

      // Only restore split liveState/simState from v2 state schema (ignore legacy flat v1 dumps)
      if (raw.version === 2 && raw.liveState && typeof raw.liveState === 'object') {
        const ls = raw.liveState as Partial<TelemetryState>;
        liveState = {
          users: Array.isArray(ls.users) ? ls.users : [],
          alerts: Array.isArray(ls.alerts) ? scrubAlerts(ls.alerts) : [],
          fgaEvents: Array.isArray(ls.fgaEvents) ? scrubFgaEvents(ls.fgaEvents) : [],
          triggers: Array.isArray(ls.triggers) ? scrubTriggers(ls.triggers) : [],
          auditLogs: Array.isArray(ls.auditLogs) ? scrubAuditLogs(ls.auditLogs) : [],
          employees: Array.isArray(ls.employees) ? maskEmployeesCmnd(ls.employees) : [],
          failedLogons: Array.isArray(ls.failedLogons) ? ls.failedLogons : [],
          defenseHealth: ls.defenseHealth,
        };
      }
      if (raw.version === 2 && raw.simState && typeof raw.simState === 'object') {
        const ss = raw.simState as Partial<TelemetryState>;
        const persistedClearedAt: Record<string, string> = {};
        if (
          ss.simUserClearedAt &&
          typeof ss.simUserClearedAt === 'object' &&
          !Array.isArray(ss.simUserClearedAt)
        ) {
          for (const [k, v] of Object.entries(ss.simUserClearedAt)) {
            if (typeof v === 'string' && v.trim()) {
              persistedClearedAt[k.trim().toUpperCase()] = v.trim();
            }
          }
        }
        simState = {
          users: Array.isArray(ss.users) && ss.users.length > 0 ? ss.users : simState.users,
          alerts: Array.isArray(ss.alerts) ? scrubAlerts(ss.alerts) : simState.alerts,
          fgaEvents: Array.isArray(ss.fgaEvents) ? scrubFgaEvents(ss.fgaEvents) : simState.fgaEvents,
          triggers: Array.isArray(ss.triggers) ? scrubTriggers(ss.triggers) : simState.triggers,
          auditLogs: Array.isArray(ss.auditLogs) ? scrubAuditLogs(ss.auditLogs) : simState.auditLogs,
          // Keep raw INITIAL_EMPLOYEES in simState memory if needed for trigger baseline comparisons
          employees: INITIAL_EMPLOYEES.map((e) => ({ ...e })),
          failedLogons: Array.isArray(ss.failedLogons) ? ss.failedLogons : [],
          defenseHealth: ss.defenseHealth,
          simUserClearedAt: persistedClearedAt,
        };
      }
    } catch {
      // Ignore corrupted state file
    }
  }

  function savePersistedState(): void {
    try {
      liveState.alerts = scrubAlerts(liveState.alerts);
      liveState.fgaEvents = scrubFgaEvents(liveState.fgaEvents);
      liveState.triggers = scrubTriggers(liveState.triggers);
      liveState.auditLogs = scrubAuditLogs(liveState.auditLogs);

      simState.alerts = scrubAlerts(simState.alerts);
      simState.fgaEvents = scrubFgaEvents(simState.fgaEvents);
      simState.triggers = scrubTriggers(simState.triggers);
      simState.auditLogs = scrubAuditLogs(simState.auditLogs);

      const payload = {
        version: 2,
        updatedAt: new Date().toISOString(),
        activeMode,
        autoResponse,
        lastOracleSyncAt,
        auditClearedAt,
        fgaClearedAt,
        pendingCommands,
        liveState: scrubStateForPersistence(liveState),
        simState: scrubStateForPersistence(simState),
        reviewedAlertKeys: Array.from(reviewedAlertKeys).slice(-300),
        reviewedFgaKeys: Array.from(reviewedFgaKeys).slice(-300),
        reviewedTriggerIds: Array.from(reviewedTriggerIds).slice(-300),
        reviewedAuditKeys: Array.from(reviewedAuditKeys).slice(-300),
      };

      writeFileAtomic(stateFile, JSON.stringify(payload, null, 2));
    } catch {
      // Ignore disk persistence errors
    }
  }

  loadPersistedState();

  function isBridgeConnected(): boolean {
    return (
      Boolean(lastOracleSyncAt) &&
      Date.now() - new Date(lastOracleSyncAt as string).getTime() < 20000
    );
  }

  function applyIncomingOracleTelemetry(bData: Record<string, unknown>): void {
    lastOracleSyncAt = new Date().toISOString();

    const unackedUserActionUsers = new Set(
      pendingCommands
        .filter((cmd) => cmd.type === 'user_action' && typeof cmd.payload?.username === 'string')
        .map((cmd) => String(cmd.payload.username).trim().toUpperCase())
    );

    if (Array.isArray(bData.users)) {
      const existingByUsername = new Map(
        liveState.users.map((u) => [u.USERNAME.toUpperCase(), u])
      );
      liveState.users = (bData.users as DbUser[]).map((incomingUser) => {
        const uname = String(incomingUser.USERNAME || '').toUpperCase();
        if (unackedUserActionUsers.has(uname) && existingByUsername.has(uname)) {
          return existingByUsername.get(uname)!;
        }
        return incomingUser;
      });
    }

    if (Array.isArray(bData.alerts)) {
      liveState.alerts = (bData.alerts as AlertItem[]).map((a) => ({
        ...a,
        details: sanitizeSqlCredentials(a.details || ''),
        reviewed: reviewedAlertKeys.has(a.key) || Boolean(a.reviewed),
      }));
    }

    if (Array.isArray(bData.fga_events)) {
      liveState.fgaEvents = (bData.fga_events as FgaEvent[])
        .filter((f) => {
          if (!fgaClearedAt || !f.EVENT_TIMESTAMP) return true;
          return f.EVENT_TIMESTAMP > fgaClearedAt;
        })
        .map((f) => ({
          ...f,
          SQL_TEXT: sanitizeSqlCredentials(f.SQL_TEXT || ''),
          reviewed: reviewedFgaKeys.has(getFgaKey(f)) || Boolean(f.reviewed),
        }));
    }

    if (Array.isArray(bData.triggers)) {
      liveState.triggers = (bData.triggers as TriggerAlert[]).map((t) => ({
        ...t,
        DETAILS: sanitizeSqlCredentials(t.DETAILS || ''),
        reviewed: reviewedTriggerIds.has(Number(t.ALERT_ID)) || Boolean(t.reviewed),
      }));
    }

    if (Array.isArray(bData.audit_logs)) {
      liveState.auditLogs = (bData.audit_logs as AuditLogRow[])
        .filter((r) => {
          if (!auditClearedAt || !r.EVENT_TIMESTAMP) return true;
          return r.EVENT_TIMESTAMP > auditClearedAt;
        })
        .map((r) => ({
          ...r,
          SQL_TEXT: sanitizeSqlCredentials(r.SQL_TEXT || ''),
          reviewed: reviewedAuditKeys.has(getAuditKey(r)) || Boolean(r.reviewed),
        }));
    }

    if (Array.isArray(bData.employees)) {
      liveState.employees = bData.employees as Employee[];
    }

    if (Array.isArray(bData.failed_logons)) {
      liveState.failedLogons = bData.failed_logons as FailedLogon[];
    }

    if (bData.defense_health && typeof bData.defense_health === 'object') {
      liveState.defenseHealth = bData.defense_health as DefenseHealth;
    }

    savePersistedState();
  }

  async function forwardToOracleBridge(
    endpoint: string,
    payload: Record<string, unknown>
  ): Promise<BridgeForwardResult> {
    if (!bridgeUrl) {
      return { ok: false, networkError: true, error: 'Oracle bridge URL is not configured' };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const resp = await fetch(`${bridgeUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Bridge-Token': bridgeToken,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (resp.ok) {
        return { ok: true, status: resp.status };
      }

      let errMsg = `Bridge HTTP ${resp.status}`;
      try {
        const text = await resp.text();
        if (text) {
          const parsed = JSON.parse(text) as Record<string, unknown>;
          if (typeof parsed.error === 'string' && parsed.error.trim()) {
            errMsg = parsed.error.trim();
          } else if (typeof parsed.message === 'string' && parsed.message.trim()) {
            errMsg = parsed.message.trim();
          }
        }
      } catch {
        // Non-JSON error body from bridge
      }

      const isClientRejection = resp.status >= 400 && resp.status < 500;
      return {
        ok: false,
        status: resp.status,
        error: errMsg,
        networkError: !isClientRejection,
      };
    } catch (err) {
      return {
        ok: false,
        networkError: true,
        error: err instanceof Error ? err.message : 'Bridge connection failed',
      };
    } finally {
      clearTimeout(timer);
    }
  }

  function sendBridgeRejection(res: express.Response, bridgeResult: BridgeForwardResult): void {
    const statusCode = bridgeResult.status === 401 ? 502 : 400;
    res.status(statusCode).json({
      ok: false,
      error: bridgeResult.error || 'Bridge rejected command',
    });
  }

  function getActiveSession(req: express.Request): {
    sessionId: string;
    session: SessionRecord;
  } | null {
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies.soc_session;
    if (!sid) return null;
    const rec = sessions.get(sid);
    if (!rec) return null;
    if (rec.expiresAt <= Date.now()) {
      sessions.delete(sid);
      return null;
    }
    return { sessionId: sid, session: rec };
  }

  function requireSocAuth(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): void {
    const authHeader = req.headers.authorization;
    if (typeof authHeader === 'string' && /^bearer\s+/i.test(authHeader)) {
      const providedBearer = authHeader.replace(/^bearer\s+/i, '').trim();
      if (safeTokenEquals(providedBearer, socAdminToken)) {
        next();
        return;
      }
      res.status(401).json({ ok: false, error: 'Invalid Bearer token' });
      return;
    }

    const activeSess = getActiveSession(req);
    if (!activeSess) {
      res.status(401).json({ ok: false, error: 'Authentication required' });
      return;
    }

    if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
      const csrfHeader = req.header('X-CSRF-Token');
      if (!safeTokenEquals(csrfHeader, activeSess.session.csrfToken)) {
        res.status(403).json({ ok: false, error: 'CSRF token missing or invalid' });
        return;
      }
    }

    next();
  }

  function requireBridgeAuth(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): void {
    const provided = req.header('X-Bridge-Token');
    if (!safeTokenEquals(provided, bridgeToken)) {
      res.status(401).json({ ok: false, error: 'Invalid or missing X-Bridge-Token' });
      return;
    }
    next();
  }

  const app = express();
  app.disable('x-powered-by');

  // Strict Origin-allowlist CORS middleware (never emits Access-Control-Allow-Origin: *)
  app.use((req, res, next) => {
    res.setHeader('Vary', 'Origin');
    const origin = req.headers.origin;
    if (typeof origin === 'string' && origin.length > 0) {
      if (!allowedOriginSet.has(origin)) {
        if (req.method === 'OPTIONS' || req.path.startsWith('/api/')) {
          res.status(403).json({ ok: false, error: 'Origin not allowed by CORS policy' });
          return;
        }
      } else {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader(
          'Access-Control-Allow-Headers',
          'Content-Type, Authorization, X-CSRF-Token, X-Bridge-Token'
        );
      }
    }

    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  app.use(express.json({ limit: '5mb' }));

  // Public health endpoint (non-sensitive operational status only)
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      status: 'healthy',
      timestamp: getUtcTimestamp(),
      active_mode: activeMode,
      oracle_bridge_connected: isBridgeConnected(),
    });
  });

  // Public auth status check
  app.get('/api/auth/status', (req, res) => {
    const authHeader = req.headers.authorization;
    if (typeof authHeader === 'string' && /^bearer\s+/i.test(authHeader)) {
      const providedBearer = authHeader.replace(/^bearer\s+/i, '').trim();
      if (safeTokenEquals(providedBearer, socAdminToken)) {
        const activeSess = getActiveSession(req);
        res.json({
          authenticated: true,
          ...(activeSess ? { csrfToken: activeSess.session.csrfToken } : {}),
        });
        return;
      }
    }

    const activeSess = getActiveSession(req);
    if (activeSess) {
      res.json({ authenticated: true, csrfToken: activeSess.session.csrfToken });
      return;
    }

    res.json({ authenticated: false });
  });

  // Public login endpoint creating HttpOnly SameSite=Strict cookie + CSRF token
  app.post('/api/auth/session', requireJsonContentType, (req, res) => {
    const providedToken = typeof req.body?.token === 'string' ? req.body.token : '';
    if (!safeTokenEquals(providedToken, socAdminToken)) {
      res.status(401).json({ ok: false, error: 'Invalid SOC operator token' });
      return;
    }

    const sessionId = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(24).toString('hex');
    const now = Date.now();
    pruneSessions(now, true);
    sessions.set(sessionId, {
      csrfToken,
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS,
    });

    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    const cookieParts = [
      `soc_session=${sessionId}`,
      'HttpOnly',
      'SameSite=Strict',
      'Path=/',
      `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    ];
    if (isSecure) cookieParts.push('Secure');

    res.setHeader('Set-Cookie', cookieParts.join('; '));
    res.json({ ok: true, csrfToken });
  });

  // Public logout endpoint
  app.post('/api/auth/logout', (req, res) => {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.soc_session) {
      sessions.delete(cookies.soc_session);
    }
    res.setHeader(
      'Set-Cookie',
      'soc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
    );
    res.json({ ok: true });
  });

  // Bridge-to-Server telemetry sync (requires X-Bridge-Token)
  app.post('/api/oracle-sync', requireBridgeAuth, requireJsonContentType, (req, res) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<
      string,
      unknown
    >;

    if (Array.isArray(body.ack_command_ids)) {
      const ackSet = new Set(body.ack_command_ids.map(String));
      pendingCommands = pendingCommands.filter((cmd) => !ackSet.has(cmd.id));
    }

    applyIncomingOracleTelemetry(body);

    res.json({
      ok: true,
      received_at: lastOracleSyncAt,
      auto_response: autoResponse,
      pending_commands: [...pendingCommands],
    });
  });

  // Protected: Download authenticated oracle/bridge.py script
  app.get('/api/oracle-bridge.py', requireSocAuth, (_req, res) => {
    const bridgePath = path.resolve(repoRoot, 'oracle', 'bridge.py');
    if (!fs.existsSync(bridgePath)) {
      res.status(404).json({ ok: false, error: 'oracle/bridge.py not found' });
      return;
    }
    res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="oracle_bridge.py"');
    res.send(fs.readFileSync(bridgePath, 'utf-8'));
  });

  // Protected: Download standalone Oracle Bridge deployment bundle (ZIP)
  app.get('/api/oracle-bridge-bundle.zip', requireSocAuth, (_req, res) => {
    const entries: Array<{ name: string; data: Buffer; mtime?: Date }> = [];
    for (const relPath of ORACLE_BRIDGE_BUNDLE_FILES) {
      const absPath = path.resolve(repoRoot, relPath);
      if (!fs.existsSync(absPath)) {
        res.status(404).json({ ok: false, error: `Missing bundle file: ${relPath}` });
        return;
      }
      const stat = fs.statSync(absPath);
      entries.push({
        name: relPath,
        data: fs.readFileSync(absPath),
        mtime: stat.mtime,
      });
    }

    const zipBuffer = buildZipBuffer(entries);
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="oracle_bridge_bundle.zip"');
    res.setHeader('Cache-Control', 'no-store');
    res.send(zipBuffer);
  });

  // Protected: Fetch dashboard state for activeMode ('oracle_live' or 'simulation')
  app.get('/api/data', requireSocAuth, async (req, res) => {
    if (req.query.flush === '1' && bridgeUrl) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        const bridgeRes = await fetch(`${bridgeUrl}/api/data?flush=1`, {
          headers: { 'X-Bridge-Token': bridgeToken },
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (bridgeRes.ok) {
          const bData = (await bridgeRes.json()) as Record<string, unknown>;
          if (bData && bData.ok) {
            applyIncomingOracleTelemetry(bData);
          }
        }
      } catch {
        // Bridge unreachable; serve current state
      }
    }

    const activeState = getActiveState();
    const connected = isBridgeConnected();
    const dataSource: DataSourceMode =
      activeMode === 'simulation' ? 'simulation' : connected ? 'oracle_live' : 'disconnected';

    const includePii = req.query.include_pii === '1';
    const projectedEmployees = includePii
      ? activeState.employees
      : maskEmployeesCmnd(activeState.employees);

    const metrics = calculateSystemMetrics(
      activeState.auditLogs.length,
      activeState.alerts.length,
      activeState.triggers.length,
      activeState.fgaEvents.length,
      activeState.users
    );

    res.json({
      ok: true,
      timestamp: getUtcTimestamp(),
      dsn: oracleDsn,
      oracle_bridge_connected: connected,
      last_oracle_sync: lastOracleSyncAt,
      data_source: dataSource,
      active_mode: activeMode,
      auto_response: autoResponse,
      defense_health: activeState.defenseHealth,
      metrics,
      users: activeState.users,
      alerts: activeState.alerts,
      fga_events: activeState.fgaEvents,
      triggers: activeState.triggers,
      audit_logs: activeState.auditLogs,
      failed_logons: activeState.failedLogons,
      employees: projectedEmployees,
    });
  });

  // Protected: Switch activeMode between 'oracle_live' and 'simulation'
  app.post('/api/mode', requireSocAuth, requireJsonContentType, (req, res) => {
    const requestedMode = req.body?.mode;
    if (requestedMode !== 'oracle_live' && requestedMode !== 'simulation') {
      res.status(400).json({
        ok: false,
        error: "Invalid mode; expected 'oracle_live' or 'simulation'",
      });
      return;
    }

    activeMode = requestedMode;
    savePersistedState();
    res.json({ ok: true, active_mode: activeMode });
  });

  // Protected: Persist review flags across reloads
  app.post('/api/review-state', requireSocAuth, requireJsonContentType, (req, res) => {
    const {
      reviewed_alert_keys,
      reviewed_fga_keys,
      reviewed_trigger_ids,
      reviewed_audit_keys,
    } = req.body || {};

    const applyReviewFlags = (state: TelemetryState) => {
      if (Array.isArray(reviewed_alert_keys)) {
        state.alerts = state.alerts.map((a) => ({
          ...a,
          reviewed: reviewedAlertKeys.has(a.key),
        }));
      }
      if (Array.isArray(reviewed_fga_keys)) {
        state.fgaEvents = state.fgaEvents.map((f) => ({
          ...f,
          reviewed: reviewedFgaKeys.has(getFgaKey(f)),
        }));
      }
      if (Array.isArray(reviewed_trigger_ids)) {
        state.triggers = state.triggers.map((t) => ({
          ...t,
          reviewed: reviewedTriggerIds.has(Number(t.ALERT_ID)),
        }));
      }
      if (Array.isArray(reviewed_audit_keys)) {
        state.auditLogs = state.auditLogs.map((r) => ({
          ...r,
          reviewed: reviewedAuditKeys.has(getAuditKey(r)),
        }));
      }
    };

    if (Array.isArray(reviewed_alert_keys)) {
      reviewedAlertKeys = new Set(reviewed_alert_keys.map(String));
    }
    if (Array.isArray(reviewed_fga_keys)) {
      reviewedFgaKeys = new Set(reviewed_fga_keys.map(String));
    }
    if (Array.isArray(reviewed_trigger_ids)) {
      reviewedTriggerIds = new Set(reviewed_trigger_ids.map(Number));
    }
    if (Array.isArray(reviewed_audit_keys)) {
      reviewedAuditKeys = new Set(reviewed_audit_keys.map(String));
    }

    applyReviewFlags(liveState);
    applyReviewFlags(simState);
    savePersistedState();
    res.json({ ok: true });
  });

  // Protected: Execute SQL batch in simulation workspace (NEVER mutates liveState or lastOracleSyncAt)
  app.post('/api/execute-oracle-sql', requireSocAuth, requireJsonContentType, (req, res) => {
    const body =
      req.body && typeof req.body === 'object' && !Array.isArray(req.body)
        ? (req.body as Record<string, unknown>)
        : null;
    if (!body) {
      res.status(400).json({ ok: false, error: 'Request body must be a JSON object' });
      return;
    }

    const {
      sql,
      dbUser = 'U1',
      host: customHost = 'LAPTOP-R03ORTGV',
      osUser = 'pc',
      client = 'SQL Developer',
    } = body;

    if (!sql || typeof sql !== 'string' || !sql.trim()) {
      res.status(400).json({ ok: false, error: 'Câu lệnh SQL trống!', message: 'Câu lệnh SQL trống!' });
      return;
    }

    if (typeof dbUser !== 'string' || dbUser.length > 256) {
      res.status(400).json({ ok: false, error: 'Invalid dbUser: expected string up to 256 characters' });
      return;
    }
    if (typeof customHost !== 'string' || customHost.length > 256) {
      res.status(400).json({ ok: false, error: 'Invalid host: expected string up to 256 characters' });
      return;
    }
    if (typeof osUser !== 'string' || osUser.length > 256) {
      res.status(400).json({ ok: false, error: 'Invalid osUser: expected string up to 256 characters' });
      return;
    }
    if (typeof client !== 'string' || client.length > 256) {
      res.status(400).json({ ok: false, error: 'Invalid client: expected string up to 256 characters' });
      return;
    }

    const outcome = evaluateOracleSqlBatch(
      sql,
      dbUser,
      simState.users,
      simState.alerts,
      simState.triggers,
      autoResponse,
      customHost,
      osUser,
      client,
      simState.employees,
      simState.simUserClearedAt || {}
    );

    simState.alerts = scrubAlerts([...outcome.newAlerts, ...simState.alerts]);
    simState.triggers = scrubTriggers([...outcome.newTriggers, ...simState.triggers]);
    simState.fgaEvents = scrubFgaEvents([...outcome.newFgaEvents, ...simState.fgaEvents]);
    simState.auditLogs = scrubAuditLogs([...outcome.newAuditLogs, ...simState.auditLogs]);
    simState.users = outcome.updatedUsers;
    activeMode = 'simulation';

    savePersistedState();

    res.json({
      ok: true,
      active_mode: activeMode,
      message:
        outcome.oracleOutputs[0] ||
        `Đã tiếp nhận và phân tích ${outcome.newAuditLogs.length} câu lệnh từ Oracle (${dbUser})!`,
      outputs: outcome.oracleOutputs,
      new_alerts_count: outcome.newAlerts.length,
      new_triggers_count: outcome.newTriggers.length,
    });
  });

  // Protected: Lock, Unlock, Revoke DML, Grant DML
  app.post('/api/user-action', requireSocAuth, requireJsonContentType, async (req, res) => {
    const body =
      req.body && typeof req.body === 'object' && !Array.isArray(req.body)
        ? (req.body as Record<string, unknown>)
        : null;
    if (!body) {
      res.status(400).json({ ok: false, error: 'Request body must be a JSON object' });
      return;
    }

    const rawUsername = typeof body.username === 'string' ? body.username.trim().toUpperCase() : '';
    const action = typeof body.action === 'string' ? body.action.trim() : '';

    if (!ORACLE_IDENTIFIER_RE.test(rawUsername) || !VALID_USER_ACTIONS.has(action)) {
      res.status(400).json({ ok: false, error: 'Invalid username or action' });
      return;
    }
    if (PROTECTED_ACCOUNTS.has(rawUsername)) {
      res.status(400).json({
        ok: false,
        error: `Cannot perform action on protected Oracle account ${rawUsername}`,
      });
      return;
    }

    const nowStr = getUtcTimestamp();
    const activeState = getActiveState();

    if (activeMode === 'oracle_live') {
      const bridgeResult = await forwardToOracleBridge('/api/user-action', {
        username: rawUsername,
        action,
      });
      if (!bridgeResult.ok && !bridgeResult.networkError) {
        sendBridgeRejection(res, bridgeResult);
        return;
      }
      if (!bridgeResult.ok && bridgeResult.networkError) {
        enqueuePendingCommand({
          id: crypto.randomUUID(),
          type: 'user_action',
          payload: { username: rawUsername, action },
          createdAt: nowStr,
        });
      }
    }

    activeState.users = activeState.users.map((u) => {
      if (u.USERNAME.toUpperCase() !== rawUsername) return u;
      if (action === 'lock') {
        return {
          ...u,
          ACCOUNT_STATUS: 'LOCKED',
          LOCK_DATE: nowStr,
          RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 3),
          RESPONSE_LABEL: policy.thresholds.level_3.label,
        };
      }
      if (action === 'unlock') {
        return {
          ...u,
          ACCOUNT_STATUS: 'OPEN',
          RISK_SCORE: 0,
          RESPONSE_LEVEL: 0,
          RESPONSE_LABEL: policy.thresholds.level_0.label,
          LOCK_DATE: undefined,
        };
      }
      if (action === 'revoke_dml') {
        return {
          ...u,
          DML_STATUS: 'READ-ONLY',
          PRIVILEGES: 'SELECT',
          RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 2),
          RESPONSE_LABEL: policy.thresholds.level_2.label,
        };
      }
      // grant_dml
      return {
        ...u,
        DML_STATUS: 'FULL DML',
        PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
        RISK_SCORE: 0,
        RESPONSE_LEVEL: 0,
        RESPONSE_LABEL: policy.thresholds.level_0.label,
      };
    });

    if (activeMode === 'simulation' && (action === 'unlock' || action === 'grant_dml')) {
      const maxAlertTime = simState.alerts
        .filter((a) => a.user.toUpperCase() === rawUsername && typeof a.time === 'string')
        .reduce((maxT, a) => (a.time > maxT ? a.time : maxT), nowStr);
      simState.simUserClearedAt = {
        ...(simState.simUserClearedAt || {}),
        [rawUsername]: maxAlertTime > nowStr ? maxAlertTime : nowStr,
      };
    }

    savePersistedState();
    res.json({ ok: true, users: activeState.users });
  });

  // Protected: Clear reviewed, single, or scoped alerts/events
  app.post('/api/clear-alerts', requireSocAuth, requireJsonContentType, async (req, res) => {
    const body =
      req.body && typeof req.body === 'object' && !Array.isArray(req.body)
        ? (req.body as Record<string, unknown>)
        : null;
    if (!body) {
      res.status(400).json({ ok: false, error: 'Request body must be a JSON object' });
      return;
    }

    const rawTarget = body.target === undefined ? 'all' : body.target;
    if (typeof rawTarget !== 'string' || !VALID_CLEAR_TARGETS.has(rawTarget)) {
      res.status(400).json({ ok: false, error: 'Invalid clear-alerts target' });
      return;
    }
    const target = rawTarget;

    let nowStr: string;
    if (body.cutoff !== undefined) {
      const normalized = normalizeCutoffTimestamp(body.cutoff);
      if (!normalized) {
        res.status(400).json({
          ok: false,
          error: 'Invalid cutoff timestamp; expected YYYY-MM-DD HH:MM:SS or ISO-8601 UTC',
        });
        return;
      }
      nowStr = normalized;
    } else {
      nowStr = getUtcTimestamp();
    }

    const {
      alert_key,
      alert_id,
      fga_key,
      audit_key,
      reviewed_keys,
      reviewed_fga_keys,
      reviewed_trigger_ids,
      reviewed_audit_keys,
    } = body;

    const bridgePayload: Record<string, unknown> = {
      target,
      alert_key,
      alert_id,
      fga_key,
      audit_key,
      reviewed_keys,
      reviewed_fga_keys,
      reviewed_trigger_ids,
      reviewed_audit_keys,
      cutoff: nowStr,
    };

    if (activeMode === 'oracle_live') {
      const bridgeResult = await forwardToOracleBridge('/api/clear-alerts', bridgePayload);
      if (!bridgeResult.ok && !bridgeResult.networkError) {
        sendBridgeRejection(res, bridgeResult);
        return;
      }
      if (!bridgeResult.ok && bridgeResult.networkError) {
        enqueuePendingCommand({
          id: crypto.randomUUID(),
          type: 'clear_alerts',
          payload: bridgePayload,
          createdAt: new Date().toISOString(),
        });
      }
    }

    const activeState = getActiveState();
    const applyContainmentOnPartialReset = activeMode === 'oracle_live' ? false : autoResponse;

    if (target === 'single_ids' && alert_key) {
      activeState.alerts = activeState.alerts.filter((a) => a.key !== String(alert_key));
      reviewedAlertKeys.delete(String(alert_key));
      activeState.users = recalculateUsersAfterReset(
        activeState.users,
        activeState.alerts,
        applyContainmentOnPartialReset
      );
    } else if (target === 'single_trigger' && alert_id !== undefined) {
      activeState.triggers = activeState.triggers.filter(
        (t) => Number(t.ALERT_ID) !== Number(alert_id)
      );
      reviewedTriggerIds.delete(Number(alert_id));
    } else if (target === 'single_fga') {
      const targetKey =
        fga_key ||
        (Array.isArray(reviewed_fga_keys) && reviewed_fga_keys.length > 0
          ? reviewed_fga_keys[0]
          : undefined);
      if (targetKey) {
        const keyStr = String(targetKey);
        activeState.fgaEvents = activeState.fgaEvents.filter((f) => getFgaKey(f) !== keyStr);
        reviewedFgaKeys.delete(keyStr);
      }
    } else if (target === 'single_audit') {
      const targetKey =
        audit_key ||
        (Array.isArray(reviewed_audit_keys) && reviewed_audit_keys.length > 0
          ? reviewed_audit_keys[0]
          : undefined);
      if (targetKey) {
        const keyStr = String(targetKey);
        activeState.auditLogs = activeState.auditLogs.filter((r) => getAuditKey(r) !== keyStr);
        reviewedAuditKeys.delete(keyStr);
      }
    } else if (target === 'reviewed') {
      const hasAlerts = Array.isArray(reviewed_keys) && reviewed_keys.length > 0;
      const hasFga = Array.isArray(reviewed_fga_keys) && reviewed_fga_keys.length > 0;
      const hasTriggers =
        Array.isArray(reviewed_trigger_ids) && reviewed_trigger_ids.length > 0;
      const hasAudit = Array.isArray(reviewed_audit_keys) && reviewed_audit_keys.length > 0;

      if (hasAlerts) {
        const keySet = new Set(reviewed_keys.map(String));
        activeState.alerts = activeState.alerts.filter((a) => !keySet.has(a.key));
        keySet.forEach((k) => reviewedAlertKeys.delete(k));
        activeState.users = recalculateUsersAfterReset(
          activeState.users,
          activeState.alerts,
          applyContainmentOnPartialReset
        );
      }
      if (hasFga) {
        const fgaSet = new Set(reviewed_fga_keys.map(String));
        activeState.fgaEvents = activeState.fgaEvents.filter(
          (f) => !fgaSet.has(getFgaKey(f))
        );
        fgaSet.forEach((k) => reviewedFgaKeys.delete(k));
      }
      if (hasTriggers) {
        const trigSet = new Set(reviewed_trigger_ids.map(Number));
        activeState.triggers = activeState.triggers.filter(
          (t) => !trigSet.has(Number(t.ALERT_ID))
        );
        trigSet.forEach((id) => reviewedTriggerIds.delete(id));
      }
      if (hasAudit) {
        const audSet = new Set(reviewed_audit_keys.map(String));
        activeState.auditLogs = activeState.auditLogs.filter(
          (r) => !audSet.has(getAuditKey(r))
        );
        audSet.forEach((k) => reviewedAuditKeys.delete(k));
      }
    } else if (target === 'ids') {
      activeState.alerts = [];
      reviewedAlertKeys.clear();
      if (activeMode === 'simulation') {
        simState.simUserClearedAt = {};
      }
      activeState.users = recalculateUsersAfterReset(activeState.users, [], autoResponse);
    } else if (target === 'fga') {
      activeState.fgaEvents = [];
      reviewedFgaKeys.clear();
      if (activeMode === 'oracle_live') {
        fgaClearedAt = nowStr;
      }
    } else if (target === 'triggers') {
      activeState.triggers = [];
      reviewedTriggerIds.clear();
    } else if (target === 'audit') {
      activeState.auditLogs = [];
      reviewedAuditKeys.clear();
      if (activeMode === 'oracle_live') {
        auditClearedAt = nowStr;
      }
    } else if (target === 'all') {
      activeState.alerts = [];
      activeState.triggers = [];
      activeState.fgaEvents = [];
      activeState.auditLogs = [];
      reviewedAlertKeys.clear();
      reviewedFgaKeys.clear();
      reviewedTriggerIds.clear();
      reviewedAuditKeys.clear();
      if (activeMode === 'oracle_live') {
        auditClearedAt = nowStr;
        fgaClearedAt = nowStr;
      } else {
        simState.simUserClearedAt = {};
      }
      activeState.users = recalculateUsersAfterReset(activeState.users, [], autoResponse);
    }

    savePersistedState();

    res.json({
      ok: true,
      alerts: activeState.alerts,
      triggers: activeState.triggers,
      fga_events: activeState.fgaEvents,
      audit_logs: activeState.auditLogs,
      users: activeState.users,
    });
  });

  // Protected: Toggle Active IPS auto-response
  app.post('/api/toggle-ips', requireSocAuth, requireJsonContentType, async (req, res) => {
    const body =
      req.body && typeof req.body === 'object' && !Array.isArray(req.body)
        ? (req.body as Record<string, unknown>)
        : null;
    if (!body) {
      res.status(400).json({ ok: false, error: 'Request body must be a JSON object' });
      return;
    }

    const nextAutoResponse = Boolean(body.auto_response ?? true);
    const bridgeResult = await forwardToOracleBridge('/api/toggle-ips', {
      auto_response: nextAutoResponse,
    });
    if (!bridgeResult.ok && !bridgeResult.networkError) {
      sendBridgeRejection(res, bridgeResult);
      return;
    }

    autoResponse = nextAutoResponse;
    if (!bridgeResult.ok && bridgeResult.networkError) {
      enqueuePendingCommand({
        id: crypto.randomUUID(),
        type: 'toggle_ips',
        payload: { auto_response: autoResponse },
        createdAt: new Date().toISOString(),
      });
    }

    savePersistedState();
    res.json({ ok: true, auto_response: autoResponse });
  });

  // JSON API 404 catch-all so unknown /api/* routes never fall through to SPA HTML
  app.use('/api', (_req, res) => {
    res.status(404).json({ ok: false, error: 'API route not found' });
  });

  // Explicit JSON body parse & payload limit error handler
  app.use(
    (
      err: unknown,
      _req: express.Request,
      res: express.Response,
      next: express.NextFunction
    ) => {
      if (
        err &&
        typeof err === 'object' &&
        'type' in err &&
        (err as { type?: string }).type === 'entity.too.large'
      ) {
        res.status(413).json({ ok: false, error: 'Payload Too Large' });
        return;
      }
      if (
        err instanceof SyntaxError ||
        (err &&
          typeof err === 'object' &&
          'type' in err &&
          (err as { type?: string }).type === 'entity.parse.failed')
      ) {
        res.status(400).json({ ok: false, error: 'Invalid JSON request body' });
        return;
      }
      next(err);
    }
  );

  const getRuntimeInfo = (): DashboardRuntimeInfo => ({
    port,
    host,
    stateFile,
    repoRoot,
    bridgeUrl,
    bridgeToken,
    socAdminToken,
    allowedOrigins: [...allowedOrigins],
    activeMode,
    bridgeManagedExternally,
  });

  return { app, getRuntimeInfo };
}

async function startServer(): Promise<void> {
  const { app, getRuntimeInfo } = createDashboardApp();
  const info = getRuntimeInfo();
  const bridgePort = Number(process.env.BRIDGE_PORT) || 8050;
  const bridgeHost = process.env.BRIDGE_HOST || '127.0.0.1';

  let bridgeSpawning = false;
  let bridgeChild: ChildProcess | null = null;
  let watcherTimer: ReturnType<typeof setInterval> | null = null;

  const ensureOracleBridgeDaemon = async () => {
    if (info.bridgeManagedExternally || bridgeSpawning || bridgeChild) return;
    const running = await isPortListening(bridgePort, bridgeHost);
    if (running) return;

    const bridgePath = path.resolve(info.repoRoot, 'oracle', 'bridge.py');
    if (!fs.existsSync(bridgePath)) return;

    bridgeSpawning = true;
    try {
      const child = spawn('python', [bridgePath], {
        cwd: path.dirname(bridgePath),
        env: {
          ...process.env,
          NO_BROWSER: '1',
          DASHBOARD_URL: `http://${info.host === '0.0.0.0' ? '127.0.0.1' : info.host}:${info.port}`,
          BRIDGE_API_TOKEN: info.bridgeToken,
        },
        stdio: 'ignore',
      });
      bridgeChild = child;
      child.once('exit', () => {
        if (bridgeChild === child) bridgeChild = null;
      });
      child.once('error', () => {
        if (bridgeChild === child) bridgeChild = null;
      });
      console.log(
        '[*] Đã tự động khởi chạy tiến trình cầu nối Oracle 23ai (oracle/bridge.py) ở chế độ ngầm.'
      );
    } catch {
      // Ignore spawn errors if python is unavailable
    } finally {
      setTimeout(() => {
        bridgeSpawning = false;
      }, 5000);
    }
  };

  if (!info.bridgeManagedExternally) {
    void ensureOracleBridgeDaemon();
    watcherTimer = setInterval(() => {
      void ensureOracleBridgeDaemon();
    }, 10000);
  } else {
    console.log('[*] BRIDGE_MANAGED_EXTERNALLY=1: Bỏ qua tự động spawn oracle/bridge.py.');
  }

  const httpServer = http.createServer(app);

  // Vite middleware for development vs static dist serving for production
  const isProduction =
    process.env.NODE_ENV === 'production' ||
    Boolean(process.env.K_SERVICE) ||
    process.env.npm_lifecycle_event === 'start';

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: { server: httpServer },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(
        `[ERROR] Port ${info.port} on ${info.host} is already in use. Please stop the conflicting process or change PORT in .env.`
      );
      process.exit(1);
    }
    console.error('[ERROR] Server failed to bind:', err);
    process.exit(1);
  });

  const shutdown = (signal: string) => {
    console.log(`\n[*] Received ${signal}, shutting down Oracle DB-IDS Server...`);
    if (watcherTimer) {
      clearInterval(watcherTimer);
      watcherTimer = null;
    }
    if (bridgeChild && !bridgeChild.killed) {
      try {
        bridgeChild.kill('SIGTERM');
      } catch {
        // Ignore child kill error
      }
      bridgeChild = null;
    }
    httpServer.close(() => {
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 2000).unref();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  httpServer.listen(info.port, info.host, () => {
    console.log(`Oracle DB-IDS Server running on http://${info.host}:${info.port}`);
    if (!process.env.SOC_ADMIN_TOKEN?.trim()) {
      console.log(`[SOC AUTH] Generated ephemeral SOC_ADMIN_TOKEN: ${info.socAdminToken}`);
    } else {
      console.log('[SOC AUTH] Using SOC_ADMIN_TOKEN configured from environment.');
    }
  });
}

const normalizePath = (p: string) =>
  process.platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p);

if (process.argv[1] && normalizePath(process.argv[1]) === normalizePath(__filename)) {
  startServer().catch((err) => {
    console.error('[FATAL] Failed to start Oracle DB-IDS Server:', err);
    process.exit(1);
  });
}
