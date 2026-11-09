import express from 'express';
import fs from 'fs';
import http from 'http';
import net from 'net';
import path from 'path';
import { spawn, execSync } from 'child_process';
import { fileURLToPath } from 'url';
import {
  INITIAL_ALERTS,
  INITIAL_AUDIT_LOGS,
  INITIAL_EMPLOYEES,
  INITIAL_FGA_EVENTS,
  INITIAL_TRIGGERS,
  INITIAL_USERS,
} from './src/data/initialData.ts';
import type {
  AlertItem,
  AuditLogRow,
  DbUser,
  Employee,
  FgaEvent,
  TriggerAlert,
} from './src/types/ids.ts';
import {
  calculateSystemMetrics,
  recalculateUsersAfterReset,
} from './src/utils/analytics.ts';
import { evaluateOracleSqlBatch } from './src/utils/oracleDetector.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STATE_FILE = path.join(__dirname, '.dashboard_state.json');
const BRIDGE_PORT = 8050;
const BRIDGE_URL = `http://127.0.0.1:${BRIDGE_PORT}`;

interface PendingOracleCommand {
  id: string;
  type: 'user_action' | 'clear_alerts' | 'toggle_ips';
  payload: Record<string, unknown>;
  createdAt: string;
}

// Server-authoritative state for live Oracle DB-IDS telemetry (persisted to .dashboard_state.json)
let users: DbUser[] = [...INITIAL_USERS];
let alerts: AlertItem[] = [...INITIAL_ALERTS];
let fgaEvents: FgaEvent[] = [...INITIAL_FGA_EVENTS];
let triggers: TriggerAlert[] = [...INITIAL_TRIGGERS];
let auditLogs: AuditLogRow[] = [...INITIAL_AUDIT_LOGS];
let employees: Employee[] = [...INITIAL_EMPLOYEES];
let autoResponse = true;
let lastOracleSyncAt: string | null = null;
let auditClearedAt: string | null = null;
let fgaClearedAt: string | null = null;
let pendingCommands: PendingOracleCommand[] = [];

// Persistent sets of reviewed items across page reloads
let reviewedAlertKeys = new Set<string>();
let reviewedFgaKeys = new Set<string>();
let reviewedTriggerIds = new Set<number>();
let reviewedAuditKeys = new Set<string>();

function getFgaKey(f: FgaEvent): string {
  return `${f.EVENT_TIMESTAMP}_${f.DBUSERNAME}_${f.FGA_POLICY_NAME}_${f.SQL_TEXT || ''}`;
}

function getAuditKey(r: AuditLogRow): string {
  return `${r.EVENT_TIMESTAMP}_${r.DBUSERNAME}_${r.ACTION_NAME}_${(r.SQL_TEXT || '').slice(0, 40)}`;
}

function loadPersistedDashboardState() {
  try {
    if (!fs.existsSync(STATE_FILE)) return;
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
    if (Array.isArray(raw.users) && raw.users.length > 0) users = raw.users;
    if (Array.isArray(raw.alerts)) alerts = raw.alerts.slice(0, 100);
    if (Array.isArray(raw.fgaEvents)) fgaEvents = raw.fgaEvents.slice(0, 50);
    if (Array.isArray(raw.triggers)) triggers = raw.triggers.slice(0, 50);
    if (Array.isArray(raw.auditLogs)) auditLogs = raw.auditLogs.slice(0, 100);
    if (Array.isArray(raw.employees) && raw.employees.length > 0) employees = raw.employees;
    if (typeof raw.autoResponse === 'boolean') autoResponse = raw.autoResponse;
    if (typeof raw.lastOracleSyncAt === 'string') lastOracleSyncAt = raw.lastOracleSyncAt;
    if (typeof raw.auditClearedAt === 'string') auditClearedAt = raw.auditClearedAt;
    if (typeof raw.fgaClearedAt === 'string') fgaClearedAt = raw.fgaClearedAt;
    if (Array.isArray(raw.reviewedAlertKeys)) reviewedAlertKeys = new Set(raw.reviewedAlertKeys);
    if (Array.isArray(raw.reviewedFgaKeys)) reviewedFgaKeys = new Set(raw.reviewedFgaKeys);
    if (Array.isArray(raw.reviewedTriggerIds)) reviewedTriggerIds = new Set(raw.reviewedTriggerIds.map(Number));
    if (Array.isArray(raw.reviewedAuditKeys)) reviewedAuditKeys = new Set(raw.reviewedAuditKeys);
  } catch {
    // Ignore corrupted state file
  }
}

function savePersistedDashboardState() {
  try {
    // Cap arrays in memory and on disk to prevent memory bloat
    alerts = alerts.slice(0, 100);
    fgaEvents = fgaEvents.slice(0, 50);
    triggers = triggers.slice(0, 50);
    auditLogs = auditLogs.slice(0, 100);

    const payload = {
      updatedAt: new Date().toISOString(),
      autoResponse,
      lastOracleSyncAt,
      auditClearedAt,
      fgaClearedAt,
      users,
      alerts,
      fgaEvents,
      triggers,
      auditLogs,
      employees,
      reviewedAlertKeys: Array.from(reviewedAlertKeys).slice(-300),
      reviewedFgaKeys: Array.from(reviewedFgaKeys).slice(-300),
      reviewedTriggerIds: Array.from(reviewedTriggerIds).slice(-300),
      reviewedAuditKeys: Array.from(reviewedAuditKeys).slice(-300),
    };
    fs.writeFileSync(STATE_FILE, JSON.stringify(payload, null, 2), 'utf-8');
  } catch {
    // Ignore write errors
  }
}

function isPortListening(port: number): Promise<boolean> {
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
    sock.connect(port, '127.0.0.1');
  });
}

let bridgeSpawning = false;
async function ensureOracleBridgeDaemon() {
  if (bridgeSpawning) return;
  const running = await isPortListening(BRIDGE_PORT);
  if (running) return;

  const bridgePath = path.resolve(__dirname, '..', 'oracle', 'bridge.py');
  if (!fs.existsSync(bridgePath)) return;

  bridgeSpawning = true;
  try {
    const child = spawn('python', [bridgePath], {
      cwd: path.dirname(bridgePath),
      env: { ...process.env, NO_BROWSER: '1', DASHBOARD_URL: 'http://localhost:3000' },
      stdio: 'ignore',
      detached: true,
    });
    child.unref();
    console.log('[*] Đã tự động khởi chạy tiến trình cầu nối Oracle 23ai (oracle/bridge.py) ở chế độ ngầm.');
  } catch {
    // Ignore spawn errors if python is unavailable
  } finally {
    setTimeout(() => {
      bridgeSpawning = false;
    }, 5000);
  }
}

async function forwardToOracleBridge(endpoint: string, payload: Record<string, unknown>): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const resp = await fetch(`${BRIDGE_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);
    return resp.ok;
  } catch {
    return false;
  }
}

loadPersistedDashboardState();

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  // Ensure Oracle bridge.py is running automatically and watch every 10s
  ensureOracleBridgeDaemon();
  setInterval(ensureOracleBridgeDaemon, 10000);

  app.use(express.json({ limit: '5mb' }));

  // Allow CORS so local Oracle Python agent or SQL Developer webhook can push directly
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  // 1. GET /api/data - Fetch live dashboard state
  app.get('/api/data', async (req, res) => {
    // If manual flush requested, pull fresh data directly from local bridge.py if available
    if (req.query.flush === '1') {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        const bridgeRes = await fetch(`${BRIDGE_URL}/api/data?flush=1`, { signal: controller.signal });
        clearTimeout(timer);
        if (bridgeRes.ok) {
          const bData = await bridgeRes.json();
          if (bData && bData.ok) {
            lastOracleSyncAt = new Date().toISOString();
            if (Array.isArray(bData.users) && bData.users.length > 0) users = bData.users;
            if (Array.isArray(bData.alerts)) {
              alerts = bData.alerts.map((a: AlertItem) => ({
                ...a,
                reviewed: reviewedAlertKeys.has(a.key) || !!a.reviewed,
              }));
            }
            if (Array.isArray(bData.fga_events)) {
              fgaEvents = bData.fga_events.map((f: FgaEvent) => ({
                ...f,
                reviewed: reviewedFgaKeys.has(getFgaKey(f)) || !!f.reviewed,
              }));
            }
            if (Array.isArray(bData.triggers)) {
              triggers = bData.triggers.map((t: TriggerAlert) => ({
                ...t,
                reviewed: reviewedTriggerIds.has(Number(t.ALERT_ID)) || !!t.reviewed,
              }));
            }
            if (Array.isArray(bData.audit_logs)) {
              auditLogs = bData.audit_logs.map((r: AuditLogRow) => ({
                ...r,
                reviewed: reviewedAuditKeys.has(getAuditKey(r)) || !!r.reviewed,
              }));
            }
            if (Array.isArray(bData.employees) && bData.employees.length > 0) {
              employees = bData.employees;
            }
            savePersistedDashboardState();
          }
        }
      } catch {
        // Ignore if bridge not ready
      }
    }

    const metrics = calculateSystemMetrics(
      auditLogs.length,
      alerts.length,
      triggers.length,
      fgaEvents.length,
      users
    );
    const isBridgeActive =
      !!lastOracleSyncAt &&
      Date.now() - new Date(lastOracleSyncAt).getTime() < 20000;

    res.json({
      ok: true,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      dsn: process.env.ORACLE_DSN || 'localhost:1521/FREEPDB1',
      oracle_bridge_connected: isBridgeActive,
      last_oracle_sync: lastOracleSyncAt,
      auto_response: autoResponse,
      metrics,
      users,
      alerts,
      fga_events: fgaEvents,
      triggers,
      audit_logs: auditLogs,
      employees,
    });
  });

  // 2. POST /api/oracle-sync - Receive real-time telemetry pushed from local Oracle 23ai Python Agent
  app.post('/api/oracle-sync', (req, res) => {
    const body = req.body || {};
    lastOracleSyncAt = new Date().toISOString();

    if (Array.isArray(body.users) && body.users.length > 0) {
      users = body.users;
    }
    if (Array.isArray(body.alerts)) {
      alerts = body.alerts.map((a: AlertItem) => ({
        ...a,
        reviewed: reviewedAlertKeys.has(a.key) || !!a.reviewed,
      }));
    }
    if (Array.isArray(body.fga_events)) {
      fgaEvents = body.fga_events.map((f: FgaEvent) => ({
        ...f,
        reviewed: reviewedFgaKeys.has(getFgaKey(f)) || !!f.reviewed,
      }));
    }
    if (Array.isArray(body.triggers)) {
      triggers = body.triggers.map((t: TriggerAlert) => ({
        ...t,
        reviewed: reviewedTriggerIds.has(Number(t.ALERT_ID)) || !!t.reviewed,
      }));
    }
    if (Array.isArray(body.audit_logs)) {
      auditLogs = body.audit_logs.map((r: AuditLogRow) => ({
        ...r,
        reviewed: reviewedAuditKeys.has(getAuditKey(r)) || !!r.reviewed,
      }));
    }
    if (Array.isArray(body.employees) && body.employees.length > 0) {
      employees = body.employees;
    }

    savePersistedDashboardState();

    const commandsToExecute = [...pendingCommands];
    pendingCommands = [];

    res.json({
      ok: true,
      received_at: lastOracleSyncAt,
      auto_response: autoResponse,
      pending_commands: commandsToExecute,
    });
  });

  // 2.5 POST /api/review-state - Persist review status across page reloads
  app.post('/api/review-state', (req, res) => {
    const {
      reviewed_alert_keys,
      reviewed_fga_keys,
      reviewed_trigger_ids,
      reviewed_audit_keys,
    } = req.body || {};

    if (Array.isArray(reviewed_alert_keys)) {
      reviewedAlertKeys = new Set(reviewed_alert_keys.map(String));
      alerts = alerts.map((a) => ({ ...a, reviewed: reviewedAlertKeys.has(a.key) }));
    }
    if (Array.isArray(reviewed_fga_keys)) {
      reviewedFgaKeys = new Set(reviewed_fga_keys.map(String));
      fgaEvents = fgaEvents.map((f) => ({ ...f, reviewed: reviewedFgaKeys.has(getFgaKey(f)) }));
    }
    if (Array.isArray(reviewed_trigger_ids)) {
      reviewedTriggerIds = new Set(reviewed_trigger_ids.map(Number));
      triggers = triggers.map((t) => ({ ...t, reviewed: reviewedTriggerIds.has(Number(t.ALERT_ID)) }));
    }
    if (Array.isArray(reviewed_audit_keys)) {
      reviewedAuditKeys = new Set(reviewed_audit_keys.map(String));
      auditLogs = auditLogs.map((r) => ({ ...r, reviewed: reviewedAuditKeys.has(getAuditKey(r)) }));
    }

    savePersistedDashboardState();
    res.json({ ok: true });
  });

  // 3. POST /api/execute-oracle-sql - Real-time SQL Stream / Listener from Oracle SQL Developer
  app.post('/api/execute-oracle-sql', (req, res) => {
    const { sql, dbUser = 'U1', host = 'LAPTOP-R03ORTGV', osUser = 'pc', client = 'SQL Developer' } =
      req.body || {};

    if (!sql || typeof sql !== 'string' || !sql.trim()) {
      res.status(400).json({ ok: false, message: 'Câu lệnh SQL trống!' });
      return;
    }

    const outcome = evaluateOracleSqlBatch(
      sql,
      String(dbUser),
      users,
      alerts,
      triggers,
      autoResponse,
      String(host),
      String(osUser),
      String(client)
    );

    alerts = [...outcome.newAlerts, ...alerts];
    triggers = [...outcome.newTriggers, ...triggers];
    fgaEvents = [...outcome.newFgaEvents, ...fgaEvents];
    auditLogs = [...outcome.newAuditLogs, ...auditLogs];
    users = outcome.updatedUsers;
    lastOracleSyncAt = new Date().toISOString();
    savePersistedDashboardState();

    res.json({
      ok: true,
      message:
        outcome.oracleOutputs[0] ||
        `Đã tiếp nhận và phân tích ${outcome.newAuditLogs.length} câu lệnh từ Oracle (${dbUser})!`,
      outputs: outcome.oracleOutputs,
      new_alerts_count: outcome.newAlerts.length,
      new_triggers_count: outcome.newTriggers.length,
    });
  });

  // 4. POST /api/user-action - Lock, Unlock, Revoke DML, Grant DML
  app.post('/api/user-action', async (req, res) => {
    const { username, action } = req.body || {};
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

    users = users.map((u) => {
      if (u.USERNAME !== username) return u;
      if (action === 'lock') {
        return {
          ...u,
          ACCOUNT_STATUS: 'LOCKED',
          LOCK_DATE: nowStr,
          RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 3),
          RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
        };
      } else if (action === 'unlock') {
        return {
          ...u,
          ACCOUNT_STATUS: 'OPEN',
          RISK_SCORE: 0,
          RESPONSE_LEVEL: 0,
          RESPONSE_LABEL: 'Level 0: Normal (An toàn)',
          LOCK_DATE: undefined,
        };
      } else if (action === 'revoke_dml') {
        return {
          ...u,
          DML_STATUS: 'READ-ONLY',
          PRIVILEGES: 'SELECT',
          RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 2),
          RESPONSE_LABEL: 'Level 2: HIGH (Privilege Containment)',
        };
      } else if (action === 'grant_dml') {
        return {
          ...u,
          DML_STATUS: 'FULL DML',
          PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
        };
      }
      return u;
    });

    savePersistedDashboardState();

    const forwarded = await forwardToOracleBridge('/api/user-action', { username, action });
    if (!forwarded) {
      pendingCommands.push({
        id: `${Date.now()}`,
        type: 'user_action',
        payload: { username, action },
        createdAt: nowStr,
      });
    }

    res.json({ ok: true, users });
  });

  // 5. POST /api/clear-alerts - Permanently delete reviewed or all alerts/events to free memory
  app.post('/api/clear-alerts', async (req, res) => {
    const {
      target = 'all',
      alert_key,
      alert_id,
      reviewed_keys,
      reviewed_fga_keys,
      reviewed_trigger_ids,
      reviewed_audit_keys,
      cutoff,
    } = req.body || {};
    const nowStr = cutoff || new Date().toISOString().replace('T', ' ').substring(0, 19);

    if (target === 'single_ids' && alert_key) {
      alerts = alerts.filter((a) => a.key !== alert_key);
      reviewedAlertKeys.delete(String(alert_key));
      users = recalculateUsersAfterReset(users, alerts);
    } else if (target === 'single_trigger' && alert_id !== undefined) {
      triggers = triggers.filter((t) => t.ALERT_ID !== Number(alert_id));
      reviewedTriggerIds.delete(Number(alert_id));
    } else if (target === 'reviewed') {
      const keySet = new Set(Array.isArray(reviewed_keys) ? reviewed_keys.map(String) : []);
      const fgaSet = new Set(Array.isArray(reviewed_fga_keys) ? reviewed_fga_keys.map(String) : []);
      const trigSet = new Set(Array.isArray(reviewed_trigger_ids) ? reviewed_trigger_ids.map(Number) : []);
      const audSet = new Set(Array.isArray(reviewed_audit_keys) ? reviewed_audit_keys.map(String) : []);

      alerts = alerts.filter((a) => !keySet.has(a.key) && !a.reviewed);
      fgaEvents = fgaEvents.filter((f) => !fgaSet.has(getFgaKey(f)) && !f.reviewed);
      triggers = triggers.filter((t) => !trigSet.has(Number(t.ALERT_ID)) && !t.reviewed);
      auditLogs = auditLogs.filter((r) => !audSet.has(getAuditKey(r)) && !r.reviewed);

      keySet.forEach((k) => reviewedAlertKeys.delete(k));
      fgaSet.forEach((k) => reviewedFgaKeys.delete(k));
      trigSet.forEach((id) => reviewedTriggerIds.delete(id));
      audSet.forEach((k) => reviewedAuditKeys.delete(k));

      users = recalculateUsersAfterReset(users, alerts);
    } else if (target === 'ids') {
      alerts = [];
      reviewedAlertKeys.clear();
      users = recalculateUsersAfterReset(users, []);
    } else if (target === 'fga') {
      fgaEvents = [];
      reviewedFgaKeys.clear();
      fgaClearedAt = nowStr;
    } else if (target === 'triggers') {
      triggers = [];
      reviewedTriggerIds.clear();
    } else if (target === 'audit') {
      auditLogs = [];
      reviewedAuditKeys.clear();
      auditClearedAt = nowStr;
    } else if (target === 'all') {
      alerts = [];
      triggers = [];
      fgaEvents = [];
      auditLogs = [];
      reviewedAlertKeys.clear();
      reviewedFgaKeys.clear();
      reviewedTriggerIds.clear();
      reviewedAuditKeys.clear();
      auditClearedAt = nowStr;
      fgaClearedAt = nowStr;
      users = recalculateUsersAfterReset(users, []);
    }

    savePersistedDashboardState();

    const bridgePayload = {
      target,
      alert_key,
      alert_id,
      reviewed_keys,
      reviewed_fga_keys,
      reviewed_trigger_ids,
      reviewed_audit_keys,
    };
    const forwarded = await forwardToOracleBridge('/api/clear-alerts', bridgePayload);
    if (!forwarded) {
      pendingCommands.push({
        id: `${Date.now()}`,
        type: 'clear_alerts',
        payload: bridgePayload,
        createdAt: new Date().toISOString(),
      });
    }

    res.json({ ok: true, alerts, triggers, fga_events: fgaEvents, audit_logs: auditLogs, users });
  });

  // 6. POST /api/toggle-ips
  app.post('/api/toggle-ips', async (req, res) => {
    autoResponse = Boolean(req.body?.auto_response ?? true);
    savePersistedDashboardState();

    const forwarded = await forwardToOracleBridge('/api/toggle-ips', { auto_response: autoResponse });
    if (!forwarded) {
      pendingCommands.push({
        id: `${Date.now()}`,
        type: 'toggle_ips',
        payload: { auto_response: autoResponse },
        createdAt: new Date().toISOString(),
      });
    }
    res.json({ ok: true, auto_response: autoResponse });
  });

  const httpServer = http.createServer(app);

  // Vite middleware for development vs static dist serving for Cloud Run production
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

  // Nếu cổng 3000 đang bị tiến trình node cũ chiếm giữ, tự động giải phóng trước khi listen
  if (await isPortListening(PORT)) {
    try {
      execSync(
        `powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort ${PORT} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | Where-Object { $_ -gt 0 -and $_ -ne ${process.pid} } | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"`,
        { stdio: 'ignore' }
      );
      await new Promise((r) => setTimeout(r, 600));
    } catch {
      // Ignore
    }
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Oracle DB-IDS Server running on http://localhost:${PORT}`);
  });
}

startServer();
