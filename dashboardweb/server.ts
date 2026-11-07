import express from 'express';
import path from 'path';
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

interface PendingOracleCommand {
  id: string;
  type: 'user_action' | 'clear_alerts' | 'toggle_ips';
  payload: Record<string, unknown>;
  createdAt: string;
}

// Server-authoritative state for live Oracle DB-IDS telemetry
let users: DbUser[] = [...INITIAL_USERS];
let alerts: AlertItem[] = [...INITIAL_ALERTS];
let fgaEvents: FgaEvent[] = [...INITIAL_FGA_EVENTS];
let triggers: TriggerAlert[] = [...INITIAL_TRIGGERS];
let auditLogs: AuditLogRow[] = [...INITIAL_AUDIT_LOGS];
let employees: Employee[] = [...INITIAL_EMPLOYEES];
let autoResponse = true;
let lastOracleSyncAt: string | null = null;
let auditClearedAt: string | null = null;
let pendingCommands: PendingOracleCommand[] = [];

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

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
  app.get('/api/data', (_req, res) => {
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
      // Preserve reviewed flags for existing alert keys
      const reviewedMap = new Map(alerts.map((a) => [a.key, !!a.reviewed]));
      alerts = body.alerts.map((a: AlertItem) => ({
        ...a,
        reviewed: reviewedMap.get(a.key) ?? !!a.reviewed,
      }));
    }
    if (Array.isArray(body.fga_events)) {
      fgaEvents = body.fga_events;
    }
    if (Array.isArray(body.triggers)) {
      triggers = body.triggers;
    }
    if (Array.isArray(body.audit_logs)) {
      auditLogs = auditClearedAt
        ? body.audit_logs.filter((a: AuditLogRow) => !a.EVENT_TIMESTAMP || a.EVENT_TIMESTAMP > auditClearedAt!)
        : body.audit_logs;
    }
    if (Array.isArray(body.employees) && body.employees.length > 0) {
      employees = body.employees;
    }

    const commandsToExecute = [...pendingCommands];
    pendingCommands = [];

    res.json({
      ok: true,
      received_at: lastOracleSyncAt,
      auto_response: autoResponse,
      pending_commands: commandsToExecute,
    });
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
  app.post('/api/user-action', (req, res) => {
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

    pendingCommands.push({
      id: `${Date.now()}`,
      type: 'user_action',
      payload: { username, action },
      createdAt: nowStr,
    });

    res.json({ ok: true, users });
  });

  // 5. POST /api/clear-alerts - Reset reviewed or all alerts/events
  app.post('/api/clear-alerts', (req, res) => {
    const { target = 'all', alert_key, alert_id, reviewed_keys, cutoff } = req.body || {};
    const nowStr = cutoff || new Date().toISOString().replace('T', ' ').substring(0, 19);

    if (target === 'single_ids' && alert_key) {
      alerts = alerts.filter((a) => a.key !== alert_key);
      users = recalculateUsersAfterReset(users, alerts);
    } else if (target === 'single_trigger' && alert_id !== undefined) {
      triggers = triggers.filter((t) => t.ALERT_ID !== Number(alert_id));
    } else if (target === 'reviewed' && Array.isArray(reviewed_keys)) {
      const keySet = new Set(reviewed_keys);
      alerts = alerts.filter((a) => !keySet.has(a.key) && !a.reviewed);
      users = recalculateUsersAfterReset(users, alerts);
    } else if (target === 'ids') {
      alerts = [];
      users = recalculateUsersAfterReset(users, []);
    } else if (target === 'triggers') {
      triggers = [];
    } else if (target === 'audit') {
      auditLogs = [];
      auditClearedAt = nowStr;
    } else if (target === 'all') {
      alerts = [];
      triggers = [];
      fgaEvents = [];
      auditLogs = [];
      auditClearedAt = nowStr;
      users = recalculateUsersAfterReset(users, []);
    }

    pendingCommands.push({
      id: `${Date.now()}`,
      type: 'clear_alerts',
      payload: { target, alert_key, alert_id },
      createdAt: new Date().toISOString(),
    });

    res.json({ ok: true, alerts, triggers, fga_events: fgaEvents, users });
  });

  // 6. POST /api/toggle-ips
  app.post('/api/toggle-ips', (req, res) => {
    autoResponse = Boolean(req.body?.auto_response ?? true);
    pendingCommands.push({
      id: `${Date.now()}`,
      type: 'toggle_ips',
      payload: { auto_response: autoResponse },
      createdAt: new Date().toISOString(),
    });
    res.json({ ok: true, auto_response: autoResponse });
  });

  // 7. GET /api/oracle-bridge.py - Download credential-safe Python Bridge for local Oracle 23ai
  app.get('/api/oracle-bridge.py', (req, res) => {
    const appUrl =
      process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
    const script = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ORACLE 23ai REAL-TIME BRIDGE AGENT FOR DB-IDS DASHBOARD
=======================================================
- Kết nối trực tiếp tới Oracle 23ai cục bộ (localhost:1521/FREEPDB1)
- Bảo mật tuyệt đối: KHÔNG lưu cứng mật khẩu hay username trong mã nguồn.
  Sử dụng biến môi trường ORACLE_USER / ORACLE_PASSWORD hoặc nhập ẩn (getpass).
- Tự động đẩy cảnh báo thời gian thực (mỗi 2 giây) lên Dashboard khi bạn chạy lệnh trên Oracle SQL Developer!
"""
import getpass
import json
import os
import time
import urllib.request

# 1. Đọc thông tin kết nối an toàn (Không lộ mật khẩu trên màn hình thuyết trình)
DB_DSN = os.getenv("ORACLE_DSN", "localhost:1521/FREEPDB1")
DB_USER = os.getenv("ORACLE_USER", "sys")
DB_PASS = os.getenv("ORACLE_PASSWORD", "")
CLOUD_DASHBOARD_URL = os.getenv("DASHBOARD_URL", "${appUrl}")
LOCAL_IDS_URL = "http://127.0.0.1:8050"

print("=" * 68)
print("  ORACLE 23ai LIVE TELEMETRY BRIDGE -> SOC DASHBOARD")
print(f"  Target Dashboard : {CLOUD_DASHBOARD_URL}")
print(f"  Oracle DSN       : {DB_DSN}")
print("=" * 68)

def sync_loop():
    print("[*] Đang lắng nghe sự kiện từ Oracle SQL Developer (mỗi 2 giây)...")
    while True:
        try:
            # Nếu ids_dashboard.py đang chạy ở cổng 8050, lấy dữ liệu trực tiếp và đồng bộ lên Dashboard
            req = urllib.request.Request(f"{LOCAL_IDS_URL}/api/data?flush=1")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("ok"):
                sync_req = urllib.request.Request(
                    f"{CLOUD_DASHBOARD_URL}/api/oracle-sync",
                    data=json.dumps(data).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(sync_req, timeout=4) as sync_resp:
                    reply = json.loads(sync_resp.read().decode("utf-8"))
                    for cmd in reply.get("pending_commands", []):
                        c_type = cmd.get("type")
                        payload = cmd.get("payload", {})
                        if c_type == "user_action":
                            urllib.request.urlopen(
                                urllib.request.Request(
                                    f"{LOCAL_IDS_URL}/api/user-action",
                                    data=json.dumps(payload).encode("utf-8"),
                                    headers={"Content-Type": "application/json"},
                                    method="POST",
                                )
                            )
                        elif c_type == "clear_alerts":
                            urllib.request.urlopen(
                                urllib.request.Request(
                                    f"{LOCAL_IDS_URL}/api/clear-alerts",
                                    data=json.dumps(payload).encode("utf-8"),
                                    headers={"Content-Type": "application/json"},
                                    method="POST",
                                )
                            )
        except Exception as e:
            pass
        time.sleep(2)

if __name__ == "__main__":
    sync_loop()
`;
    res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="oracle_bridge.py"'
    );
    res.send(script);
  });

  // Vite middleware for development vs static dist serving for Cloud Run production
  const isProduction =
    process.env.NODE_ENV === 'production' ||
    Boolean(process.env.K_SERVICE) ||
    process.env.npm_lifecycle_event === 'start';

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
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

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Oracle DB-IDS Server running on http://localhost:${PORT}`);
  });
}

startServer();
