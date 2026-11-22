import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createDashboardApp, type DashboardAppOptions } from '../server.ts';
import { getAuditKey, getFgaKey, type DashboardApiResponse } from '../src/types/ids.ts';

const BRIDGE_TOKEN = 'test-bridge-secret';
const SOC_TOKEN = 'test-soc-secret';
const ALLOWED_ORIGIN = 'http://localhost:3000';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqloracle-server-sync-'));

after(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function startTestServer(
  stateFileName: string,
  extraOptions: Partial<DashboardAppOptions> = {}
): Promise<{
  baseUrl: string;
  stateFile: string;
  close: () => Promise<void>;
}> {
  const stateFile = path.join(tempDir, stateFileName);
  const { app } = createDashboardApp({
    stateFile,
    bridgeToken: BRIDGE_TOKEN,
    socAdminToken: SOC_TOKEN,
    bridgeUrl: '',
    enableBridgeWatcher: false,
    allowedOrigins: [ALLOWED_ORIGIN],
    ...extraOptions,
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  const close = async () => {
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    }
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  };

  return { baseUrl, stateFile, close };
}

function bearerHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    Authorization: `Bearer ${SOC_TOKEN}`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

test('unauthenticated requests to protected endpoints all return 401', async () => {
  const srv = await startTestServer('auth-gate.json');
  try {
    const getRoutes = ['/api/data', '/api/oracle-bridge.py', '/api/oracle-bridge-bundle.zip'];
    for (const route of getRoutes) {
      const res = await fetch(`${srv.baseUrl}${route}`);
      assert.equal(res.status, 401, `GET ${route} must require authentication`);
    }

    const postRoutes: Array<{ route: string; body: Record<string, unknown> }> = [
      { route: '/api/user-action', body: { username: 'U1', action: 'unlock' } },
      { route: '/api/clear-alerts', body: { target: 'all' } },
      { route: '/api/toggle-ips', body: { auto_response: false } },
      { route: '/api/review-state', body: { reviewed_alert_keys: [] } },
      { route: '/api/execute-oracle-sql', body: { sql: 'SELECT 1 FROM DUAL;', dbUser: 'U4' } },
      { route: '/api/mode', body: { mode: 'simulation' } },
    ];

    for (const item of postRoutes) {
      const res = await fetch(`${srv.baseUrl}${item.route}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(item.body),
      });
      assert.equal(res.status, 401, `POST ${item.route} must require authentication`);
    }

    const wrongBearer = await fetch(`${srv.baseUrl}/api/data`, {
      headers: { Authorization: 'Bearer wrong-token' },
    });
    assert.equal(wrongBearer.status, 401);
  } finally {
    await srv.close();
  }
});

test('session cookie login issues HttpOnly SameSite=Strict cookie, enforces CSRF, and supports Bearer token', async () => {
  const srv = await startTestServer('session-csrf.json');
  try {
    const badLogin = await fetch(`${srv.baseUrl}/api/auth/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'wrong-soc-token' }),
    });
    assert.equal(badLogin.status, 401);

    const goodLogin = await fetch(`${srv.baseUrl}/api/auth/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: SOC_TOKEN }),
    });
    assert.equal(goodLogin.status, 200);

    const setCookieHeader = goodLogin.headers.get('set-cookie') || '';
    assert.ok(setCookieHeader.includes('soc_session='), 'Should issue soc_session cookie');
    assert.ok(setCookieHeader.includes('HttpOnly'), 'Cookie must be HttpOnly');
    assert.ok(setCookieHeader.includes('SameSite=Strict'), 'Cookie must be SameSite=Strict');

    const sessionCookie = setCookieHeader.split(';')[0];
    const loginData = (await goodLogin.json()) as { ok: boolean; csrfToken: string };
    assert.equal(loginData.ok, true);
    assert.ok(typeof loginData.csrfToken === 'string' && loginData.csrfToken.length >= 16);

    // Cookie without X-CSRF-Token on POST -> 403
    const missingCsrf = await fetch(`${srv.baseUrl}/api/toggle-ips`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ auto_response: false }),
    });
    assert.equal(missingCsrf.status, 403);

    // Cookie with valid X-CSRF-Token -> 200
    const validCsrf = await fetch(`${srv.baseUrl}/api/toggle-ips`, {
      method: 'POST',
      headers: {
        Cookie: sessionCookie,
        'X-CSRF-Token': loginData.csrfToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ auto_response: false }),
    });
    assert.equal(validCsrf.status, 200);
    const csrfBody = (await validCsrf.json()) as { ok: boolean; auto_response: boolean };
    assert.equal(csrfBody.ok, true);
    assert.equal(csrfBody.auto_response, false);

    // Bearer token succeeds directly
    const bearerRes = await fetch(`${srv.baseUrl}/api/toggle-ips`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ auto_response: true }),
    });
    assert.equal(bearerRes.status, 200);
    const bearerBody = (await bearerRes.json()) as { ok: boolean; auto_response: boolean };
    assert.equal(bearerBody.ok, true);
    assert.equal(bearerBody.auto_response, true);
  } finally {
    await srv.close();
  }
});

test('strict CORS allowlist blocks disallowed origins and Content-Type gate rejects text/plain with 415', async () => {
  const srv = await startTestServer('cors-ct.json');
  try {
    const evilOptions = await fetch(`${srv.baseUrl}/api/data`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example' },
    });
    assert.equal(evilOptions.status, 403);
    assert.equal(evilOptions.headers.get('access-control-allow-origin'), null);

    const evilPost = await fetch(`${srv.baseUrl}/api/toggle-ips`, {
      method: 'POST',
      headers: {
        Origin: 'https://evil.example',
        ...bearerHeaders(),
      },
      body: JSON.stringify({ auto_response: false }),
    });
    assert.equal(evilPost.status, 403);
    assert.notEqual(evilPost.headers.get('access-control-allow-origin'), '*');

    const allowedOptions = await fetch(`${srv.baseUrl}/api/data`, {
      method: 'OPTIONS',
      headers: { Origin: ALLOWED_ORIGIN },
    });
    assert.equal(allowedOptions.status, 204);
    assert.equal(allowedOptions.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN);
    assert.equal(allowedOptions.headers.get('access-control-allow-credentials'), 'true');

    const badContentType = await fetch(`${srv.baseUrl}/api/toggle-ips`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SOC_TOKEN}`,
        'Content-Type': 'text/plain',
      },
      body: '{"auto_response": false}',
    });
    assert.equal(badContentType.status, 415);
  } finally {
    await srv.close();
  }
});

test('/api/oracle-sync enforces X-Bridge-Token authentication', async () => {
  const srv = await startTestServer('bridge-auth.json');
  try {
    const missingToken = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ users: [] }),
    });
    assert.equal(missingToken.status, 401);

    const wrongToken = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': 'wrong-bridge-token',
      },
      body: JSON.stringify({ users: [] }),
    });
    assert.equal(wrongToken.status, 401);

    const validToken = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({ users: [] }),
    });
    assert.equal(validToken.status, 200);
    const body = (await validToken.json()) as { ok: boolean };
    assert.equal(body.ok, true);
  } finally {
    await srv.close();
  }
});

test('pendingCommands persist across app restart, guard optimistic user state, and remove only ACKed IDs', async () => {
  const stateName = 'pending-commands-restart.json';
  const srv1 = await startTestServer(stateName);

  try {
    // Seed locked U1 in liveState
    const seedSync = await fetch(`${srv1.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({
        users: [
          {
            USERNAME: 'U1',
            ACCOUNT_STATUS: 'LOCKED',
            DML_STATUS: 'READ-ONLY',
            PRIVILEGES: 'SELECT',
            RISK_SCORE: 95,
            RESPONSE_LEVEL: 3,
            RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
          },
        ],
      }),
    });
    assert.equal(seedSync.status, 200);

    // Enqueue unlock on U1 while bridgeUrl is empty (unreachable)
    const unlockRes = await fetch(`${srv1.baseUrl}/api/user-action`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ username: 'U1', action: 'unlock' }),
    });
    assert.equal(unlockRes.status, 200);

    // Enqueue a second command (toggle_ips) to verify selective ACK later
    const ipsRes = await fetch(`${srv1.baseUrl}/api/toggle-ips`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ auto_response: false }),
    });
    assert.equal(ipsRes.status, 200);
  } finally {
    await srv1.close();
  }

  // Restart a brand-new createDashboardApp pointing at the exact same stateFile
  const srv2 = await startTestServer(stateName);
  try {
    const staleSyncPayload = {
      users: [
        {
          USERNAME: 'U1',
          ACCOUNT_STATUS: 'LOCKED',
          DML_STATUS: 'READ-ONLY',
          PRIVILEGES: 'SELECT',
          RISK_SCORE: 95,
          RESPONSE_LEVEL: 3,
          RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
        },
      ],
    };

    // Sync WITHOUT ack_command_ids: must return pending commands, NOT erase them, and NOT overwrite OPEN U1 with stale LOCKED
    const syncNoAck1 = await fetch(`${srv2.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify(staleSyncPayload),
    });
    assert.equal(syncNoAck1.status, 200);
    const syncBody1 = (await syncNoAck1.json()) as {
      ok: boolean;
      pending_commands: Array<{ id: string; type: string; payload: Record<string, unknown> }>;
    };
    assert.equal(syncBody1.pending_commands.length, 2);

    const unlockCmd = syncBody1.pending_commands.find(
      (c) => c.type === 'user_action' && c.payload.username === 'U1' && c.payload.action === 'unlock'
    );
    const toggleCmd = syncBody1.pending_commands.find((c) => c.type === 'toggle_ips');
    assert.ok(unlockCmd, 'Persisted unlock command must survive restart');
    assert.ok(toggleCmd, 'Persisted toggle_ips command must survive restart');

    // Verify optimistic OPEN status was preserved despite stale LOCKED sync
    const dataRes = await fetch(`${srv2.baseUrl}/api/data`, {
      headers: { Authorization: `Bearer ${SOC_TOKEN}` },
    });
    assert.equal(dataRes.status, 200);
    const dataBody = (await dataRes.json()) as DashboardApiResponse;
    const u1AfterStaleSync = dataBody.users.find((u) => u.USERNAME === 'U1')!;
    assert.equal(u1AfterStaleSync.ACCOUNT_STATUS, 'OPEN');

    // Second sync without ACK still retains both commands
    const syncNoAck2 = await fetch(`${srv2.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify(staleSyncPayload),
    });
    const syncBody2 = (await syncNoAck2.json()) as {
      pending_commands: Array<{ id: string }>;
    };
    assert.equal(syncBody2.pending_commands.length, 2);

    // Send ACK for ONLY unlockCmd.id -> removes only unlockCmd, keeps toggleCmd
    const partialAck = await fetch(`${srv2.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({
        ack_command_ids: [unlockCmd.id],
        users: [
          {
            USERNAME: 'U1',
            ACCOUNT_STATUS: 'OPEN',
            DML_STATUS: 'FULL DML',
            PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
            RISK_SCORE: 0,
            RESPONSE_LEVEL: 0,
            RESPONSE_LABEL: 'Level 0: Normal (An toàn)',
          },
        ],
      }),
    });
    assert.equal(partialAck.status, 200);
    const partialAckBody = (await partialAck.json()) as {
      pending_commands: Array<{ id: string; type: string }>;
    };
    assert.equal(partialAckBody.pending_commands.length, 1);
    assert.equal(partialAckBody.pending_commands[0].id, toggleCmd.id);
  } finally {
    await srv2.close();
  }
});

test('clear-alerts target=reviewed isolates FGA clearing from reviewed alerts, triggers, and audit logs, plus single_fga/single_audit', async () => {
  const srv = await startTestServer('reviewed-isolation.json');
  try {
    const fga1 = {
      EVENT_TIMESTAMP: '2026-11-22 10:00:01',
      DBUSERNAME: 'U1',
      ACTION_NAME: 'SELECT',
      OBJECT_SCHEMA: 'SYS',
      OBJECT_NAME: 'NV',
      FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
      AUDIT_TYPE: 'FineGrainedAudit',
      SQL_TEXT: "SELECT * FROM SYS.NV WHERE MANV = 'NV_TRAP'",
      OS_USERNAME: 'pc',
      USERHOST: 'LAPTOP-R03ORTGV',
      CLIENT_PROGRAM_NAME: 'SQL Developer',
      RETURN_CODE: 20003,
    };
    const fga2 = {
      ...fga1,
      EVENT_TIMESTAMP: '2026-11-22 10:00:02',
      FGA_POLICY_NAME: 'FGA_HIGH_SALARY_ACCESS',
      SQL_TEXT: 'SELECT LUONG FROM SYS.NV',
    };
    const aud1 = {
      EVENT_TIMESTAMP: '2026-11-22 10:00:01',
      DBUSERNAME: 'U1',
      ACTION_NAME: 'SELECT',
      OBJECT_SCHEMA: 'SYS',
      OBJECT_NAME: 'NV',
      SQL_TEXT: "SELECT * FROM SYS.NV WHERE MANV = 'NV_TRAP'",
      RETURN_CODE: 20003,
      OS_USERNAME: 'pc',
      USERHOST: 'LAPTOP-R03ORTGV',
      CLIENT_PROGRAM_NAME: 'SQL Developer',
      AUDIT_TYPE: 'FineGrainedAudit',
    };
    const aud2 = {
      ...aud1,
      EVENT_TIMESTAMP: '2026-11-22 10:00:03',
      ACTION_NAME: 'UPDATE',
      SQL_TEXT: "UPDATE SYS.NV SET LUONG = 5000 WHERE MANV = 'NV3'",
    };

    const fk1 = getFgaKey(fga1);
    const fk2 = getFgaKey(fga2);
    const ak1 = getAuditKey(aud1);
    const ak2 = getAuditKey(aud2);

    const syncRes = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({
        users: [
          {
            USERNAME: 'U1',
            ACCOUNT_STATUS: 'LOCKED',
            DML_STATUS: 'READ-ONLY',
            PRIVILEGES: 'SELECT',
            RISK_SCORE: 95,
            RESPONSE_LEVEL: 3,
            RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
          },
        ],
        alerts: [
          {
            key: 'ALERT_1',
            severity: 'CRITICAL',
            risk_score: 95,
            response_level: 3,
            response_label: 'Level 3: CRITICAL (Full Isolation)',
            time: '2026-11-22 10:00:01',
            user: 'U1',
            attack_type: 'Honeytoken',
            details: "SELECT * FROM SYS.NV WHERE MANV = 'NV_TRAP'",
            client_program: 'SQL Developer',
            userhost: 'LAPTOP-R03ORTGV',
            os_username: 'pc',
            context: 'SQL Developer (pc@LAPTOP-R03ORTGV)',
          },
          {
            key: 'ALERT_2',
            severity: 'HIGH',
            risk_score: 65,
            response_level: 2,
            response_label: 'Level 2: HIGH (Privilege Containment)',
            time: '2026-11-22 10:00:03',
            user: 'U1',
            attack_type: 'Trigger Block',
            details: 'Salary anomaly',
            client_program: 'Database Trigger',
            userhost: 'SYS.TRG_PROTECT_NV',
            os_username: 'pc',
            context: 'Database Trigger',
          },
        ],
        fga_events: [fga1, fga2],
        triggers: [
          {
            ALERT_ID: 201,
            EVENT_TIME: '2026-11-22 10:00:03',
            DB_USER: 'U1',
            ATTACK_TYPE: 'ABNORMAL_SALARY_MODIFICATION',
            DETAILS: '900 -> 5000',
          },
          {
            ALERT_ID: 202,
            EVENT_TIME: '2026-11-22 10:00:04',
            DB_USER: 'U1',
            ATTACK_TYPE: 'UNAUTHORIZED_DELETE',
            DETAILS: 'Delete NV1',
          },
        ],
        audit_logs: [aud1, aud2],
      }),
    });
    assert.equal(syncRes.status, 200);

    // Mark items across all 4 tables as reviewed
    const reviewRes = await fetch(`${srv.baseUrl}/api/review-state`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({
        reviewed_alert_keys: ['ALERT_1'],
        reviewed_fga_keys: [fk1],
        reviewed_trigger_ids: [201],
        reviewed_audit_keys: [ak1],
      }),
    });
    assert.equal(reviewRes.status, 200);

    // Clear ONLY reviewed_fga_keys via target === 'reviewed'
    const clearReviewedFga = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({
        target: 'reviewed',
        reviewed_fga_keys: [fk1],
      }),
    });
    assert.equal(clearReviewedFga.status, 200);
    const afterReviewed = (await clearReviewedFga.json()) as {
      ok: boolean;
      alerts: Array<{ key: string; reviewed?: boolean }>;
      fga_events: Array<typeof fga1>;
      triggers: Array<{ ALERT_ID: number; reviewed?: boolean }>;
      audit_logs: Array<typeof aud1>;
    };

    assert.equal(afterReviewed.fga_events.length, 1);
    assert.equal(getFgaKey(afterReviewed.fga_events[0]), fk2);
    assert.equal(afterReviewed.alerts.length, 2, 'Reviewed alerts must stay intact');
    assert.equal(afterReviewed.triggers.length, 2, 'Reviewed triggers must stay intact');
    assert.equal(afterReviewed.audit_logs.length, 2, 'Reviewed audit logs must stay intact');
    assert.equal(afterReviewed.alerts.find((a) => a.key === 'ALERT_1')?.reviewed, true);
    assert.equal(afterReviewed.triggers.find((t) => t.ALERT_ID === 201)?.reviewed, true);

    // Test single_fga
    const clearSingleFga = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({
        target: 'single_fga',
        fga_key: fk2,
      }),
    });
    assert.equal(clearSingleFga.status, 200);
    const afterSingleFga = (await clearSingleFga.json()) as {
      fga_events: unknown[];
      alerts: unknown[];
      triggers: unknown[];
      audit_logs: unknown[];
    };
    assert.equal(afterSingleFga.fga_events.length, 0);
    assert.equal(afterSingleFga.alerts.length, 2);
    assert.equal(afterSingleFga.triggers.length, 2);
    assert.equal(afterSingleFga.audit_logs.length, 2);

    // Test single_audit
    const clearSingleAudit = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({
        target: 'single_audit',
        audit_key: ak1,
      }),
    });
    assert.equal(clearSingleAudit.status, 200);
    const afterSingleAudit = (await clearSingleAudit.json()) as {
      audit_logs: Array<typeof aud1>;
      alerts: unknown[];
      triggers: unknown[];
    };
    assert.equal(afterSingleAudit.audit_logs.length, 1);
    assert.equal(getAuditKey(afterSingleAudit.audit_logs[0]), ak2);
    assert.equal(afterSingleAudit.alerts.length, 2);
    assert.equal(afterSingleAudit.triggers.length, 2);
  } finally {
    await srv.close();
  }
});

test('liveState and simState remain strictly isolated across SQL simulation, oracle-sync, and mode switches', async () => {
  const srv = await startTestServer('split-brain.json');
  try {
    // 1. Initial oracle_live state before any bridge sync
    const initRes = await fetch(`${srv.baseUrl}/api/data`, {
      headers: { Authorization: `Bearer ${SOC_TOKEN}` },
    });
    assert.equal(initRes.status, 200);
    const initData = (await initRes.json()) as DashboardApiResponse;
    assert.equal(initData.active_mode, 'oracle_live');
    assert.equal(initData.data_source, 'disconnected');
    assert.equal(initData.oracle_bridge_connected, false);
    assert.deepEqual(initData.users, []);

    // 2. Execute SQL simulation -> switches to simulation, runs TS detector, never fakes bridge connection or mutates liveState
    const execRes = await fetch(`${srv.baseUrl}/api/execute-oracle-sql`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({
        sql: "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;",
        dbUser: 'U4',
      }),
    });
    assert.equal(execRes.status, 200);
    const execBody = (await execRes.json()) as {
      ok: boolean;
      active_mode: string;
      new_alerts_count: number;
    };
    assert.equal(execBody.active_mode, 'simulation');
    assert.ok(execBody.new_alerts_count >= 1);

    const simDataRes = await fetch(`${srv.baseUrl}/api/data`, {
      headers: { Authorization: `Bearer ${SOC_TOKEN}` },
    });
    const simData = (await simDataRes.json()) as DashboardApiResponse;
    assert.equal(simData.active_mode, 'simulation');
    assert.equal(simData.data_source, 'simulation');
    assert.equal(simData.oracle_bridge_connected, false);
    assert.equal(simData.last_oracle_sync, null);
    const simU4 = simData.users.find((u) => u.USERNAME === 'U4')!;
    assert.ok(simU4.RISK_SCORE >= 95);

    // Confirm liveState is still disconnected and empty
    const toLiveRes1 = await fetch(`${srv.baseUrl}/api/mode`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ mode: 'oracle_live' }),
    });
    assert.equal(toLiveRes1.status, 200);
    const liveBeforeSync = (await (
      await fetch(`${srv.baseUrl}/api/data`, { headers: { Authorization: `Bearer ${SOC_TOKEN}` } })
    ).json()) as DashboardApiResponse;
    assert.equal(liveBeforeSync.data_source, 'disconnected');
    assert.deepEqual(liveBeforeSync.users, []);

    // Switch back to simulation, then receive /api/oracle-sync -> must update liveState without wiping simState
    const toSimRes = await fetch(`${srv.baseUrl}/api/mode`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ mode: 'simulation' }),
    });
    assert.equal(toSimRes.status, 200);

    const syncRes = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({
        users: [
          {
            USERNAME: 'U1',
            ACCOUNT_STATUS: 'OPEN',
            DML_STATUS: 'FULL DML',
            PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
            RISK_SCORE: 0,
            RESPONSE_LEVEL: 0,
            RESPONSE_LABEL: 'Level 0: Normal (An toàn)',
          },
        ],
        alerts: [],
        failed_logons: [
          {
            DBUSERNAME: 'U1',
            FAIL_COUNT: 4,
            LAST_ATTEMPT: '2026-11-22 10:15:00',
            OS_USERNAME: 'pc',
            USERHOST: 'LAPTOP-R03ORTGV',
            CLIENT_PROGRAM_NAME: 'sqlplus.exe',
          },
        ],
        defense_health: {
          trigger_ok: true,
          fga_ok: true,
          audit_ok: true,
          crypto_policy_ok: true,
          errors: [],
        },
      }),
    });
    assert.equal(syncRes.status, 200);

    // simState still intact
    const simAfterSync = (await (
      await fetch(`${srv.baseUrl}/api/data`, { headers: { Authorization: `Bearer ${SOC_TOKEN}` } })
    ).json()) as DashboardApiResponse;
    assert.equal(simAfterSync.data_source, 'simulation');
    assert.ok(simAfterSync.users.find((u) => u.USERNAME === 'U4')!.RISK_SCORE >= 95);

    // Switch to oracle_live -> shows data_source='oracle_live', failed_logons, and defense_health
    const toLiveRes2 = await fetch(`${srv.baseUrl}/api/mode`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ mode: 'oracle_live' }),
    });
    assert.equal(toLiveRes2.status, 200);
    const liveAfterSync = (await (
      await fetch(`${srv.baseUrl}/api/data`, { headers: { Authorization: `Bearer ${SOC_TOKEN}` } })
    ).json()) as DashboardApiResponse;
    assert.equal(liveAfterSync.active_mode, 'oracle_live');
    assert.equal(liveAfterSync.data_source, 'oracle_live');
    assert.equal(liveAfterSync.oracle_bridge_connected, true);
    assert.equal(liveAfterSync.failed_logons?.length, 1);
    assert.equal(liveAfterSync.failed_logons?.[0].FAIL_COUNT, 4);
    assert.deepEqual(liveAfterSync.defense_health, {
      trigger_ok: true,
      fga_ok: true,
      audit_ok: true,
      crypto_policy_ok: true,
      errors: [],
    });
  } finally {
    await srv.close();
  }
});

test('GET /api/oracle-bridge.py returns authenticated Python source instead of SPA HTML', async () => {
  const srv = await startTestServer('bridge-download.json');
  try {
    const res = await fetch(`${srv.baseUrl}/api/oracle-bridge.py`, {
      headers: { Authorization: `Bearer ${SOC_TOKEN}` },
    });
    assert.equal(res.status, 200);
    const contentType = res.headers.get('content-type') || '';
    assert.ok(contentType.includes('text/x-python'), `Unexpected Content-Type: ${contentType}`);

    const text = await res.text();
    assert.ok(text.includes('BridgeService'), 'Should return Python oracle/bridge.py source');
    assert.ok(!text.includes('<!DOCTYPE html>'), 'Must not fall through to index.html');
  } finally {
    await srv.close();
  }
});

test('GET /api/data masks employee CMND by default and scrubs SQL passwords across logs and persisted state', async () => {
  const srv = await startTestServer('scrubbing-cmnd.json');
  try {
    const simSecret = 'SimSecret!Pass 99';
    const liveSecret = 'BridgeSecret!Pass 88';

    // Simulation SQL execution with quoted password
    const execRes = await fetch(`${srv.baseUrl}/api/execute-oracle-sql`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({
        sql: `CREATE USER TESTER IDENTIFIED BY "${simSecret}";`,
        dbUser: 'U4',
      }),
    });
    assert.equal(execRes.status, 200);

    const simData = (await (
      await fetch(`${srv.baseUrl}/api/data`, { headers: { Authorization: `Bearer ${SOC_TOKEN}` } })
    ).json()) as DashboardApiResponse;

    assert.ok(simData.employees.length > 0);
    assert.equal(simData.employees[0].CMND, '001••••••45');
    for (const emp of simData.employees) {
      assert.ok(!/^\d{9,12}$/.test(emp.CMND), `Raw CMND leaked for ${emp.MANV}: ${emp.CMND}`);
    }
    for (const alert of simData.alerts) {
      assert.ok(!alert.details.includes(simSecret));
    }
    for (const log of simData.audit_logs) {
      assert.ok(!log.SQL_TEXT.includes(simSecret));
    }

    // Live oracle-sync with raw CMND and raw password in telemetry
    const syncRes = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({
        employees: [
          {
            MANV: 'NV1',
            HOTEN: 'Nguyen Van A',
            LUONG: 900,
            GIOITINH: 'Nam',
            CMND: '001206012345',
          },
        ],
        alerts: [
          {
            key: 'PRIV|U1|2026-11-22 10:00:00|0',
            severity: 'CRITICAL',
            risk_score: 88,
            response_level: 3,
            response_label: 'Level 3: CRITICAL (Full Isolation)',
            time: '2026-11-22 10:00:00',
            user: 'U1',
            attack_type: 'Privilege Escalation',
            details: `ALTER USER U1 IDENTIFIED BY "${liveSecret}"`,
            client_program: 'sqlplus.exe',
            userhost: 'LAPTOP-R03ORTGV',
            os_username: 'pc',
            context: 'sqlplus.exe (pc@LAPTOP-R03ORTGV)',
          },
        ],
        audit_logs: [
          {
            EVENT_TIMESTAMP: '2026-11-22 10:00:00',
            DBUSERNAME: 'U1',
            ACTION_NAME: 'ALTER USER',
            OBJECT_SCHEMA: 'SYS',
            OBJECT_NAME: 'USER$',
            SQL_TEXT: `ALTER USER U1 IDENTIFIED BY "${liveSecret}"`,
            RETURN_CODE: 0,
            OS_USERNAME: 'pc',
            USERHOST: 'LAPTOP-R03ORTGV',
            CLIENT_PROGRAM_NAME: 'sqlplus.exe',
            AUDIT_TYPE: 'Standard',
          },
        ],
      }),
    });
    assert.equal(syncRes.status, 200);

    const switchLiveRes = await fetch(`${srv.baseUrl}/api/mode`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ mode: 'oracle_live' }),
    });
    assert.equal(switchLiveRes.status, 200);
    const liveData = (await (
      await fetch(`${srv.baseUrl}/api/data`, { headers: { Authorization: `Bearer ${SOC_TOKEN}` } })
    ).json()) as DashboardApiResponse;

    assert.equal(liveData.employees[0].CMND, '001••••••45');
    assert.ok(!liveData.alerts[0].details.includes(liveSecret));
    assert.ok(liveData.alerts[0].details.includes('IDENTIFIED BY "••••••••"'));
    assert.ok(!liveData.audit_logs[0].SQL_TEXT.includes(liveSecret));
    assert.ok(liveData.audit_logs[0].SQL_TEXT.includes('IDENTIFIED BY "••••••••"'));

    const persistedRaw = fs.readFileSync(srv.stateFile, 'utf-8');
    assert.ok(!persistedRaw.includes(simSecret));
    assert.ok(!persistedRaw.includes(liveSecret));
    assert.ok(!persistedRaw.includes('001206012345'));
  } finally {
    await srv.close();
  }
});

test('input validation rejects protected/invalid user-action accounts, invalid clear-alerts target/cutoff, and malformed execute-oracle-sql metadata with 400', async () => {
  const srv = await startTestServer('input-validation.json');
  try {
    for (const badUsername of ['SYS', 'SYSTEM', 'PUBLIC', 'sys', 'U1; DROP TABLE NV', '123BAD', '']) {
      const res = await fetch(`${srv.baseUrl}/api/user-action`, {
        method: 'POST',
        headers: bearerHeaders(),
        body: JSON.stringify({ username: badUsername, action: 'unlock' }),
      });
      assert.equal(res.status, 400, `Expected 400 for username=${JSON.stringify(badUsername)}`);
    }

    const badClearPayloads: Array<Record<string, unknown>> = [
      { target: 'drop_everything' },
      { target: 42 },
      { target: 'all', cutoff: 'zzz' },
      { target: 'all', cutoff: '2026-02-30 10:00:00' },
      { target: 'all', cutoff: 12345 },
    ];
    for (const body of badClearPayloads) {
      const res = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
        method: 'POST',
        headers: bearerHeaders(),
        body: JSON.stringify(body),
      });
      assert.equal(res.status, 400, `Expected 400 for clear-alerts body=${JSON.stringify(body)}`);
    }

    const validIsoCutoff = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ target: 'audit', cutoff: '2026-11-22T10:15:30.123Z' }),
    });
    assert.equal(validIsoCutoff.status, 200);

    const badSqlPayloads: Array<Record<string, unknown>> = [
      { sql: 'SELECT 1 FROM DUAL;', dbUser: ['U1'] },
      { sql: 'SELECT 1 FROM DUAL;', dbUser: { name: 'U1' } },
      { sql: 'SELECT 1 FROM DUAL;', host: 123 },
      { sql: 'SELECT 1 FROM DUAL;', osUser: 'x'.repeat(257) },
      { sql: 'SELECT 1 FROM DUAL;', client: null },
    ];
    for (const body of badSqlPayloads) {
      const res = await fetch(`${srv.baseUrl}/api/execute-oracle-sql`, {
        method: 'POST',
        headers: bearerHeaders(),
        body: JSON.stringify(body),
      });
      assert.equal(res.status, 400, `Expected 400 for execute-oracle-sql body=${JSON.stringify(body)}`);
    }
  } finally {
    await srv.close();
  }
});

test('forwardToOracleBridge rejects 4xx bridge errors without mutating liveState or queuing pendingCommands', async () => {
  const mockBridge = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/toggle-ips') {
      res.statusCode = 401;
      res.end(JSON.stringify({ ok: false, error: 'Invalid bridge token' }));
      return;
    }
    res.statusCode = 400;
    res.end(JSON.stringify({ ok: false, error: 'Bridge rejected command' }));
  });

  await new Promise<void>((resolve) => {
    mockBridge.listen(0, '127.0.0.1', resolve);
  });
  const bridgeAddr = mockBridge.address() as AddressInfo;
  const mockBridgeUrl = `http://127.0.0.1:${bridgeAddr.port}`;

  const srv = await startTestServer('bridge-4xx.json', { bridgeUrl: mockBridgeUrl });
  try {
    const seedRes = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({
        users: [
          {
            USERNAME: 'U1',
            ACCOUNT_STATUS: 'LOCKED',
            DML_STATUS: 'READ-ONLY',
            PRIVILEGES: 'SELECT',
            RISK_SCORE: 95,
            RESPONSE_LEVEL: 3,
            RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
          },
        ],
        alerts: [
          {
            key: 'ALERT_4XX',
            severity: 'CRITICAL',
            risk_score: 95,
            response_level: 3,
            response_label: 'Level 3: CRITICAL (Full Isolation)',
            time: '2026-11-22 10:00:00',
            user: 'U1',
            attack_type: 'SQL Injection',
            details: "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1",
            client_program: 'SQL Developer',
            userhost: 'LAPTOP-R03ORTGV',
            os_username: 'pc',
            context: 'SQL Developer (pc@LAPTOP-R03ORTGV)',
          },
        ],
      }),
    });
    assert.equal(seedRes.status, 200);

    const rejectedAction = await fetch(`${srv.baseUrl}/api/user-action`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ username: 'U1', action: 'unlock' }),
    });
    assert.equal(rejectedAction.status, 400);
    const rejectedActionBody = (await rejectedAction.json()) as { ok: boolean; error: string };
    assert.equal(rejectedActionBody.ok, false);
    assert.match(rejectedActionBody.error, /Bridge rejected command/);

    const rejectedClear = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ target: 'ids' }),
    });
    assert.equal(rejectedClear.status, 400);

    const rejectedToggle = await fetch(`${srv.baseUrl}/api/toggle-ips`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ auto_response: false }),
    });
    assert.equal(rejectedToggle.status, 502);

    const dataRes = await fetch(`${srv.baseUrl}/api/data`, {
      headers: { Authorization: `Bearer ${SOC_TOKEN}` },
    });
    const dataBody = (await dataRes.json()) as DashboardApiResponse;
    assert.equal(dataBody.users.find((u) => u.USERNAME === 'U1')?.ACCOUNT_STATUS, 'LOCKED');
    assert.equal(dataBody.alerts.length, 1);
    assert.equal(dataBody.auto_response, true);

    const syncCheck = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({}),
    });
    const syncBody = (await syncCheck.json()) as { pending_commands: unknown[] };
    assert.equal(syncBody.pending_commands.length, 0);
  } finally {
    await srv.close();
    if (typeof mockBridge.closeAllConnections === 'function') {
      mockBridge.closeAllConnections();
    }
    await new Promise<void>((resolve, reject) => {
      mockBridge.close((err) => (err ? reject(err) : resolve()));
    });
  }
});

test('simulation unlock sets simUserClearedAt and prevents subsequent benign SELECT from re-locking U1', async () => {
  const srv = await startTestServer('sim-unlock-watermark.json', { initialMode: 'simulation' });
  try {
    const unlockRes = await fetch(`${srv.baseUrl}/api/user-action`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ username: 'U1', action: 'unlock' }),
    });
    assert.equal(unlockRes.status, 200);
    const unlockBody = (await unlockRes.json()) as {
      ok: boolean;
      users: DashboardApiResponse['users'];
    };
    const unlockedU1 = unlockBody.users.find((u) => u.USERNAME === 'U1')!;
    assert.equal(unlockedU1.ACCOUNT_STATUS, 'OPEN');
    assert.equal(unlockedU1.RISK_SCORE, 0);

    const persisted = JSON.parse(fs.readFileSync(srv.stateFile, 'utf-8')) as {
      simState?: { simUserClearedAt?: Record<string, string> };
    };
    assert.ok(persisted.simState?.simUserClearedAt?.U1, 'simUserClearedAt.U1 must be persisted');

    const benignExec = await fetch(`${srv.baseUrl}/api/execute-oracle-sql`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({
        sql: "SELECT MANV, HOTEN FROM SYS.NV WHERE MANV = 'NV1';",
        dbUser: 'U1',
      }),
    });
    assert.equal(benignExec.status, 200);

    const simData = (await (
      await fetch(`${srv.baseUrl}/api/data`, { headers: { Authorization: `Bearer ${SOC_TOKEN}` } })
    ).json()) as DashboardApiResponse;
    const u1AfterBenign = simData.users.find((u) => u.USERNAME === 'U1')!;
    assert.equal(u1AfterBenign.ACCOUNT_STATUS, 'OPEN');
    assert.equal(u1AfterBenign.RISK_SCORE, 0);
    assert.equal(u1AfterBenign.RESPONSE_LEVEL, 0);
  } finally {
    await srv.close();
  }
});

test('oracle_live clear-alerts target=single_ids and reviewed recalculate RISK_SCORE without flipping Oracle LOCKED user to OPEN', async () => {
  const srv = await startTestServer('live-partial-clear.json');
  try {
    const syncRes = await fetch(`${srv.baseUrl}/api/oracle-sync`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Token': BRIDGE_TOKEN,
      },
      body: JSON.stringify({
        users: [
          {
            USERNAME: 'U1',
            ACCOUNT_STATUS: 'LOCKED',
            DML_STATUS: 'READ-ONLY',
            PRIVILEGES: 'SELECT',
            RISK_SCORE: 95,
            RESPONSE_LEVEL: 3,
            RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
          },
          {
            USERNAME: 'U2',
            ACCOUNT_STATUS: 'LOCKED',
            DML_STATUS: 'READ-ONLY',
            PRIVILEGES: 'SELECT',
            RISK_SCORE: 95,
            RESPONSE_LEVEL: 3,
            RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
          },
        ],
        alerts: [
          {
            key: 'LIVE_A1',
            severity: 'CRITICAL',
            risk_score: 95,
            response_level: 3,
            response_label: 'Level 3: CRITICAL (Full Isolation)',
            time: '2026-11-22 10:00:01',
            user: 'U1',
            attack_type: 'Honeytoken',
            details: "SELECT * FROM SYS.NV WHERE MANV = 'NV_TRAP'",
            client_program: 'SQL Developer',
            userhost: 'LAPTOP-R03ORTGV',
            os_username: 'pc',
            context: 'SQL Developer (pc@LAPTOP-R03ORTGV)',
          },
          {
            key: 'LIVE_A2',
            severity: 'CRITICAL',
            risk_score: 95,
            response_level: 3,
            response_label: 'Level 3: CRITICAL (Full Isolation)',
            time: '2026-11-22 10:00:02',
            user: 'U2',
            attack_type: 'SQL Injection',
            details: "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1",
            client_program: 'SQL Developer',
            userhost: 'LAPTOP-R03ORTGV',
            os_username: 'pc',
            context: 'SQL Developer (pc@LAPTOP-R03ORTGV)',
          },
        ],
      }),
    });
    assert.equal(syncRes.status, 200);

    const singleRes = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ target: 'single_ids', alert_key: 'LIVE_A1' }),
    });
    assert.equal(singleRes.status, 200);
    const singleBody = (await singleRes.json()) as { users: DashboardApiResponse['users'] };
    const u1AfterSingle = singleBody.users.find((u) => u.USERNAME === 'U1')!;
    assert.equal(u1AfterSingle.RISK_SCORE, 0);
    assert.equal(u1AfterSingle.RESPONSE_LEVEL, 0);
    assert.equal(u1AfterSingle.ACCOUNT_STATUS, 'LOCKED');
    assert.equal(u1AfterSingle.DML_STATUS, 'READ-ONLY');

    const reviewedRes = await fetch(`${srv.baseUrl}/api/clear-alerts`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: JSON.stringify({ target: 'reviewed', reviewed_keys: ['LIVE_A2'] }),
    });
    assert.equal(reviewedRes.status, 200);
    const reviewedBody = (await reviewedRes.json()) as { users: DashboardApiResponse['users'] };
    const u2AfterReviewed = reviewedBody.users.find((u) => u.USERNAME === 'U2')!;
    assert.equal(u2AfterReviewed.RISK_SCORE, 0);
    assert.equal(u2AfterReviewed.RESPONSE_LEVEL, 0);
    assert.equal(u2AfterReviewed.ACCOUNT_STATUS, 'LOCKED');
    assert.equal(u2AfterReviewed.DML_STATUS, 'READ-ONLY');
  } finally {
    await srv.close();
  }
});

test('GET /api/oracle-bridge-bundle.zip returns valid ZIP archive containing standalone bridge files', async () => {
  const srv = await startTestServer('bridge-zip.json');
  try {
    const res = await fetch(`${srv.baseUrl}/api/oracle-bridge-bundle.zip`, {
      headers: { Authorization: `Bearer ${SOC_TOKEN}` },
    });
    assert.equal(res.status, 200);
    assert.ok((res.headers.get('content-type') || '').includes('application/zip'));
    assert.ok(
      (res.headers.get('content-disposition') || '').includes('oracle_bridge_bundle.zip')
    );

    const buf = Buffer.from(await res.arrayBuffer());
    assert.equal(buf.readUInt32LE(0), 0x04034b50, 'ZIP must start with PK\\x03\\x04');

    const extracted = new Map<string, Buffer>();
    let pos = 0;
    while (pos + 4 <= buf.length && buf.readUInt32LE(pos) === 0x04034b50) {
      const method = buf.readUInt16LE(pos + 8);
      const compSize = buf.readUInt32LE(pos + 18);
      const nameLen = buf.readUInt16LE(pos + 26);
      const extraLen = buf.readUInt16LE(pos + 28);
      const nameStart = pos + 30;
      const dataStart = nameStart + nameLen + extraLen;
      const entryName = buf.subarray(nameStart, nameStart + nameLen).toString('utf8');
      const compressedData = buf.subarray(dataStart, dataStart + compSize);
      const rawData =
        method === 8 ? zlib.inflateRawSync(compressedData) : compressedData;
      extracted.set(entryName, rawData);
      pos = dataStart + compSize;
    }

    assert.ok(extracted.has('oracle/bridge.py'));
    assert.ok(extracted.has('shared/detection_policy.json'));
    assert.ok(extracted.has('.env.example'));
    assert.ok(extracted.get('oracle/bridge.py')!.toString('utf8').includes('BridgeService'));
    assert.ok(
      extracted.get('shared/detection_policy.json')!.toString('utf8').includes('protected_accounts')
    );
  } finally {
    await srv.close();
  }
});

test('oversized JSON payload (>5MB) returns 413 Payload Too Large', async () => {
  const srv = await startTestServer('payload-413.json');
  try {
    const oversizedBody = JSON.stringify({
      sql: 'A'.repeat(5 * 1024 * 1024 + 4096),
      dbUser: 'U1',
    });
    const res = await fetch(`${srv.baseUrl}/api/execute-oracle-sql`, {
      method: 'POST',
      headers: bearerHeaders(),
      body: oversizedBody,
    });
    assert.equal(res.status, 413);
    const body = (await res.json()) as { ok: boolean; error: string };
    assert.equal(body.ok, false);
    assert.equal(body.error, 'Payload Too Large');
  } finally {
    await srv.close();
  }
});
