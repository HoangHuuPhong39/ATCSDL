import test from 'node:test';
import assert from 'node:assert/strict';
import policy from '../../shared/detection_policy.json' with { type: 'json' };
import { INITIAL_EMPLOYEES, INITIAL_USERS } from '../src/data/initialData.ts';
import type { DbUser } from '../src/types/ids.ts';
import {
  classifyResponseLevel,
  computeUserRiskScore,
  getRiskColorHex,
  recalculateUsersAfterReset,
} from '../src/utils/analytics.ts';
import { evaluateOracleSqlBatch, splitSqlStatements } from '../src/utils/oracleDetector.ts';

function makeCleanUsers(): DbUser[] {
  return recalculateUsersAfterReset(INITIAL_USERS, []);
}

test('policy thresholds and risk colors match shared/detection_policy.json', () => {
  assert.equal(policy.thresholds.level_0.min, 0);
  assert.equal(policy.thresholds.level_0.max, 19);
  assert.equal(policy.thresholds.level_1.min, 20);
  assert.equal(policy.thresholds.level_1.max, 49);
  assert.equal(policy.thresholds.level_2.min, 50);
  assert.equal(policy.thresholds.level_2.max, 79);
  assert.equal(policy.thresholds.level_3.min, 80);
  assert.equal(policy.thresholds.level_3.max, 100);

  const cases: Array<{ score: number; level: 0 | 1 | 2 | 3; label: string; color: string }> = [
    { score: -5, level: 0, label: policy.thresholds.level_0.label, color: '#10b981' },
    { score: 0, level: 0, label: policy.thresholds.level_0.label, color: '#10b981' },
    { score: 19, level: 0, label: policy.thresholds.level_0.label, color: '#10b981' },
    { score: 20, level: 1, label: policy.thresholds.level_1.label, color: '#eab308' },
    { score: 49, level: 1, label: policy.thresholds.level_1.label, color: '#eab308' },
    { score: 50, level: 2, label: policy.thresholds.level_2.label, color: '#f97316' },
    { score: 79, level: 2, label: policy.thresholds.level_2.label, color: '#f97316' },
    { score: 80, level: 3, label: policy.thresholds.level_3.label, color: '#ef4444' },
    { score: 100, level: 3, label: policy.thresholds.level_3.label, color: '#ef4444' },
    { score: 150, level: 3, label: policy.thresholds.level_3.label, color: '#ef4444' },
  ];

  for (const c of cases) {
    const res = classifyResponseLevel(c.score);
    assert.equal(res.level, c.level, `Score ${c.score} should map to level ${c.level}`);
    assert.equal(res.label, c.label, `Score ${c.score} label should match policy`);
    assert.equal(getRiskColorHex(c.score), c.color, `Score ${c.score} color mismatch`);
  }
});

test('splitSqlStatements ignores standalone comments while preserving inline comments for SQLi detection', () => {
  const script = [
    '-- Standalone header comment; should not produce a statement',
    '/* Standalone block comment ; ignored */',
    "SELECT * FROM SYS.NV WHERE manv = 'NV1;test' /* inline;hint */;",
    '-- Comment between statements; also ignored',
    'SELECT hoten -- inline comment',
    'FROM SYS.NV;',
    '/* Trailing standalone comment; ignored */',
  ].join('\n');

  const stmts = splitSqlStatements(script);
  assert.equal(stmts.length, 2);
  assert.ok(stmts[0].includes("'NV1;test'"), 'Semicolon inside string literal must not split');
  assert.ok(stmts[0].includes('/* inline;hint */'), 'Inline /* */ comment must be preserved');
  assert.ok(stmts[1].includes('-- inline comment'), 'Inline -- comment must be preserved');

  const exactSingleRes = evaluateOracleSqlBatch(
    "SELECT * FROM SYS.NV WHERE manv = 'NV1' --",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(exactSingleRes.newAlerts.length, 1);
  assert.ok(exactSingleRes.newAlerts[0].key.startsWith('SQLI|'));
  assert.equal(exactSingleRes.newAlerts[0].severity, 'CRITICAL');
  assert.equal(exactSingleRes.newAlerts[0].risk_score, 95);

  const outcome = evaluateOracleSqlBatch(
    "-- header comment\nSELECT * FROM SYS.NV WHERE manv = 'NV1' --",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );

  assert.equal(outcome.newAlerts.length, 1);
  assert.ok(outcome.newAlerts[0].key.startsWith('SQLI|'));
  assert.equal(outcome.newAlerts[0].severity, 'CRITICAL');
  assert.equal(outcome.newAlerts[0].risk_score, policy.attack_scores.sql_injection);
  assert.equal(outcome.newAlerts[0].risk_score, 95);

  const blockOutcome = evaluateOracleSqlBatch(
    "SELECT * FROM SYS.NV WHERE manv = 'NV1' /* inline comment */",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(blockOutcome.newAlerts.length, 1);
  assert.ok(blockOutcome.newAlerts[0].key.startsWith('SQLI|'));
  assert.equal(blockOutcome.newAlerts[0].risk_score, 95);
});

test('SQLi engine detects evasion vectors OR 2=2, DBMS_LOCK.SLEEP, and UTL_FILE at 95 CRITICAL', () => {
  const vectors = [
    "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 2=2;",
    'SELECT DBMS_LOCK.SLEEP(5) FROM DUAL;',
    "SELECT UTL_FILE.FOPEN('EXP_DIR', 'dump.txt', 'r') FROM DUAL;",
  ];

  for (const sql of vectors) {
    const outcome = evaluateOracleSqlBatch(sql, 'U4', makeCleanUsers(), [], [], true);
    assert.equal(outcome.newAlerts.length, 1, `Expected 1 SQLi alert for: ${sql}`);
    assert.ok(outcome.newAlerts[0].key.startsWith('SQLI|'), `Expected SQLI key for: ${sql}`);
    assert.equal(outcome.newAlerts[0].severity, 'CRITICAL');
    assert.equal(outcome.newAlerts[0].risk_score, policy.attack_scores.sql_injection);
    assert.equal(outcome.newAlerts[0].risk_score, 95);
  }
});

test('single COUNT(*) returns 28 LOW (Level 1) keeping FULL DML, while combined COUNT(*)+SUM returns 65 HIGH', () => {
  const singleProbe = evaluateOracleSqlBatch(
    "SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam';",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );

  assert.equal(singleProbe.newAlerts.length, 1);
  const probeAlert = singleProbe.newAlerts[0];
  assert.equal(probeAlert.severity, 'LOW');
  assert.equal(probeAlert.risk_score, policy.attack_scores.sdb_probe_low);
  assert.equal(probeAlert.risk_score, 28);
  assert.equal(probeAlert.response_level, 1);

  const u4AfterProbe = singleProbe.updatedUsers.find((u) => u.USERNAME === 'U4')!;
  assert.equal(u4AfterProbe.RISK_SCORE, 28);
  assert.equal(u4AfterProbe.RESPONSE_LEVEL, 1);
  assert.equal(u4AfterProbe.DML_STATUS, 'FULL DML');
  assert.equal(u4AfterProbe.ACCOUNT_STATUS, 'OPEN');

  const combinedOutcome = evaluateOracleSqlBatch(
    "SELECT COUNT(*), SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam';",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );

  assert.equal(combinedOutcome.newAlerts.length, 2);
  const combinedFga = combinedOutcome.newAlerts.find((a) => a.key.startsWith('FGA_SAL|'));
  const combinedAlert = combinedOutcome.newAlerts.find((a) => a.key.startsWith('STAT_COUNT_SUM|'));
  assert.ok(combinedFga, 'Should emit FGA_SAL alert when SUM(luong) touches LUONG on SYS.NV');
  assert.equal(combinedFga.risk_score, policy.attack_scores.fga_sensitive_access);
  assert.equal(combinedFga.risk_score, 35);
  assert.ok(combinedAlert, 'Should emit STAT_COUNT_SUM alert for combined COUNT+SUM');
  assert.equal(combinedAlert.severity, 'HIGH');
  assert.equal(combinedAlert.risk_score, policy.attack_scores.sdb_count_based);
  assert.equal(combinedAlert.risk_score, 65);
  assert.equal(combinedAlert.response_level, 2);

  const u4AfterCombined = combinedOutcome.updatedUsers.find((u) => u.USERNAME === 'U4')!;
  assert.equal(u4AfterCombined.DML_STATUS, 'READ-ONLY');
  assert.equal(u4AfterCombined.ACCOUNT_STATUS, 'OPEN');
});

test('SDB Tracker (72) and Linear System (78) scores match policy.attack_scores', () => {
  const trackerSql = `
    SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam';
    SELECT SUM(luong) FROM SYS.NV WHERE (manv = 'NV3' OR gioitinh = 'Nam');
    SELECT SUM(luong) FROM SYS.NV WHERE (manv != 'NV3' AND gioitinh = 'Nam');
  `;
  const trackerRes = evaluateOracleSqlBatch(trackerSql, 'U4', makeCleanUsers(), [], [], true);
  assert.equal(trackerRes.newAlerts.filter((a) => a.key.startsWith('FGA_SAL|')).length, 2);
  const trackerAlert = trackerRes.newAlerts.find((a) => a.key.startsWith('STAT_INF|'))!;
  assert.ok(trackerAlert, 'Expected STAT_INF alert for SDB Tracker sequence');
  assert.equal(trackerAlert.severity, 'HIGH');
  assert.equal(trackerAlert.risk_score, policy.attack_scores.sdb_tracker);
  assert.equal(trackerAlert.risk_score, 72);

  const linearSql = `
    SELECT SUM(luong) FROM SYS.NV WHERE manv IN ('NV1', 'NV2', 'NV3');
    SELECT SUM(luong) FROM SYS.NV WHERE manv IN ('NV1', 'NV2', 'NV4');
    SELECT AVG(luong) FROM SYS.NV WHERE manv IN ('NV1', 'NV3', 'NV4');
  `;
  const linearRes = evaluateOracleSqlBatch(linearSql, 'U4', makeCleanUsers(), [], [], true);
  assert.equal(linearRes.newAlerts.filter((a) => a.key.startsWith('FGA_SAL|')).length, 3);
  const linearAlert = linearRes.newAlerts.find((a) => a.key.startsWith('STAT_INF|'))!;
  assert.ok(linearAlert, 'Expected STAT_INF alert for SDB Linear System sequence');
  assert.equal(linearAlert.severity, 'HIGH');
  assert.equal(linearAlert.risk_score, policy.attack_scores.sdb_linear_system);
  assert.equal(linearAlert.risk_score, 78);
});

test('multi-column and arithmetic UPDATEs use NV3 baseline (1200) for ORA-20002, and CMND/HOTEN tampering triggers ORA-20004', () => {
  const nv3 = INITIAL_EMPLOYEES.find((e) => e.MANV === 'NV3')!;
  assert.equal(nv3.LUONG, 1200);

  const multiColOutcome = evaluateOracleSqlBatch(
    "UPDATE SYS.NV SET hoten='X', luong=5000 WHERE manv='NV3';",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(multiColOutcome.newTriggers.length, 1);
  assert.equal(multiColOutcome.newTriggers[0].ATTACK_TYPE, 'ABNORMAL_SALARY_MODIFICATION');
  assert.ok(multiColOutcome.newTriggers[0].DETAILS.includes('1200'));
  assert.ok(multiColOutcome.newTriggers[0].DETAILS.includes('5000'));
  assert.equal(
    multiColOutcome.newAuditLogs[0].RETURN_CODE,
    policy.trigger_codes.ABNORMAL_SALARY_MODIFICATION
  );
  assert.equal(multiColOutcome.newAuditLogs[0].RETURN_CODE, 20002);

  const arithOutcome = evaluateOracleSqlBatch(
    "UPDATE SYS.NV SET luong = luong * 2 WHERE manv='NV3';",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(arithOutcome.newTriggers.length, 1);
  assert.equal(arithOutcome.newTriggers[0].ATTACK_TYPE, 'ABNORMAL_SALARY_MODIFICATION');
  assert.ok(arithOutcome.newTriggers[0].DETAILS.includes('1200'));
  assert.ok(arithOutcome.newTriggers[0].DETAILS.includes('2400'));
  assert.equal(arithOutcome.newAuditLogs[0].RETURN_CODE, 20002);

  const cmndTamperOutcome = evaluateOracleSqlBatch(
    "UPDATE SYS.NV SET cmnd = '999999999999' WHERE manv = 'NV3';",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(cmndTamperOutcome.newTriggers.length, 1);
  assert.equal(cmndTamperOutcome.newTriggers[0].ATTACK_TYPE, 'UNAUTHORIZED_DML_INTEGRITY');
  assert.equal(
    cmndTamperOutcome.newAuditLogs[0].RETURN_CODE,
    policy.trigger_codes.UNAUTHORIZED_DML_INTEGRITY
  );
  assert.equal(cmndTamperOutcome.newAuditLogs[0].RETURN_CODE, 20004);

  const hotenTamperOutcome = evaluateOracleSqlBatch(
    "UPDATE SYS.NV SET hoten = 'Fake Name' WHERE manv = 'NV3';",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(hotenTamperOutcome.newTriggers.length, 1);
  assert.equal(hotenTamperOutcome.newTriggers[0].ATTACK_TYPE, 'UNAUTHORIZED_DML_INTEGRITY');
  assert.equal(hotenTamperOutcome.newAuditLogs[0].RETURN_CODE, 20004);
});

test('masquerading baseline deviation without kali keyword produces MASQ alert (75 HIGH)', () => {
  const outcome = evaluateOracleSqlBatch(
    'SELECT hoten FROM SYS.NV;',
    'U1',
    makeCleanUsers(),
    [],
    [],
    true,
    'UNKNOWN-PC',
    'bob',
    'SQL Developer'
  );

  const masqAlert = outcome.newAlerts.find((a) => a.key.startsWith('MASQ|'));
  assert.ok(masqAlert, 'Expected MASQ alert for U1 from UNKNOWN-PC / bob');
  assert.equal(masqAlert.severity, 'HIGH');
  assert.equal(masqAlert.risk_score, policy.attack_scores.masquerading);
  assert.equal(masqAlert.risk_score, 75);

  const pureDeviationOutcome = evaluateOracleSqlBatch(
    'SELECT hoten FROM SYS.NV;',
    'U1',
    makeCleanUsers(),
    [],
    [],
    true,
    'OFFICE-PC-99',
    'bob',
    'SQL Developer'
  );
  const pureMasq = pureDeviationOutcome.newAlerts.find((a) => a.key.startsWith('MASQ|'));
  assert.ok(pureMasq, 'Expected MASQ alert for pure baseline host/os deviation');
  assert.equal(pureMasq.risk_score, 75);
});

test('dangerous DDL (DROP TABLE) and Privilege Escalation (GRANT DBA) are detected with exact policy scores', () => {
  const ddlOutcome = evaluateOracleSqlBatch(
    'DROP TABLE SYS.NV;',
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(ddlOutcome.newAlerts.length, 1);
  assert.ok(ddlOutcome.newAlerts[0].key.startsWith('DDL|'));
  assert.equal(ddlOutcome.newAlerts[0].severity, 'CRITICAL');
  assert.equal(ddlOutcome.newAlerts[0].risk_score, policy.attack_scores.ddl_destructive);
  assert.equal(ddlOutcome.newAlerts[0].risk_score, 85);

  const privOutcome = evaluateOracleSqlBatch(
    'GRANT DBA TO U4;',
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(privOutcome.newAlerts.length, 1);
  assert.ok(privOutcome.newAlerts[0].key.startsWith('PRIV|'));
  assert.equal(privOutcome.newAlerts[0].severity, 'CRITICAL');
  assert.equal(privOutcome.newAlerts[0].risk_score, policy.attack_scores.privilege_escalation);
  assert.equal(privOutcome.newAlerts[0].risk_score, 88);
});

test('multiple HIGH alerts escalate user risk from Level 2 READ-ONLY to Level 3 LOCKED without tier clamping', () => {
  let users = makeCleanUsers();
  let alerts = [] as ReturnType<typeof evaluateOracleSqlBatch>['newAlerts'];
  let triggers = [] as ReturnType<typeof evaluateOracleSqlBatch>['newTriggers'];

  // First HIGH trigger block (65) -> Level 2 READ-ONLY
  const first = evaluateOracleSqlBatch(
    "UPDATE SYS.NV SET luong = 5000 WHERE manv = 'NV3';",
    'U4',
    users,
    alerts,
    triggers,
    true
  );
  users = first.updatedUsers;
  alerts = [...first.newAlerts, ...alerts];
  triggers = [...first.newTriggers, ...triggers];

  let u4 = users.find((u) => u.USERNAME === 'U4')!;
  assert.equal(u4.RISK_SCORE, 65);
  assert.equal(u4.RESPONSE_LEVEL, 2);
  assert.equal(u4.DML_STATUS, 'READ-ONLY');
  assert.equal(u4.ACCOUNT_STATUS, 'OPEN');

  // Four subsequent READ-ONLY DML violations (each 65 HIGH): total 5 alerts -> 65 + 4*4 = 81 (Level 3 LOCKED)
  for (let i = 0; i < 4; i++) {
    const step = evaluateOracleSqlBatch(
      "UPDATE SYS.NV SET hoten = 'Bypass' WHERE manv = 'NV3';",
      'U4',
      users,
      alerts,
      triggers,
      true
    );
    users = step.updatedUsers;
    alerts = [...step.newAlerts, ...alerts];
    triggers = [...step.newTriggers, ...triggers];
  }

  u4 = users.find((u) => u.USERNAME === 'U4')!;
  assert.equal(alerts.length, 5);
  assert.equal(u4.RISK_SCORE, computeUserRiskScore(alerts.map((a) => a.risk_score)));
  assert.equal(u4.RISK_SCORE, 81);
  assert.equal(u4.RESPONSE_LEVEL, 3);
  assert.equal(u4.ACCOUNT_STATUS, 'LOCKED');
});

test('credentials in SQL (IDENTIFIED BY "...") are scrubbed before storing in auditLogs and alerts', () => {
  const secretPass = 'TopSecret!@# 2026';
  const outcome = evaluateOracleSqlBatch(
    `CREATE USER ROGUE IDENTIFIED BY "${secretPass}";`,
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );

  assert.equal(outcome.newAlerts.length, 1);
  assert.equal(outcome.newAuditLogs.length, 1);

  assert.ok(!outcome.newAlerts[0].details.includes(secretPass));
  assert.ok(outcome.newAlerts[0].details.includes('IDENTIFIED BY "••••••••"'));

  assert.ok(!outcome.newAuditLogs[0].SQL_TEXT.includes(secretPass));
  assert.ok(outcome.newAuditLogs[0].SQL_TEXT.includes('IDENTIFIED BY "••••••••"'));
});

test('userClearedAt prevents old alerts from re-locking unlocked user on benign SELECT while post-unlock attacks still trigger', () => {
  const users = makeCleanUsers();
  const historicalAlert = {
    key: 'SQLI|U1|2026-11-22 09:00:00|0',
    severity: 'CRITICAL' as const,
    risk_score: 95,
    response_level: 3 as const,
    response_label: policy.thresholds.level_3.label,
    time: '2026-11-22 09:00:00',
    user: 'U1',
    attack_type: 'SQL Injection',
    details: "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1",
    client_program: 'SQL Developer',
    userhost: 'LAPTOP-R03ORTGV',
    os_username: 'pc',
    context: 'SQL Developer (pc@LAPTOP-R03ORTGV)',
  };
  const clearedAt = { U1: '2026-11-22 10:00:00' };

  const benignRes = evaluateOracleSqlBatch(
    "SELECT MANV, HOTEN FROM SYS.NV WHERE MANV = 'NV1';",
    'U1',
    users,
    [historicalAlert],
    [],
    true,
    'LAPTOP-R03ORTGV',
    'pc',
    'SQL Developer',
    INITIAL_EMPLOYEES,
    clearedAt
  );
  assert.equal(benignRes.newAlerts.length, 0);
  const u1AfterBenign = benignRes.updatedUsers.find((u) => u.USERNAME === 'U1')!;
  assert.equal(u1AfterBenign.RISK_SCORE, 0);
  assert.equal(u1AfterBenign.RESPONSE_LEVEL, 0);
  assert.equal(u1AfterBenign.ACCOUNT_STATUS, 'OPEN');

  const attackRes = evaluateOracleSqlBatch(
    "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;",
    'U1',
    users,
    [historicalAlert],
    [],
    true,
    'LAPTOP-R03ORTGV',
    'pc',
    'SQL Developer',
    INITIAL_EMPLOYEES,
    clearedAt
  );
  assert.equal(attackRes.newAlerts.length, 1);
  assert.ok(attackRes.newAlerts[0].key.startsWith('SQLI|'));
  const u1AfterAttack = attackRes.updatedUsers.find((u) => u.USERNAME === 'U1')!;
  assert.equal(u1AfterAttack.RISK_SCORE, 95);
  assert.equal(u1AfterAttack.RESPONSE_LEVEL, 3);
  assert.equal(u1AfterAttack.ACCOUNT_STATUS, 'LOCKED');
});

test('Honeytoken and SQLi take precedence over DML_RO and Trigger DML checks', () => {
  const readOnlyUsers = makeCleanUsers().map((u) =>
    u.USERNAME === 'U4'
      ? { ...u, DML_STATUS: 'READ-ONLY' as const, PRIVILEGES: 'SELECT' }
      : u
  );

  // Honeytoken inside UPDATE on READ-ONLY user -> TRAP (95 CRITICAL), not DML_RO or TRIG
  const trapRoRes = evaluateOracleSqlBatch(
    "UPDATE SYS.NV SET luong = 10000 WHERE manv = 'NV_TRAP';",
    'U4',
    readOnlyUsers,
    [],
    [],
    true
  );
  assert.equal(trapRoRes.newAlerts.length, 1);
  assert.ok(trapRoRes.newAlerts[0].key.startsWith('TRAP|'));
  assert.equal(trapRoRes.newAlerts[0].risk_score, 95);
  assert.equal(trapRoRes.newTriggers.length, 0);

  // Honeytoken inside DELETE on FULL DML user -> TRAP (95 CRITICAL), not TRIG
  const trapTrigRes = evaluateOracleSqlBatch(
    "DELETE FROM SYS.NV WHERE manv = 'NV_TRAP';",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(trapTrigRes.newAlerts.length, 1);
  assert.ok(trapTrigRes.newAlerts[0].key.startsWith('TRAP|'));
  assert.equal(trapTrigRes.newTriggers.length, 0);

  // SQLi inside UPDATE on READ-ONLY user -> SQLI (95 CRITICAL), not DML_RO or TRIG
  const sqliRoRes = evaluateOracleSqlBatch(
    "UPDATE SYS.NV SET luong = 10000 WHERE manv = 'NV1' OR 1=1;",
    'U4',
    readOnlyUsers,
    [],
    [],
    true
  );
  assert.equal(sqliRoRes.newAlerts.length, 1);
  assert.ok(sqliRoRes.newAlerts[0].key.startsWith('SQLI|'));
  assert.equal(sqliRoRes.newAlerts[0].risk_score, 95);
  assert.equal(sqliRoRes.newTriggers.length, 0);

  // SQLi inside DELETE on FULL DML user -> SQLI (95 CRITICAL), not TRIG
  const sqliTrigRes = evaluateOracleSqlBatch(
    "DELETE FROM SYS.NV WHERE manv = 'NV1' OR 1=1;",
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(sqliTrigRes.newAlerts.length, 1);
  assert.ok(sqliTrigRes.newAlerts[0].key.startsWith('SQLI|'));
  assert.equal(sqliTrigRes.newTriggers.length, 0);
});

test('STAT_FUNC on LUONG or CMND emits FGA_SAL (35 MEDIUM) while plain COUNT(*) stays 28 LOW without FGA', () => {
  const plainCount = evaluateOracleSqlBatch(
    'SELECT COUNT(*) FROM SYS.NV;',
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(plainCount.newFgaEvents.length, 0);
  assert.equal(plainCount.newAlerts.length, 1);
  assert.ok(plainCount.newAlerts[0].key.startsWith('STAT_WARN|'));
  assert.equal(plainCount.newAlerts[0].severity, 'LOW');
  assert.equal(plainCount.newAlerts[0].risk_score, 28);

  const sumLuong = evaluateOracleSqlBatch(
    'SELECT SUM(luong) FROM SYS.NV;',
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(sumLuong.newFgaEvents.length, 1);
  assert.equal(sumLuong.newFgaEvents[0].FGA_POLICY_NAME, 'FGA_HIGH_SALARY_ACCESS');
  const luongFgaAlert = sumLuong.newAlerts.find((a) => a.key.startsWith('FGA_SAL|'));
  assert.ok(luongFgaAlert, 'Expected FGA_SAL alert for SUM(luong)');
  assert.equal(luongFgaAlert.severity, 'MEDIUM');
  assert.equal(luongFgaAlert.risk_score, 35);

  const countCmnd = evaluateOracleSqlBatch(
    'SELECT COUNT(cmnd) FROM SYS.NV;',
    'U4',
    makeCleanUsers(),
    [],
    [],
    true
  );
  assert.equal(countCmnd.newFgaEvents.length, 1);
  assert.equal(countCmnd.newFgaEvents[0].FGA_POLICY_NAME, 'FGA_HIGH_SALARY_ACCESS');
  const cmndFgaAlert = countCmnd.newAlerts.find((a) => a.key.startsWith('FGA_SAL|'));
  assert.ok(cmndFgaAlert, 'Expected FGA_SAL alert for COUNT(cmnd)');
  assert.equal(cmndFgaAlert.risk_score, 35);
});

test('detectMasquerading allows non-SQL-Developer clients on trusted host/OS and flags client only when host/OS deviates', () => {
  const sameHostOsRes = evaluateOracleSqlBatch(
    'SELECT hoten FROM SYS.NV;',
    'U1',
    makeCleanUsers(),
    [],
    [],
    true,
    'LAPTOP-R03ORTGV',
    'pc',
    'DBeaver'
  );
  assert.equal(
    sameHostOsRes.newAlerts.filter((a) => a.key.startsWith('MASQ|')).length,
    0,
    'Non-SQL-Developer client on trusted host/OS must not false-positive as masquerading'
  );

  const deviatedRes = evaluateOracleSqlBatch(
    'SELECT hoten FROM SYS.NV;',
    'U1',
    makeCleanUsers(),
    [],
    [],
    true,
    'OFFICE-PC-99',
    'pc',
    'DBeaver'
  );
  const masqAlert = deviatedRes.newAlerts.find((a) => a.key.startsWith('MASQ|'));
  assert.ok(masqAlert, 'Expected MASQ alert when host deviates from baseline');
  assert.ok(masqAlert.details.includes('USERHOST'));
  assert.ok(masqAlert.details.includes("Client 'DBeaver'"));
});
