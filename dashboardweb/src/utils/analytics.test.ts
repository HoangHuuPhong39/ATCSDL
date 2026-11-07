import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyAlertGroup,
  computeAttackBreakdown,
  calculateSystemMetrics,
  buildAttackHeatmapMatrix,
  getTimeBucketLabel,
  recalculateUsersAfterReset,
} from './analytics';
import {
  sanitizeSqlCredentials,
  maskUsername,
  maskHost,
  maskCmnd,
} from './privacy';
import { evaluateOracleSqlBatch } from './oracleDetector';
import {
  buildPdfReportModel,
  wrapTextByChars,
  buildPdfBinaryFromJpegPages,
} from './pdfExporter';
import { INITIAL_ALERTS, INITIAL_AUDIT_LOGS, INITIAL_USERS } from '../data/initialData';

test('classifyAlertGroup distinguishes DBMS technical attacks from SDB inference attacks', () => {
  assert.equal(
    classifyAlertGroup({
      attack_type: '[DBMS - SQL Injection] Chèn mã độc làm thay đổi cấu trúc câu lệnh SQL',
      details: "SELECT * FROM SYS.NV WHERE MANV = 'NV1' OR '1'='1'",
    }),
    'DBMS'
  );

  assert.equal(
    classifyAlertGroup({
      attack_type: '[SDB - Tracker Attack] Tấn công trình theo dõi lách kiểm soát kích cỡ tập truy vấn',
      details: 'SELECT SUM(LUONG) FROM SYS.NV',
    }),
    'SDB'
  );
});

test('computeAttackBreakdown accurately counts all 10 DBMS and SDB attack techniques', () => {
  const summary = computeAttackBreakdown(INITIAL_ALERTS);
  assert.equal(summary.total, INITIAL_ALERTS.length);
  assert.equal(summary.dbmsCount + summary.sdbCount, summary.total);
  assert.ok(summary.dbmsCount >= 5, 'Should have at least 5 DBMS technical attack alerts');
  assert.ok(summary.sdbCount >= 4, 'Should have at least 4 SDB inference attack alerts');
  assert.equal(summary.dbmsPercent + summary.sdbPercent, 100);
});

test('calculateSystemMetrics computes locked, readonly, and max_risk accurately', () => {
  const metrics = calculateSystemMetrics(15, 11, 4, 8, INITIAL_USERS);
  assert.equal(metrics.audit_count, 15);
  assert.equal(metrics.alert_count, 11);
  assert.ok(metrics.locked_count >= 1);
  assert.ok(metrics.readonly_count >= 1);
  assert.equal(metrics.max_risk, 95);
});

test('buildAttackHeatmapMatrix builds complete user x timeSlot Recharts matrix with intensity scores', () => {
  assert.equal(getTimeBucketLabel('2026-11-06 14:09:59'), '14:05–14:09');
  assert.equal(getTimeBucketLabel('2026-11-06 00:08:58'), '00:05–00:09');

  const matrix = buildAttackHeatmapMatrix(INITIAL_ALERTS, INITIAL_USERS, 'ALL');
  assert.equal(matrix.users.length, 4);
  assert.ok(matrix.timeSlots.length >= 6);
  assert.equal(matrix.points.length, matrix.users.length * matrix.timeSlots.length);

  const activeCells = matrix.points.filter((p) => p.intensity > 0);
  assert.ok(activeCells.length >= 5, 'Should have multiple active attack cells across users and time slots');
  assert.ok(matrix.peakCell && matrix.peakCell.intensity >= 95);
});

test('recalculateUsersAfterReset resets user risk and restores privileges when alerts are cleared after review', () => {
  const allCleared = recalculateUsersAfterReset(INITIAL_USERS, []);
  for (const u of allCleared) {
    assert.equal(u.RISK_SCORE, 0);
    assert.equal(u.RESPONSE_LEVEL, 0);
    assert.equal(u.ACCOUNT_STATUS, 'OPEN');
    assert.equal(u.DML_STATUS, 'FULL DML');
  }

  const onlyU3Alerts = INITIAL_ALERTS.filter((a) => a.user === 'U3');
  const partialReset = recalculateUsersAfterReset(INITIAL_USERS, onlyU3Alerts);
  const u1 = partialReset.find((u) => u.USERNAME === 'U1')!;
  const u3 = partialReset.find((u) => u.USERNAME === 'U3')!;
  assert.equal(u1.RISK_SCORE, 0);
  assert.equal(u1.ACCOUNT_STATUS, 'OPEN');
  assert.ok(u3.RISK_SCORE >= 65);
  assert.equal(u3.RESPONSE_LEVEL, 2);
});

test('privacy helpers redact plain-text passwords and mask sensitive usernames, hosts, and CMND', () => {
  const rawSql = "CREATE USER U1 IDENTIFIED BY U1123; CONNECT U1/SecretPass@localhost:1521/FREEPDB1";
  const sanitized = sanitizeSqlCredentials(rawSql);
  assert.ok(!sanitized.includes('U1123'), 'Plain-text password should be redacted');
  assert.ok(!sanitized.includes('SecretPass'), 'Connection password should be redacted');

  assert.equal(maskUsername('U1', true), 'U••1');
  assert.equal(maskUsername('U1', false), 'U1');
  assert.equal(maskHost('LAPTOP-R03ORTGV', true), 'LAP••••GV');
  assert.equal(maskCmnd('001206012345', true), '001••••••45');
});

test('evaluateOracleSqlBatch detects real Oracle SQL Developer commands from User_U1.sql', () => {
  const userU1Worksheet = `
    UPDATE SYS.NV SET luong = 10000 WHERE manv = 'NV1';
    DELETE FROM SYS.NV WHERE manv = 'NV2';
    SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;
    SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam';
    SELECT COUNT(*) FROM SYS.NV WHERE luong > 900;
    SELECT SUM(luong) FROM SYS.NV WHERE luong > 900;
    SELECT AVG(luong) FROM SYS.NV WHERE gioitinh = 'Nu';
  `;

  const res = evaluateOracleSqlBatch(
    userU1Worksheet,
    'U4',
    INITIAL_USERS,
    [],
    [],
    true,
    'LAPTOP-R03ORTGV',
    'pc',
    'SQL Developer'
  );

  assert.ok(res.newTriggers.length >= 2, 'Should trigger ORA-20002 salary fraud and ORA-20001 unauthorized delete');
  assert.ok(res.newAlerts.length >= 3, 'Should generate alerts for Trigger blocks, SQL Injection, and SDB Inference');
  const u4 = res.updatedUsers.find((u) => u.USERNAME === 'U4')!;
  assert.ok(u4.RISK_SCORE >= 95);
  assert.equal(u4.ACCOUNT_STATUS, 'LOCKED');
});

test('buildPdfReportModel and buildPdfBinaryFromJpegPages generate valid PDF 1.4 security reports with privacy masking', () => {
  const metrics = calculateSystemMetrics(
    INITIAL_AUDIT_LOGS.length,
    INITIAL_ALERTS.length,
    2,
    3,
    INITIAL_USERS
  );

  const fullModel = buildPdfReportModel(
    {
      metrics,
      users: INITIAL_USERS,
      alerts: INITIAL_ALERTS,
      auditLogs: INITIAL_AUDIT_LOGS,
    },
    {
      scope: 'full',
      privacyMode: true,
      reportCode: 'SOC-TEST-2026',
    }
  );

  assert.equal(fullModel.alertRows.length, INITIAL_ALERTS.length);
  assert.equal(fullModel.auditRows.length, INITIAL_AUDIT_LOGS.length);
  assert.equal(fullModel.alertRows[0].user, 'U••1');
  assert.equal(fullModel.auditRows[0].dbUser, 'U••1');

  const alertsOnlyModel = buildPdfReportModel(
    {
      metrics,
      users: INITIAL_USERS,
      alerts: INITIAL_ALERTS,
      auditLogs: INITIAL_AUDIT_LOGS,
    },
    {
      scope: 'alerts',
      privacyMode: false,
    }
  );
  assert.equal(alertsOnlyModel.alertRows.length, INITIAL_ALERTS.length);
  assert.equal(alertsOnlyModel.auditRows.length, 0);
  assert.equal(alertsOnlyModel.alertRows[0].user, 'U1');

  const wrapped = wrapTextByChars(
    "SELECT * FROM V$ENCRYPTION_KEYS UNION ALL SELECT DBMS_CRYPTO.DECRYPT(cmnd, 4353, master_key) FROM SYS.NV",
    40
  );
  assert.ok(wrapped.length >= 2);

  // Verify PDF 1.4 binary structure
  const fakeJpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xd9]);
  const pdfBytes = buildPdfBinaryFromJpegPages([
    { jpegBytes: fakeJpeg, widthPx: 1240, heightPx: 1754 },
  ]);
  const textDecoder = new TextDecoder();
  const pdfText = textDecoder.decode(pdfBytes);
  assert.ok(pdfText.startsWith('%PDF-1.4'), 'PDF binary should start with %PDF-1.4 header');
  assert.ok(pdfText.includes('/Type /Catalog'), 'PDF binary should contain Catalog object');
  assert.ok(pdfText.includes('/Filter /DCTDecode'), 'PDF binary should embed JPEG stream');
  assert.ok(pdfText.trim().endsWith('%%EOF'), 'PDF binary should end with %%EOF');
});

