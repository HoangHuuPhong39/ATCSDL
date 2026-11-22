import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyAlertGroup,
  computeAttackBreakdown,
  computeUserRiskScore,
  calculateSystemMetrics,
  buildAttackHeatmapMatrix,
  getTimeBucketLabel,
  recalculateUsersAfterReset,
} from './analytics.ts';
import {
  sanitizeSqlCredentials,
  redactSensitiveDetails,
  maskUsername,
  maskHost,
  maskCmnd,
} from './privacy.ts';
import { evaluateOracleSqlBatch } from './oracleDetector.ts';
import {
  buildPdfReportModel,
  wrapTextByChars,
  buildPdfBinaryFromJpegPages,
  renderPdfReportPages,
} from './pdfExporter.ts';
import { INITIAL_ALERTS, INITIAL_AUDIT_LOGS, INITIAL_USERS } from '../data/initialData.ts';

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

test('computeAttackBreakdown accurately counts all DBMS and SDB attack techniques without duplication', () => {
  const summary = computeAttackBreakdown(INITIAL_ALERTS);
  assert.equal(summary.total, INITIAL_ALERTS.length);
  assert.equal(summary.dbmsCount + summary.sdbCount, summary.total);
  assert.ok(summary.dbmsCount >= 5, 'Should have at least 5 DBMS technical attack alerts');
  assert.ok(summary.sdbCount >= 4, 'Should have at least 4 SDB inference attack alerts');
  assert.equal(summary.dbmsPercent + summary.sdbPercent, 100);

  const dbmsTechSum = summary.byTechnique
    .filter((t) => t.group === 'DBMS')
    .reduce((acc, t) => acc + t.count, 0);
  const sdbTechSum = summary.byTechnique
    .filter((t) => t.group === 'SDB')
    .reduce((acc, t) => acc + t.count, 0);

  assert.equal(dbmsTechSum, summary.dbmsCount);
  assert.equal(sdbTechSum, summary.sdbCount);
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
  // U3 has 3 alerts [70, 65, 72] -> 72 + 2*4 = 80 (Level 3 LOCKED without tier clamping)
  assert.equal(u3.RISK_SCORE, 80);
  assert.equal(u3.RESPONSE_LEVEL, 3);
  assert.equal(u3.ACCOUNT_STATUS, 'LOCKED');
});

test('computeUserRiskScore escalates across tiers without clamping and autoResponse=false preserves account locks', () => {
  // 5 alerts of 65 -> 65 + (5 - 1) * 4 = 81 (escalates past 79 without tier clamping)
  assert.equal(computeUserRiskScore([65, 65, 65, 65, 65]), 81);
  // 6 alerts of 65 -> 65 + min(20, 5 * 4) = 85 (hits bonus_cap = 20)
  assert.equal(computeUserRiskScore([65, 65, 65, 65, 65, 65]), 85);

  const resetWithoutAutoResponse = recalculateUsersAfterReset(INITIAL_USERS, [], false);
  for (let i = 0; i < INITIAL_USERS.length; i++) {
    const before = INITIAL_USERS[i];
    const after = resetWithoutAutoResponse[i];
    assert.equal(after.RISK_SCORE, 0);
    assert.equal(after.RESPONSE_LEVEL, 0);
    assert.equal(after.ACCOUNT_STATUS, before.ACCOUNT_STATUS);
    assert.equal(after.DML_STATUS, before.DML_STATUS);
    assert.equal(after.PRIVILEGES, before.PRIVILEGES);
  }
});

test('privacy helpers redact plain-text and quoted passwords and mask PII/context while preserving employee IDs', () => {
  const rawSql = "CREATE USER U1 IDENTIFIED BY U1123; CONNECT U1/SecretPass@localhost:1521/FREEPDB1";
  const sanitized = sanitizeSqlCredentials(rawSql);
  assert.ok(!sanitized.includes('U1123'), 'Plain-text password should be redacted');
  assert.ok(!sanitized.includes('SecretPass'), 'Connection password should be redacted');

  const connShortSql = 'CONN u1/secret@FREEPDB1; CONNECTION_CHECK=1';
  const sanitizedConn = sanitizeSqlCredentials(connShortSql);
  assert.ok(!sanitizedConn.includes('secret'), 'CONN abbreviation password should be redacted');
  assert.equal(sanitizedConn, 'CONN u1/••••••••@FREEPDB1; CONNECTION_CHECK=1');

  const connShortMasked = sanitizeSqlCredentials('CONN u1/"My Secret"@FREEPDB1', true);
  assert.ok(!connShortMasked.includes('My Secret'));
  assert.equal(connShortMasked, 'CONN u••1/••••••••@FREEPDB1');

  const quotedCredSql = 'CREATE USER U1 IDENTIFIED BY "My Pass!@#1"';
  const sanitizedQuoted = sanitizeSqlCredentials(quotedCredSql);
  assert.ok(!sanitizedQuoted.includes('My Pass!@#1'), 'Quoted password with spaces/symbols should be redacted');
  assert.equal(sanitizedQuoted, 'CREATE USER U1 IDENTIFIED BY "••••••••"');

  assert.equal(maskUsername('U1', true), 'U••1');
  assert.equal(maskUsername('U1', false), 'U1');
  assert.equal(maskHost('LAPTOP-R03ORTGV', true), 'LAP••••GV');
  assert.equal(maskCmnd('001206012345', true), '001••••••45');

  const sensitiveText =
    'User U1 from pc@LAPTOP-R03ORTGV (192.168.56.109) queried NV1, NV_TRAP with CMND 001206012345; CREATE USER U1 IDENTIFIED BY "My Pass!@#1"';
  const redacted = redactSensitiveDetails(sensitiveText, true, ['U1', 'NV1', 'NV_TRAP']);
  assert.ok(!redacted.includes('001206012345'), 'CMND should be masked in privacyMode');
  assert.ok(redacted.includes('001••••••45'), 'Masked CMND format should appear');
  assert.ok(!redacted.includes('192.168.56.109'), 'IPv4 should be masked in privacyMode');
  assert.ok(redacted.includes('192.•••.•••.109'), 'Masked IPv4 format should appear');
  assert.ok(!redacted.includes('pc@LAPTOP-R03ORTGV'), 'os@host should be masked in privacyMode');
  assert.ok(!redacted.includes('My Pass!@#1'), 'Password should be scrubbed');
  assert.ok(/\bU••1\b/.test(redacted), 'Known DB username U1 should be masked');
  assert.ok(redacted.includes('NV1'), 'Employee ID NV1 must remain visible');
  assert.ok(redacted.includes('NV_TRAP'), 'Employee ID NV_TRAP must remain visible');

  const unmasked = redactSensitiveDetails(sensitiveText, false, ['U1']);
  assert.ok(!unmasked.includes('My Pass!@#1'), 'Passwords must be scrubbed even when privacyMode=false');
  assert.ok(unmasked.includes('001206012345'));
  assert.ok(unmasked.includes('192.168.56.109'));
  assert.ok(unmasked.includes('pc@LAPTOP-R03ORTGV'));
  assert.ok(/\bU1\b/.test(unmasked));
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

test('renderPdfReportPages redraws Alerts and Audit headers on multi-page breaks and clamps long audit context', () => {
  const drawnTexts: string[] = [];
  const fakeJpegBase64 = Buffer.from([0xff, 0xd8, 0xff, 0xd9]).toString('base64');
  const origDocument = (globalThis as Record<string, unknown>).document;

  (globalThis as Record<string, unknown>).document = {
    createElement: (tag: string) => {
      assert.equal(tag, 'canvas');
      return {
        width: 0,
        height: 0,
        getContext: () => ({
          fillStyle: '',
          strokeStyle: '',
          lineWidth: 1,
          font: '',
          fillRect: () => {},
          strokeRect: () => {},
          setLineDash: () => {},
          fillText: (text: string) => {
            drawnTexts.push(String(text));
          },
        }),
        toDataURL: () => `data:image/jpeg;base64,${fakeJpegBase64}`,
      };
    },
  };

  try {
    const manyAlerts = Array.from({ length: 40 }, (_, i) => ({
      ...INITIAL_ALERTS[0],
      key: `ALERT_PAGE_${i}`,
      time: `2026-11-22 10:00:${String(i % 60).padStart(2, '0')}`,
    }));
    const longContextClient = 'VeryLongCustomOracleSqlClientProgramNameExceedingColumnWidth';
    const manyAudits = Array.from({ length: 40 }, (_, i) => ({
      ...INITIAL_AUDIT_LOGS[0],
      EVENT_TIMESTAMP: `2026-11-22 10:01:${String(i % 60).padStart(2, '0')}`,
      CLIENT_PROGRAM_NAME: i === 0 ? longContextClient : 'SQL Developer',
      OS_USERNAME: i === 0 ? 'very_long_os_username_identifier' : 'pc',
      USERHOST: i === 0 ? 'VERY-LONG-WORKSTATION-HOSTNAME-0123456789' : 'LAPTOP-R03ORTGV',
    }));

    const metrics = calculateSystemMetrics(
      manyAudits.length,
      manyAlerts.length,
      1,
      1,
      INITIAL_USERS
    );
    const model = buildPdfReportModel(
      {
        metrics,
        users: INITIAL_USERS,
        alerts: manyAlerts,
        auditLogs: manyAudits,
      },
      {
        scope: 'full',
        privacyMode: false,
        reportCode: 'SOC-MULTIPAGE-TEST',
      }
    );

    const { pageDataUrls, pdfBytes } = renderPdfReportPages(model);
    assert.ok(pageDataUrls.length >= 4, `Expected multi-page PDF, got ${pageDataUrls.length} pages`);

    const pdfText = new TextDecoder().decode(pdfBytes);
    assert.ok(pdfText.startsWith('%PDF-1.4'));
    assert.ok(pdfText.trim().endsWith('%%EOF'));

    const alertsHeadersCount = drawnTexts.filter(
      (t) => t === 'Loại Tấn công & Câu lệnh SQL Vi phạm'
    ).length;
    const auditHeadersCount = drawnTexts.filter(
      (t) => t === 'Ngữ cảnh & Câu lệnh SQL (SQL_TEXT)'
    ).length;
    assert.ok(
      alertsHeadersCount >= 2,
      `Alerts table header should repeat after page break (saw ${alertsHeadersCount})`
    );
    assert.ok(
      auditHeadersCount >= 2,
      `Audit table header should repeat after page break (saw ${auditHeadersCount})`
    );

    assert.ok(
      !drawnTexts.some((t) => t.includes(longContextClient + ' (very_long_os_username_identifier')),
      'Long audit context must be clamped before overflowing column'
    );
    const clampedCtxDraw = drawnTexts.find((t) =>
      t.startsWith(`Ngữ cảnh: ${longContextClient.slice(0, 39)}`)
    );
    assert.ok(clampedCtxDraw, 'Clamped audit context should end with ellipsis');
    assert.ok(clampedCtxDraw.endsWith('...'));
    assert.ok(clampedCtxDraw.length <= 52);
  } finally {
    if (origDocument === undefined) {
      delete (globalThis as Record<string, unknown>).document;
    } else {
      (globalThis as Record<string, unknown>).document = origDocument;
    }
  }
});

