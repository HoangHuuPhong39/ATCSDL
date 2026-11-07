import type { AlertItem, AuditLogRow, DbUser, FgaEvent, TriggerAlert } from '../types/ids.ts';
import { classifyResponseLevel } from './analytics.ts';

const SQLI_REGEX =
  /(\bOR\b\s+['"]?1['"]?\s*=\s*['"]?1|\bOR\b\s+['"][a-zA-Z0-9]+['"]\s*=\s*['"][a-zA-Z0-9]+['"]|\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|--\s*$|\/\*\s*|\bDBMS_PIPE\b|\bUTL_HTTP\b|\bUTL_INADDR\b)/i;

const HONEYTOKEN_REGEX = /(NV_TRAP|001099000000)/i;
const STAT_FUNC_REGEX = /\b(COUNT|SUM|AVG|MAX|MIN)\s*\(/i;
const CRYPTO_DIRECT_REGEX =
  /\b(V\$ENCRYPTION_KEYS|V\$ENCRYPTION_WALLET|DBA_ENCRYPTED_COLUMNS|ENC\$|USER_ENCRYPTED_COLUMNS)\b/i;
const CRYPTO_INDIRECT_REGEX =
  /\b(DBMS_CRYPTO|ADMINISTER\s+KEY\s+MANAGEMENT|UTL_I18N\.STRING_TO_RAW)\b/i;
const PRIV_ABUSE_REGEX =
  /^\s*(GRANT|REVOKE|CREATE\s+USER|ALTER\s+USER|DROP\s+USER|ALTER\s+SYSTEM|ALTER\s+DATABASE)\b/i;

export interface OracleExecutionOutcome {
  newAlerts: AlertItem[];
  newTriggers: TriggerAlert[];
  newFgaEvents: FgaEvent[];
  newAuditLogs: AuditLogRow[];
  updatedUsers: DbUser[];
  oracleOutputs: string[];
}

/**
 * Splits a SQL Developer worksheet script into executable statements,
 * ignoring SQL comment lines (-- ...).
 */
export function splitSqlStatements(sqlScript: string): string[] {
  const withoutBlockComments = sqlScript.replace(/\/\*[\s\S]*?\*\//g, '');
  const lines = withoutBlockComments
    .split(/\r?\n/)
    .map((line) => line.replace(/--.*$/, '').trim())
    .filter(Boolean);

  const combined = lines.join('\n');
  return combined
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Evaluates one or more Oracle SQL statements executed from SQL Developer / SQL*Plus
 * against the 5-layer Defense-in-Depth engine (Trigger -> FGA -> Unified Audit -> IDS -> Active IPS).
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
  customClient: string = 'SQL Developer'
): OracleExecutionOutcome {
  const statements = splitSqlStatements(sqlScript);
  const user = dbUser.trim().toUpperCase() || 'U1';
  const nowBase = new Date();

  const newAlerts: AlertItem[] = [];
  const newTriggers: TriggerAlert[] = [];
  const newFgaEvents: FgaEvent[] = [];
  const newAuditLogs: AuditLogRow[] = [];
  const oracleOutputs: string[] = [];

  let nextTrigId =
    currentTriggers.reduce((max, t) => Math.max(max, Number(t.ALERT_ID) || 0), 100) + 1;

  const statQueriesInBatch: string[] = [];

  statements.forEach((rawStmt, idx) => {
    const tsDate = new Date(nowBase.getTime() + idx * 1000);
    const nowStr = tsDate.toISOString().replace('T', ' ').substring(0, 19);
    const normSql = rawStmt.replace(/\s+/g, ' ').trim();
    const upperSql = normSql.toUpperCase();
    const ctx = `${customClient} (${customOsUser}@${customHost})`;

    // Check current user status before executing
    const targetUserObj = currentUsers.find((u) => u.USERNAME === user);
    const isCurrentlyLocked = targetUserObj?.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
    const isCurrentlyReadOnly = targetUserObj?.DML_STATUS.toUpperCase() === 'READ-ONLY';

    if (isCurrentlyLocked) {
      oracleOutputs.push(
        `ORA-28000: the account ${user} is locked (Phiên kết nối bị từ chối bởi Active IPS Level 3)`
      );
      return;
    }

    // 1. Check DML when user is already downgraded to READ-ONLY (Level 2)
    const isDml = /^(UPDATE|DELETE|INSERT)\b/i.test(normSql);
    if (isDml && isCurrentlyReadOnly) {
      const alertKey = `DML_RO|${user}|${nowStr}|${idx}`;
      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: upperSql.split(' ')[0],
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: normSql,
        RETURN_CODE: 41900,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
      });
      newAlerts.push({
        key: alertKey,
        severity: 'HIGH',
        risk_score: 65,
        response_level: 2,
        response_label: 'Level 2: HIGH (Privilege Containment)',
        time: nowStr,
        user,
        attack_type: `Vi phạm Read-Only (Hạ quyền Level 2): Cố tình thực thi ${upperSql.split(' ')[0]} (ORA-41900)`,
        details: normSql,
        client_program: customClient,
        userhost: customHost,
        os_username: customOsUser,
        audit_type: 'Standard',
        context: ctx,
      });
      oracleOutputs.push(
        `ORA-41900: missing ${upperSql.split(' ')[0]} privilege on "SYS"."NV" (Tài khoản ${user} đang bị cô lập READ-ONLY)`
      );
      return;
    }

    // 2. Check Trigger Block: DELETE FROM SYS.NV
    if (/^DELETE\s+FROM\s+(SYS\.|SYSTEM\.)?NV\b/i.test(normSql)) {
      const manvMatch = normSql.match(/MANV\s*=\s*['"]([^'"]+)['"]/i);
      const targetManv = manvMatch ? manvMatch[1].toUpperCase() : 'NV2';
      const trigDetails = `Cố tình xóa nhân viên mã: ${targetManv}`;
      const trigId = nextTrigId++;

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
        SQL_TEXT: normSql,
        RETURN_CODE: 20001,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
      });

      newAlerts.push({
        key: `TRIG|${trigId}|${user}|${nowStr}`,
        severity: 'HIGH',
        risk_score: 65,
        response_level: 2,
        response_label: 'Level 2: HIGH (Privilege Containment)',
        time: nowStr,
        user,
        attack_type: 'Trigger Block: Xóa nhân viên trái phép (ORA-20001)',
        details: `${trigDetails} · SQL: ${normSql}`,
        client_program: 'Database Trigger',
        userhost: 'SYS.TRG_PROTECT_NV',
        os_username: customOsUser,
        audit_type: 'Standard',
        context: `Database Trigger (SYS.TRG_PROTECT_NV)`,
      });

      oracleOutputs.push(
        `ORA-20001: IDS BLOCK: Ban khong duoc phep xoa du lieu nhan vien! (${targetManv}) — Đã ghi log tự trị SYS.IDS_TRIGGER_ALERTS #${trigId}`
      );
      return;
    }

    // 3. Check Trigger Block: UPDATE SYS.NV SET luong = ...
    if (/^UPDATE\s+(SYS\.|SYSTEM\.)?NV\s+SET\s+LUONG\s*=/i.test(normSql)) {
      const luongMatch = normSql.match(/LUONG\s*=\s*(\d+)/i);
      const newLuong = luongMatch ? Number(luongMatch[1]) : 10000;
      const oldLuong = 900;
      if (newLuong > oldLuong * 1.5) {
        const trigDetails = `Tăng lương bất thường từ ${oldLuong} lên ${newLuong}`;
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
          SQL_TEXT: normSql,
          RETURN_CODE: 20002,
          OS_USERNAME: customOsUser,
          USERHOST: customHost,
          CLIENT_PROGRAM_NAME: customClient,
          AUDIT_TYPE: 'Standard',
          UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
        });

        newAlerts.push({
          key: `TRIG|${trigId}|${user}|${nowStr}`,
          severity: 'HIGH',
          risk_score: 65,
          response_level: 2,
          response_label: 'Level 2: HIGH (Privilege Containment)',
          time: nowStr,
          user,
          attack_type: 'Trigger Block: Gian lận tăng lương > 50% (ORA-20002)',
          details: `${trigDetails} · SQL: ${normSql}`,
          client_program: 'Database Trigger',
          userhost: 'SYS.TRG_PROTECT_NV',
          os_username: customOsUser,
          audit_type: 'Standard',
          context: `Database Trigger (SYS.TRG_PROTECT_NV)`,
        });

        oracleOutputs.push(
          `ORA-20002: IDS BLOCK: Phat hien hanh vi gian lan tang luong vuot nguong! (${oldLuong} -> ${newLuong}) — Đã ghi log tự trị SYS.IDS_TRIGGER_ALERTS #${trigId}`
        );
        return;
      }
    }

    // 4. Check Honeytoken Trap (NV_TRAP)
    if (HONEYTOKEN_REGEX.test(normSql)) {
      newFgaEvents.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
        AUDIT_TYPE: 'FineGrainedAudit',
        SQL_TEXT: normSql,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        RETURN_CODE: 0,
      });

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: normSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'FineGrainedAudit',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
      });

      newAlerts.push({
        key: `TRAP|${user}|${nowStr}|${idx}`,
        severity: 'CRITICAL',
        risk_score: 95,
        response_level: 3,
        response_label: 'Level 3: CRITICAL (Full Isolation)',
        time: nowStr,
        user,
        attack_type: '[SDB - Direct Attack & Honeytoken] Truy cập trực tiếp dữ liệu cá nhân & chạm bẫy NV_TRAP',
        details: normSql,
        client_program: customClient,
        userhost: customHost,
        os_username: customOsUser,
        fga_policy: 'FGA_HONEYTOKEN_TRAP',
        audit_type: 'FineGrainedAudit',
        context: ctx,
      });

      oracleOutputs.push(
        `[DBMS_FGA] Kích hoạt bẫy FGA_HONEYTOKEN_TRAP! Cảnh báo CRITICAL (Risk 95/100) đã gửi về Dashboard.`
      );
      return;
    }

    // 5. Check SQL Injection (e.g. SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1)
    if (SQLI_REGEX.test(normSql)) {
      newFgaEvents.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
        AUDIT_TYPE: 'FineGrainedAudit',
        SQL_TEXT: normSql,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        RETURN_CODE: 0,
      });

      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: normSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'FineGrainedAudit',
        FGA_POLICY_NAME: 'FGA_HONEYTOKEN_TRAP',
      });

      newAlerts.push({
        key: `SQLI|${user}|${nowStr}|${idx}`,
        severity: 'CRITICAL',
        risk_score: 95,
        response_level: 3,
        response_label: 'Level 3: CRITICAL (Full Isolation)',
        time: nowStr,
        user,
        attack_type: '[DBMS - SQL Injection] Chèn mã độc làm thay đổi cấu trúc câu lệnh SQL (OR 1=1)',
        details: normSql,
        client_program: customClient,
        userhost: customHost,
        os_username: customOsUser,
        fga_policy: 'FGA_HONEYTOKEN_TRAP',
        audit_type: 'FineGrainedAudit',
        context: ctx,
      });

      oracleOutputs.push(
        `[IDS SQLi Engine] Phát hiện mẫu SQL Injection (${normSql})! Điểm rủi ro: 95/100 (Level 3 Full Isolation).`
      );
      return;
    }

    // 6. Check Unauthorized Encryption Key Access
    if (CRYPTO_DIRECT_REGEX.test(normSql) || CRYPTO_INDIRECT_REGEX.test(normSql)) {
      const isDirect = CRYPTO_DIRECT_REGEX.test(normSql);
      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: isDirect ? 'V$ENCRYPTION_KEYS' : 'DBMS_CRYPTO',
        SQL_TEXT: normSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_CRYPTO_KEY_POL',
      });

      newAlerts.push({
        key: `CRYPTO|${user}|${nowStr}|${idx}`,
        severity: 'CRITICAL',
        risk_score: 92,
        response_level: 3,
        response_label: 'Level 3: CRITICAL (Full Isolation)',
        time: nowStr,
        user,
        attack_type: `[DBMS - Key Access] Truy cập khóa mã hóa trái phép (${
          isDirect ? 'Trực tiếp kho khóa TDE' : 'Gián tiếp qua DBMS_CRYPTO'
        })`,
        details: normSql,
        client_program: customClient,
        userhost: customHost,
        os_username: customOsUser,
        audit_type: 'Standard',
        context: ctx,
      });

      oracleOutputs.push(
        `[IDS Crypto Guard] Phát hiện truy cập khóa mã hóa trái phép (Risk 92/100 - Level 3).`
      );
      return;
    }

    // 7. Check Privilege Escalation (GRANT / REVOKE / ALTER USER)
    if (PRIV_ABUSE_REGEX.test(normSql)) {
      const actionVerb = upperSql.split(' ')[0];
      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: actionVerb,
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'DBA',
        SQL_TEXT: normSql,
        RETURN_CODE: 1031,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_PRIV_ABUSE_POL',
      });

      newAlerts.push({
        key: `PRIV|${user}|${nowStr}|${idx}`,
        severity: 'CRITICAL',
        risk_score: 88,
        response_level: 3,
        response_label: 'Level 3: CRITICAL (Full Isolation)',
        time: nowStr,
        user,
        attack_type: `[DBMS - Privilege Escalation] Leo thang đặc quyền vượt mức được cấp (${actionVerb})`,
        details: normSql,
        client_program: customClient,
        userhost: customHost,
        os_username: customOsUser,
        audit_type: 'Standard',
        context: ctx,
      });

      oracleOutputs.push(
        `[IDS Privilege Watch] Phát hiện hành vi leo thang đặc quyền (${actionVerb})! Điểm rủi ro: 88/100.`
      );
      return;
    }

    // 8. Check Statistical Queries (COUNT, SUM, AVG) on SYS.NV
    if (STAT_FUNC_REGEX.test(normSql)) {
      statQueriesInBatch.push(normSql);
      newAuditLogs.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        SQL_TEXT: normSql,
        RETURN_CODE: 0,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        AUDIT_TYPE: 'Standard',
        UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
      });
      return;
    }

    // 9. Standard SELECT on SYS.NV
    newAuditLogs.push({
      EVENT_TIMESTAMP: nowStr,
      DBUSERNAME: user,
      ACTION_NAME: 'SELECT',
      OBJECT_SCHEMA: 'SYS',
      OBJECT_NAME: 'NV',
      SQL_TEXT: normSql,
      RETURN_CODE: 0,
      OS_USERNAME: customOsUser,
      USERHOST: customHost,
      CLIENT_PROGRAM_NAME: customClient,
      AUDIT_TYPE: 'Standard',
      UNIFIED_AUDIT_POLICIES: 'IDS_DML_NV_POL',
    });

    if (/LUONG\s*>=\s*1000|MANV\s*=\s*['"]NV3['"]/i.test(normSql)) {
      newFgaEvents.push({
        EVENT_TIMESTAMP: nowStr,
        DBUSERNAME: user,
        ACTION_NAME: 'SELECT',
        OBJECT_SCHEMA: 'SYS',
        OBJECT_NAME: 'NV',
        FGA_POLICY_NAME: 'FGA_HIGH_SALARY_ACCESS',
        AUDIT_TYPE: 'FineGrainedAudit',
        SQL_TEXT: normSql,
        OS_USERNAME: customOsUser,
        USERHOST: customHost,
        CLIENT_PROGRAM_NAME: customClient,
        RETURN_CODE: 0,
      });
      newAlerts.push({
        key: `FGA_SAL|${user}|${nowStr}|${idx}`,
        severity: 'MEDIUM',
        risk_score: 35,
        response_level: 1,
        response_label: 'Level 1: LOW/MED (Warning & Monitor)',
        time: nowStr,
        user,
        attack_type: '[SDB - Direct Attack] Truy cập cột nhạy cảm LUONG >= 1000 (FGA_HIGH_SALARY_ACCESS)',
        details: normSql,
        client_program: customClient,
        userhost: customHost,
        os_username: customOsUser,
        fga_policy: 'FGA_HIGH_SALARY_ACCESS',
        audit_type: 'FineGrainedAudit',
        context: ctx,
      });
      oracleOutputs.push(
        `[DBMS_FGA] Truy vấn chạm chính sách FGA_HIGH_SALARY_ACCESS (Score 35/100).`
      );
    } else {
      oracleOutputs.push(`Thực thi thành công câu lệnh chuẩn: ${normSql} (Đã ghi nhận vào UNIFIED_AUDIT_TRAIL).`);
    }
  });

  // Evaluate collected Statistical Queries (SDB Inference Engine)
  if (statQueriesInBatch.length > 0) {
    const nowStr = new Date(nowBase.getTime() + statements.length * 1000)
      .toISOString()
      .replace('T', ' ')
      .substring(0, 19);
    const ctx = `${customClient} (${customOsUser}@${customHost})`;
    const joinedSql = statQueriesInBatch.join(' ; ');
    const hasCount = statQueriesInBatch.some((s) => /COUNT\s*\(/i.test(s));
    const hasSumOrAvg = statQueriesInBatch.some((s) => /\b(SUM|AVG)\s*\(/i.test(s));
    const hasTracker = statQueriesInBatch.some((s) => /\bOR\b|!=|<>|\bNOT\b/i.test(s));
    const sumCount = statQueriesInBatch.filter((s) => /\b(SUM|AVG)\s*\(/i.test(s)).length;

    let sdbType =
      '[SDB - Count-based Attack] Tấn công suy diễn thống kê kết hợp COUNT và SUM/AVG';
    let sdbScore = 65;

    if (hasTracker && statQueriesInBatch.length >= 2) {
      sdbType =
        '[SDB - Tracker Attack] Tấn công trình theo dõi lách kiểm soát kích cỡ tập truy vấn';
      sdbScore = 70;
    } else if (sumCount >= 3) {
      sdbType =
        '[SDB - Linear System Attack] Thiết lập hệ phương trình tuyến tính A*X = B từ chuỗi SUM/AVG';
      sdbScore = 72;
    } else if (hasCount && hasSumOrAvg) {
      sdbType =
        '[SDB - Count-based Attack] Tấn công dựa vào đếm kết hợp COUNT và SUM/AVG làm lộ lương cá nhân';
      sdbScore = 65;
    } else if (statQueriesInBatch.length >= 3) {
      sdbType =
        '[SDB - Count-based Attack] Thực hiện chuỗi truy vấn thống kê liên tiếp dò tìm dữ liệu cá nhân';
      sdbScore = 65;
    }

    newAlerts.push({
      key: `STAT_INF|${user}|${nowStr}|${statQueriesInBatch.length}`,
      severity: 'HIGH',
      risk_score: sdbScore,
      response_level: 2,
      response_label: 'Level 2: HIGH (Privilege Containment)',
      time: nowStr,
      user,
      attack_type: sdbType,
      details: `Phát hiện ${statQueriesInBatch.length} truy vấn hàm thống kê SDB: ${joinedSql}`,
      client_program: customClient,
      userhost: customHost,
      os_username: customOsUser,
      audit_type: 'Standard',
      context: ctx,
    });

    oracleOutputs.push(
      `[IDS SDB Inference Engine] Phát hiện ${sdbType} (${statQueriesInBatch.length} truy vấn thống kê)! Điểm rủi ro: ${sdbScore}/100.`
    );
  }

  // Recalculate User Risk & Apply Active IPS Response
  const allAlerts = [...newAlerts, ...currentAlerts];
  const updatedUsers = currentUsers.map((u) => {
    if (u.USERNAME !== user) return u;
    const userAlerts = allAlerts.filter((a) => a.user === user);
    if (userAlerts.length === 0) return u;

    const scores = userAlerts.map((a) => a.risk_score);
    const maxScore = Math.max(...scores);
    const bonus = Math.min(14, (scores.length - 1) * 4);
    const totalScore =
      maxScore < 50
        ? Math.min(49, maxScore + bonus)
        : maxScore < 80
        ? Math.min(79, maxScore + bonus)
        : Math.min(100, maxScore + bonus);

    const { level, label } = classifyResponseLevel(totalScore);
    const nowStr = nowBase.toISOString().replace('T', ' ').substring(0, 19);

    let acctStatus = u.ACCOUNT_STATUS;
    let dmlStatus = u.DML_STATUS;
    let privs = u.PRIVILEGES;
    let lockDate = u.LOCK_DATE;

    if (autoResponse) {
      if (level === 3) {
        acctStatus = 'LOCKED';
        dmlStatus = 'READ-ONLY';
        privs = 'SELECT';
        lockDate = nowStr;
      } else if (level === 2 && !acctStatus.includes('LOCK')) {
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
