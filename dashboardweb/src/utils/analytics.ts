import policy from '../../../shared/detection_policy.json' with { type: 'json' };
import type { AlertItem, DbUser, Metrics } from '../types/ids.ts';

export type AttackGroup = 'DBMS' | 'SDB';

export type AttackTechniqueId =
  | 'sqli'
  | 'masquerade'
  | 'priv_escalation'
  | 'failed_logins'
  | 'crypto_key'
  | 'ddl_dml_ro'
  | 'behavioral'
  | 'trigger_dml'
  | 'sdb_direct'
  | 'sdb_count'
  | 'sdb_tracker'
  | 'sdb_linear';

export interface AttackBreakdown {
  total: number;
  dbmsCount: number;
  sdbCount: number;
  dbmsPercent: number;
  sdbPercent: number;
  criticalCount: number;
  highCount: number;
  mediumLowCount: number;
  byTechnique: {
    id: string;
    label: string;
    group: AttackGroup;
    count: number;
  }[];
}

export interface HeatmapCellPoint {
  xIndex: number;
  yIndex: number;
  timeSlot: string;
  user: string;
  intensity: number;
  eventCount: number;
  maxRisk: number;
  dbmsCount: number;
  sdbCount: number;
  topAttack: string;
  levelLabel: string;
  fill: string;
  stroke: string;
  sampleAlert?: AlertItem;
}

export interface HeatmapMatrixResult {
  users: string[];
  timeSlots: string[];
  points: HeatmapCellPoint[];
  peakCell: HeatmapCellPoint | null;
}

const TECHNIQUE_CATALOG: Record<AttackTechniqueId, { label: string; group: AttackGroup }> = {
  sqli: { label: 'SQL Injection', group: 'DBMS' },
  masquerade: { label: 'Giả mạo / Giả danh (Masquerading)', group: 'DBMS' },
  priv_escalation: { label: 'Leo thang đặc quyền (Privilege Escalation)', group: 'DBMS' },
  failed_logins: { label: 'Đăng nhập thất bại (Brute-Force)', group: 'DBMS' },
  crypto_key: { label: 'Truy cập khóa mã hóa trái phép', group: 'DBMS' },
  ddl_dml_ro: { label: 'DDL trái phép & Vi phạm Read-Only', group: 'DBMS' },
  behavioral: { label: 'Bất thường hành vi & Công cụ (Bulk / Client)', group: 'DBMS' },
  trigger_dml: { label: 'Gian lận / Phá hoại dữ liệu (Trigger)', group: 'DBMS' },
  sdb_direct: { label: '[SDB] Tấn công trực tiếp & Honeytoken', group: 'SDB' },
  sdb_count: { label: '[SDB] Tấn công dựa vào đếm & Thăm dò thống kê', group: 'SDB' },
  sdb_tracker: { label: '[SDB] Tấn công trình theo dõi (Tracker)', group: 'SDB' },
  sdb_linear: { label: '[SDB] Tấn công hệ tuyến tính (A·X=B)', group: 'SDB' },
};

function classifyTechniqueFromPrefix(
  keyUpper: string,
  attackUpper: string,
  detailsUpper: string
): AttackTechniqueId | null {
  if (!keyUpper) return null;
  if (keyUpper.startsWith('SQLI|')) return 'sqli';
  if (keyUpper.startsWith('TRAP|') || keyUpper.startsWith('FGA_SAL|')) return 'sdb_direct';
  if (keyUpper.startsWith('CRYPTO|')) return 'crypto_key';
  if (keyUpper.startsWith('PRIV|')) return 'priv_escalation';
  if (keyUpper.startsWith('BF|')) return 'failed_logins';
  if (keyUpper.startsWith('MASQ|')) return 'masquerade';
  if (keyUpper.startsWith('DDL|') || keyUpper.startsWith('DML_RO|')) return 'ddl_dml_ro';
  if (keyUpper.startsWith('BULK|') || keyUpper.startsWith('CLIENT|')) return 'behavioral';
  if (keyUpper.startsWith('SDB_TRACKER|')) return 'sdb_tracker';
  if (keyUpper.startsWith('SDB_LINEAR|')) return 'sdb_linear';
  if (
    keyUpper.startsWith('SDB_COUNT|') ||
    keyUpper.startsWith('STAT_COUNT_SUM|') ||
    keyUpper.startsWith('STAT_WARN|')
  ) {
    return 'sdb_count';
  }
  if (keyUpper.startsWith('STAT_INF|')) {
    const combined = `${attackUpper} ${detailsUpper}`;
    if (
      combined.includes('LINEAR') ||
      combined.includes('TUYẾN TÍNH') ||
      combined.includes('A*X') ||
      combined.includes('A·X')
    ) {
      return 'sdb_linear';
    }
    if (combined.includes('TRACKER') || combined.includes('TRÌNH THEO DÕI')) {
      return 'sdb_tracker';
    }
    return 'sdb_count';
  }
  if (keyUpper.startsWith('TRIG|')) {
    if (attackUpper.includes('HONEYTOKEN') || attackUpper.includes('NV_TRAP')) {
      return 'sdb_direct';
    }
    if (attackUpper.includes('SQL INJECTION') || attackUpper.includes('SQL_INJECTION')) {
      return 'sqli';
    }
    return 'trigger_dml';
  }
  if (keyUpper.startsWith('SDB_')) {
    return 'sdb_count';
  }
  return null;
}

function classifyTechniqueFromText(
  attackUpper: string,
  detailsUpper: string
): AttackTechniqueId {
  // Prioritize attack_type metadata before inspecting raw SQL details
  if (attackUpper.includes('SQL INJECTION') || attackUpper.includes('SQLI')) return 'sqli';
  if (
    attackUpper.includes('MASQUERAD') ||
    attackUpper.includes('GIẢ MẠO') ||
    attackUpper.includes('GIẢ DANH')
  ) {
    return 'masquerade';
  }
  if (
    attackUpper.includes('PRIVILEGE') ||
    attackUpper.includes('LEO THANG') ||
    attackUpper.includes('GRANT DBA')
  ) {
    return 'priv_escalation';
  }
  if (
    attackUpper.includes('BRUTE-FORCE') ||
    attackUpper.includes('FAILED LOGIN') ||
    attackUpper.includes('ĐĂNG NHẬP THẤT BẠI') ||
    attackUpper.includes('ORA-01017')
  ) {
    return 'failed_logins';
  }
  if (
    attackUpper.includes('KEY ACCESS') ||
    attackUpper.includes('ENCRYPTION KEY') ||
    attackUpper.includes('KHÓA MÃ HÓA')
  ) {
    return 'crypto_key';
  }
  if (
    attackUpper.includes('UNAUTHORIZED DDL') ||
    attackUpper.includes('DDL') ||
    attackUpper.includes('READ-ONLY') ||
    attackUpper.includes('ORA-41900')
  ) {
    return 'ddl_dml_ro';
  }
  if (
    attackUpper.includes('BULK QUERY') ||
    attackUpper.includes('BEHAVIORAL') ||
    attackUpper.includes('CONTEXTUAL ANOMALY') ||
    attackUpper.includes('CÔNG CỤ KẾT NỐI')
  ) {
    return 'behavioral';
  }
  if (
    attackUpper.includes('LINEAR SYSTEM') ||
    attackUpper.includes('HỆ TUYẾN TÍNH') ||
    attackUpper.includes('HỆ PHƯƠNG TRÌNH')
  ) {
    return 'sdb_linear';
  }
  if (attackUpper.includes('TRACKER') || attackUpper.includes('TRÌNH THEO DÕI')) {
    return 'sdb_tracker';
  }
  if (
    attackUpper.includes('COUNT-BASED') ||
    attackUpper.includes('DỰA VÀO ĐẾM') ||
    attackUpper.includes('STATISTICAL INFERENCE') ||
    attackUpper.includes('STATISTICAL PROBE') ||
    attackUpper.includes('THĂM DÒ THỐNG KÊ') ||
    attackUpper.includes('SUY DIỄN THỐNG KÊ')
  ) {
    return 'sdb_count';
  }
  if (
    attackUpper.includes('DIRECT ATTACK') ||
    attackUpper.includes('HONEYTOKEN') ||
    attackUpper.includes('FGA_HIGH_SALARY_ACCESS') ||
    attackUpper.includes('TRỰC TIẾP')
  ) {
    return 'sdb_direct';
  }
  if (
    attackUpper.includes('TRIGGER') ||
    attackUpper.includes('ORA-20001') ||
    attackUpper.includes('ORA-20002') ||
    attackUpper.includes('ORA-20004')
  ) {
    return 'trigger_dml';
  }

  // Fallback inspection on details when attack_type is generic
  if (detailsUpper.includes('OR 1=1') || detailsUpper.includes("OR '1'='1'")) return 'sqli';
  if (detailsUpper.includes('ENCRYPTION_KEYS') || detailsUpper.includes('DBMS_CRYPTO')) {
    return 'crypto_key';
  }
  if (detailsUpper.includes('GRANT DBA')) return 'priv_escalation';
  if (detailsUpper.includes('A*X') || detailsUpper.includes('A·X')) return 'sdb_linear';
  if (detailsUpper.includes('COUNT = 1') || detailsUpper.includes('COUNT(*)')) return 'sdb_count';
  if (detailsUpper.includes('NV_TRAP') || detailsUpper.includes('001099000000')) {
    return 'sdb_direct';
  }

  if (
    attackUpper.includes('[SDB') ||
    attackUpper.includes('SDB ') ||
    attackUpper.includes('SUY DIỄN')
  ) {
    return 'sdb_count';
  }

  return 'trigger_dml';
}

/**
 * Classifies an alert into a single canonical attack technique ID, using `key` prefix first
 * and falling back to `attack_type` / `details` text classification.
 */
export function classifyAttackTechnique(
  alert: Pick<AlertItem, 'attack_type' | 'details'> & Partial<Pick<AlertItem, 'key'>>
): AttackTechniqueId {
  const keyUpper = (alert.key || '').trim().toUpperCase();
  const attackUpper = (alert.attack_type || '').toUpperCase();
  const detailsUpper = (alert.details || '').toUpperCase();

  return (
    classifyTechniqueFromPrefix(keyUpper, attackUpper, detailsUpper) ??
    classifyTechniqueFromText(attackUpper, detailsUpper)
  );
}

/**
 * Classifies an alert into DBMS Technical Attack or SDB Inference Attack
 * consistently with `computeAttackBreakdown`.
 */
export function classifyAlertGroup(
  alert: Pick<AlertItem, 'attack_type' | 'details'> & Partial<Pick<AlertItem, 'key'>>
): AttackGroup {
  const techId = classifyAttackTechnique(alert);
  return TECHNIQUE_CATALOG[techId].group;
}

/**
 * Computes non-duplicated statistical breakdown of alerts for SOC analytics.
 * Guarantees `dbmsCount + sdbCount === total` and exact group-to-technique summation.
 */
export function computeAttackBreakdown(alerts: AlertItem[]): AttackBreakdown {
  const total = alerts.length;
  let dbmsCount = 0;
  let sdbCount = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumLowCount = 0;

  const techCounters: Record<
    AttackTechniqueId,
    { label: string; group: AttackGroup; count: number }
  > = {
    sqli: { ...TECHNIQUE_CATALOG.sqli, count: 0 },
    masquerade: { ...TECHNIQUE_CATALOG.masquerade, count: 0 },
    priv_escalation: { ...TECHNIQUE_CATALOG.priv_escalation, count: 0 },
    failed_logins: { ...TECHNIQUE_CATALOG.failed_logins, count: 0 },
    crypto_key: { ...TECHNIQUE_CATALOG.crypto_key, count: 0 },
    ddl_dml_ro: { ...TECHNIQUE_CATALOG.ddl_dml_ro, count: 0 },
    behavioral: { ...TECHNIQUE_CATALOG.behavioral, count: 0 },
    trigger_dml: { ...TECHNIQUE_CATALOG.trigger_dml, count: 0 },
    sdb_direct: { ...TECHNIQUE_CATALOG.sdb_direct, count: 0 },
    sdb_count: { ...TECHNIQUE_CATALOG.sdb_count, count: 0 },
    sdb_tracker: { ...TECHNIQUE_CATALOG.sdb_tracker, count: 0 },
    sdb_linear: { ...TECHNIQUE_CATALOG.sdb_linear, count: 0 },
  };

  for (const a of alerts) {
    const techId = classifyAttackTechnique(a);
    techCounters[techId].count++;

    if (techCounters[techId].group === 'SDB') {
      sdbCount++;
    } else {
      dbmsCount++;
    }

    if (a.severity === 'CRITICAL') criticalCount++;
    else if (a.severity === 'HIGH') highCount++;
    else mediumLowCount++;
  }

  const dbmsPercent = total > 0 ? Math.round((dbmsCount / total) * 100) : 0;
  const sdbPercent = total > 0 ? 100 - dbmsPercent : 0;

  return {
    total,
    dbmsCount,
    sdbCount,
    dbmsPercent,
    sdbPercent,
    criticalCount,
    highCount,
    mediumLowCount,
    byTechnique: Object.entries(techCounters).map(([id, val]) => ({
      id,
      ...val,
    })),
  };
}

/**
 * Aggregates alert risk scores for a user according to canonical policy (`shared/detection_policy.json`).
 */
export function computeUserRiskScore(scores: number[]): number {
  const validScores = scores
    .filter((s) => Number.isFinite(s))
    .map((s) => Math.max(policy.thresholds.level_0.min, Math.min(policy.thresholds.level_3.max, s)));

  if (validScores.length === 0) return 0;

  const maxScore = Math.max(...validScores);
  const bonus = Math.min(
    policy.scoring.bonus_cap,
    Math.max(0, validScores.length - 1) * policy.scoring.bonus_per_extra_alert
  );
  const combined = maxScore + bonus;

  if (policy.scoring.clamp_by_tier) {
    if (maxScore < policy.thresholds.level_2.min) {
      return Math.min(policy.thresholds.level_1.max, combined);
    }
    if (maxScore < policy.thresholds.level_3.min) {
      return Math.min(policy.thresholds.level_2.max, combined);
    }
  }

  return Math.min(policy.thresholds.level_3.max, Math.round(combined));
}

export function getRiskColorHex(score: number): string {
  if (score >= policy.thresholds.level_3.min) return '#ef4444';
  if (score >= policy.thresholds.level_2.min) return '#f97316';
  if (score >= policy.thresholds.level_1.min) return '#eab308';
  return '#10b981';
}

export function classifyResponseLevel(score: number): { level: 0 | 1 | 2 | 3; label: string } {
  const safeScore = Number.isFinite(score)
    ? Math.max(policy.thresholds.level_0.min, Math.min(policy.thresholds.level_3.max, score))
    : 0;

  if (safeScore >= policy.thresholds.level_3.min) {
    return { level: 3, label: policy.thresholds.level_3.label };
  }
  if (safeScore >= policy.thresholds.level_2.min) {
    return { level: 2, label: policy.thresholds.level_2.label };
  }
  if (safeScore >= policy.thresholds.level_1.min) {
    return { level: 1, label: policy.thresholds.level_1.label };
  }
  return { level: 0, label: policy.thresholds.level_0.label };
}

/**
 * Maps an alert timestamp (YYYY-MM-DD HH:MM:SS) to a 5-minute time bucket label (HH:MM–HH:MM).
 */
export function getTimeBucketLabel(timestamp: string): string {
  const timePart = (timestamp.split(' ')[1] || '00:00:00').trim();
  const [hhStr = '00', mmStr = '00'] = timePart.split(':');
  const hh = parseInt(hhStr, 10) || 0;
  const mm = parseInt(mmStr, 10) || 0;
  const startMin = Math.floor(mm / 5) * 5;
  const endMin = Math.min(59, startMin + 4);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(hh)}:${pad(startMin)}–${pad(hh)}:${pad(endMin)}`;
}

/**
 * Builds a 2D Recharts Heatmap matrix representing attack intensity across Time Slots (X) and Users (Y).
 */
export function buildAttackHeatmapMatrix(
  alerts: AlertItem[],
  users: DbUser[],
  filterGroup: 'ALL' | AttackGroup = 'ALL'
): HeatmapMatrixResult {
  const userList = users.length > 0 ? users.map((u) => u.USERNAME) : ['U1', 'U2', 'U3', 'U4'];

  const filteredAlerts =
    filterGroup === 'ALL'
      ? alerts
      : alerts.filter((a) => classifyAlertGroup(a) === filterGroup);

  const defaultBuckets = [
    '00:00–00:04',
    '00:05–00:09',
    '00:15–00:19',
    '00:20–00:24',
    '00:25–00:29',
    '14:05–14:09',
  ];

  const bucketSet = new Set<string>(defaultBuckets);
  for (const a of filteredAlerts) {
    if (a.time) {
      bucketSet.add(getTimeBucketLabel(a.time));
    }
  }

  const timeSlots = Array.from(bucketSet).sort((a, b) => a.localeCompare(b));

  const points: HeatmapCellPoint[] = [];
  let peakCell: HeatmapCellPoint | null = null;

  userList.forEach((user, yIndex) => {
    timeSlots.forEach((timeSlot, xIndex) => {
      const matching = filteredAlerts.filter(
        (a) => a.user.toUpperCase() === user.toUpperCase() && getTimeBucketLabel(a.time) === timeSlot
      );

      const eventCount = matching.length;
      const maxRisk = eventCount > 0 ? Math.max(...matching.map((m) => m.risk_score)) : 0;
      const bonus = eventCount > 1 ? Math.min(10, (eventCount - 1) * 5) : 0;
      const intensity = eventCount > 0 ? Math.min(100, maxRisk + bonus) : 0;

      let dbmsCount = 0;
      let sdbCount = 0;
      for (const m of matching) {
        if (classifyAlertGroup(m) === 'SDB') sdbCount++;
        else dbmsCount++;
      }

      const sortedByRisk = [...matching].sort((a, b) => b.risk_score - a.risk_score);
      const sampleAlert = sortedByRisk[0];
      const topAttack = sampleAlert ? sampleAlert.attack_type : 'Không phát hiện xâm nhập (An toàn)';

      let fill = '#0b1322';
      let stroke = 'rgba(56, 189, 248, 0.14)';
      let levelLabel = 'Level 0: An toàn (0)';

      if (intensity >= policy.thresholds.level_3.min) {
        fill = 'rgba(239, 68, 68, 0.82)';
        stroke = '#f87171';
        levelLabel = policy.thresholds.level_3.label;
      } else if (intensity >= policy.thresholds.level_2.min) {
        fill = 'rgba(249, 115, 22, 0.78)';
        stroke = '#fb923c';
        levelLabel = policy.thresholds.level_2.label;
      } else if (intensity > 0) {
        fill = 'rgba(14, 165, 233, 0.7)';
        stroke = '#38bdf8';
        levelLabel = 'Level 1: LOW/MED (Warning)';
      }

      const cell: HeatmapCellPoint = {
        xIndex,
        yIndex,
        timeSlot,
        user,
        intensity,
        eventCount,
        maxRisk,
        dbmsCount,
        sdbCount,
        topAttack,
        levelLabel,
        fill,
        stroke,
        sampleAlert,
      };

      points.push(cell);

      if (
        !peakCell ||
        cell.intensity > peakCell.intensity ||
        (cell.intensity === peakCell.intensity && cell.eventCount > peakCell.eventCount)
      ) {
        peakCell = cell;
      }
    });
  });

  return {
    users: userList,
    timeSlots,
    points,
    peakCell,
  };
}

export function calculateSystemMetrics(
  auditCount: number,
  alertCount: number,
  triggerCount: number,
  fgaCount: number,
  users: DbUser[]
): Metrics {
  const locked_count = users.filter((u) => u.ACCOUNT_STATUS.toUpperCase().includes('LOCK')).length;
  const readonly_count = users.filter((u) => u.DML_STATUS.toUpperCase() === 'READ-ONLY').length;
  const max_risk = users.length > 0 ? Math.max(...users.map((u) => u.RISK_SCORE)) : 0;

  return {
    audit_count: auditCount,
    alert_count: alertCount,
    trigger_count: triggerCount,
    fga_count: fgaCount,
    locked_count,
    readonly_count,
    max_risk,
  };
}

/**
 * Recalculates each user's RISK_SCORE, RESPONSE_LEVEL, and containment status
 * based on remaining active alerts after reviewed alerts/events are reset.
 * When `autoResponse === false`, only risk score/level/label are updated.
 */
export function recalculateUsersAfterReset(
  users: DbUser[],
  remainingAlerts: AlertItem[],
  autoResponse: boolean = true
): DbUser[] {
  const nowUtc = new Date().toISOString().replace('T', ' ').substring(0, 19);

  return users.map((u) => {
    const userAlerts = remainingAlerts.filter(
      (a) => a.user.toUpperCase() === u.USERNAME.toUpperCase()
    );

    const nextScore = computeUserRiskScore(userAlerts.map((a) => a.risk_score));
    const { level, label } = classifyResponseLevel(nextScore);

    if (!autoResponse) {
      return {
        ...u,
        RISK_SCORE: nextScore,
        RESPONSE_LEVEL: level,
        RESPONSE_LABEL: label,
      };
    }

    if (level === 3) {
      return {
        ...u,
        RISK_SCORE: nextScore,
        RESPONSE_LEVEL: 3,
        RESPONSE_LABEL: label,
        ACCOUNT_STATUS: 'LOCKED',
        DML_STATUS: 'READ-ONLY',
        PRIVILEGES: 'SELECT',
        LOCK_DATE: u.LOCK_DATE || nowUtc,
      };
    }

    if (level === 2) {
      return {
        ...u,
        RISK_SCORE: nextScore,
        RESPONSE_LEVEL: 2,
        RESPONSE_LABEL: label,
        ACCOUNT_STATUS: 'OPEN',
        DML_STATUS: 'READ-ONLY',
        PRIVILEGES: 'SELECT',
        LOCK_DATE: undefined,
      };
    }

    return {
      ...u,
      RISK_SCORE: nextScore,
      RESPONSE_LEVEL: level,
      RESPONSE_LABEL: label,
      ACCOUNT_STATUS: 'OPEN',
      DML_STATUS: 'FULL DML',
      PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
      LOCK_DATE: undefined,
    };
  });
}
