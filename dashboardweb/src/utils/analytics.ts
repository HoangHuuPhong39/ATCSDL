import type { AlertItem, DbUser, Metrics } from '../types/ids.ts';

export type AttackGroup = 'DBMS' | 'SDB';

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

/**
 * Classifies an alert into DBMS Technical Attack or SDB Inference Attack
 * based on its attack_type or details.
 */
export function classifyAlertGroup(alert: Pick<AlertItem, 'attack_type' | 'details'>): AttackGroup {
  const text = `${alert.attack_type} ${alert.details}`.toUpperCase();
  if (
    text.includes('[SDB') ||
    text.includes('SDB ') ||
    text.includes('COUNT-BASED') ||
    text.includes('TRACKER') ||
    text.includes('LINEAR SYSTEM') ||
    text.includes('DIRECT ATTACK') ||
    text.includes('SUY DIỄN')
  ) {
    return 'SDB';
  }
  return 'DBMS';
}

/**
 * Computes non-duplicated statistical breakdown of alerts for SOC analytics.
 */
export function computeAttackBreakdown(alerts: AlertItem[]): AttackBreakdown {
  const total = alerts.length;
  let dbmsCount = 0;
  let sdbCount = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumLowCount = 0;

  const techCounters: Record<string, { label: string; group: AttackGroup; count: number }> = {
    sqli: { label: 'SQL Injection', group: 'DBMS', count: 0 },
    masquerade: { label: 'Giả mạo / Giả danh (Masquerading)', group: 'DBMS', count: 0 },
    priv_escalation: { label: 'Leo thang đặc quyền (Privilege Escalation)', group: 'DBMS', count: 0 },
    failed_logins: { label: 'Đăng nhập thất bại (Brute-Force)', group: 'DBMS', count: 0 },
    crypto_key: { label: 'Truy cập khóa mã hóa trái phép', group: 'DBMS', count: 0 },
    trigger_dml: { label: 'Gian lận / Phá hoại dữ liệu (Trigger)', group: 'DBMS', count: 0 },
    sdb_direct: { label: '[SDB] Tấn công trực tiếp & Honeytoken', group: 'SDB', count: 0 },
    sdb_count: { label: '[SDB] Tấn công dựa vào đếm (COUNT=1 & SUM)', group: 'SDB', count: 0 },
    sdb_tracker: { label: '[SDB] Tấn công trình theo dõi (Tracker)', group: 'SDB', count: 0 },
    sdb_linear: { label: '[SDB] Tấn công hệ tuyến tính (A·X=B)', group: 'SDB', count: 0 },
  };

  for (const a of alerts) {
    const group = classifyAlertGroup(a);
    if (group === 'SDB') {
      sdbCount++;
    } else {
      dbmsCount++;
    }

    if (a.severity === 'CRITICAL') criticalCount++;
    else if (a.severity === 'HIGH') highCount++;
    else mediumLowCount++;

    const upper = `${a.attack_type} ${a.details}`.toUpperCase();
    if (upper.includes('SQL INJECTION') || upper.includes('OR 1=1')) {
      techCounters.sqli.count++;
    } else if (upper.includes('MASQUERAD') || upper.includes('GIẢ MẠO') || upper.includes('GIẢ DANH')) {
      techCounters.masquerade.count++;
    } else if (upper.includes('PRIVILEGE') || upper.includes('LEO THANG') || upper.includes('GRANT DBA')) {
      techCounters.priv_escalation.count++;
    } else if (upper.includes('BRUTE-FORCE') || upper.includes('FAILED LOGINS') || upper.includes('ORA-01017')) {
      techCounters.failed_logins.count++;
    } else if (upper.includes('KEY ACCESS') || upper.includes('KHÓA MÃ HÓA') || upper.includes('ENCRYPTION_KEYS') || upper.includes('DBMS_CRYPTO')) {
      techCounters.crypto_key.count++;
    } else if (upper.includes('LINEAR SYSTEM') || upper.includes('HỆ TUYẾN TÍNH') || upper.includes('A*X') || upper.includes('A·X')) {
      techCounters.sdb_linear.count++;
    } else if (upper.includes('TRACKER') || upper.includes('TRÌNH THEO DÕI')) {
      techCounters.sdb_tracker.count++;
    } else if (upper.includes('COUNT-BASED') || upper.includes('DỰA VÀO ĐẾM') || upper.includes('COUNT = 1')) {
      techCounters.sdb_count.count++;
    } else if (upper.includes('DIRECT ATTACK') || upper.includes('TRỰC TIẾP') || upper.includes('HONEYTOKEN') || upper.includes('NV_TRAP')) {
      techCounters.sdb_direct.count++;
    } else {
      techCounters.trigger_dml.count++;
    }
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

export function getRiskColorHex(score: number): string {
  if (score >= 80) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 20) return '#eab308';
  return '#10b981';
}

export function classifyResponseLevel(score: number): { level: 0 | 1 | 2 | 3; label: string } {
  if (score >= 80) {
    return { level: 3, label: 'Level 3: CRITICAL (Full Isolation)' };
  }
  if (score >= 50) {
    return { level: 2, label: 'Level 2: HIGH (Privilege Containment)' };
  }
  if (score >= 20) {
    return { level: 1, label: 'Level 1: LOW/MED (Warning & Monitor)' };
  }
  return { level: 0, label: 'Level 0: Normal (An toàn)' };
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

  // Default baseline time slots + any dynamic buckets from alerts
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

      if (intensity >= 80) {
        fill = 'rgba(239, 68, 68, 0.82)';
        stroke = '#f87171';
        levelLabel = 'Level 3: CRITICAL (Full Isolation)';
      } else if (intensity >= 50) {
        fill = 'rgba(249, 115, 22, 0.78)';
        stroke = '#fb923c';
        levelLabel = 'Level 2: HIGH (Privilege Containment)';
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

      if (!peakCell || cell.intensity > peakCell.intensity || (cell.intensity === peakCell.intensity && cell.eventCount > peakCell.eventCount)) {
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
 */
export function recalculateUsersAfterReset(
  users: DbUser[],
  remainingAlerts: AlertItem[]
): DbUser[] {
  return users.map((u) => {
    const userAlerts = remainingAlerts.filter(
      (a) => a.user.toUpperCase() === u.USERNAME.toUpperCase()
    );

    if (userAlerts.length === 0) {
      return {
        ...u,
        ACCOUNT_STATUS: 'OPEN',
        DML_STATUS: 'FULL DML',
        PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
        RISK_SCORE: 0,
        RESPONSE_LEVEL: 0,
        RESPONSE_LABEL: 'Level 0: Normal (An toàn)',
        LOCK_DATE: undefined,
      };
    }

    const maxScore = Math.max(...userAlerts.map((a) => a.risk_score));
    const bonus = Math.min(10, (userAlerts.length - 1) * 3);
    const nextScore =
      maxScore >= 80
        ? Math.min(100, maxScore + bonus)
        : maxScore >= 50
        ? Math.min(79, maxScore + bonus)
        : Math.min(49, maxScore + bonus);

    if (nextScore >= 80) {
      return {
        ...u,
        RISK_SCORE: nextScore,
        RESPONSE_LEVEL: 3,
        RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
        ACCOUNT_STATUS: 'LOCKED',
        DML_STATUS: 'READ-ONLY',
        PRIVILEGES: 'SELECT',
      };
    } else if (nextScore >= 50) {
      return {
        ...u,
        RISK_SCORE: nextScore,
        RESPONSE_LEVEL: 2,
        RESPONSE_LABEL: 'Level 2: HIGH (Privilege Containment)',
        ACCOUNT_STATUS: 'OPEN',
        DML_STATUS: 'READ-ONLY',
        PRIVILEGES: 'SELECT',
        LOCK_DATE: undefined,
      };
    } else {
      return {
        ...u,
        RISK_SCORE: nextScore,
        RESPONSE_LEVEL: 1,
        RESPONSE_LABEL: 'Level 1: LOW/MED (Warning & Monitor)',
        ACCOUNT_STATUS: 'OPEN',
        DML_STATUS: 'FULL DML',
        PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
        LOCK_DATE: undefined,
      };
    }
  });
}

