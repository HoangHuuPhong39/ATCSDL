import React, { useMemo, useState, useRef, useEffect } from 'react';
import {
  ArrowRight,
  Database,
  CheckCircle2,
  CheckCheck,
  Trash2,
  Unlock,
  Lock,
  ShieldCheck,
  ShieldAlert,
  FileDown,
  Info,
} from 'lucide-react';
import { AlertItem, DbUser, FgaEvent, Metrics, TriggerAlert, ActiveTab } from '../../types/ids';
import { KpiCards } from '../KpiCards';
import { AttackHeatmap } from '../AttackHeatmap';
import { computeAttackBreakdown, getRiskColorHex } from '../../utils/analytics';
import { maskUsername } from '../../utils/privacy';
import { Card } from '../ui/Card';
import { StatusDot } from '../ui/StatusDot';

interface OverviewTabProps {
  metrics: Metrics;
  alerts: AlertItem[];
  users: DbUser[];
  fgaEvents: FgaEvent[];
  triggers: TriggerAlert[];
  privacyMode?: boolean;
  onOpenAlertModal: (alert: AlertItem) => void;
  onNavigateTab: (tab: ActiveTab) => void;
  onOpenOracleBridge: () => void;
  onOpenPdfExport?: () => void;
  onToggleReviewAlert: (key: string) => void;
  onDismissAlert: (key: string) => void;
  onMarkAllReviewed: () => void;
  onResetReviewedAll: () => void;
  onResetAllAfterAudit: () => void;
  onUserAction?: (username: string, action: 'lock' | 'unlock' | 'revoke_dml' | 'grant_dml') => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  metrics,
  alerts,
  users,
  fgaEvents,
  triggers,
  privacyMode = false,
  onOpenAlertModal,
  onNavigateTab,
  onOpenOracleBridge,
  onOpenPdfExport,
  onToggleReviewAlert,
  onDismissAlert,
  onMarkAllReviewed,
  onResetReviewedAll,
  onResetAllAfterAudit,
  onUserAction,
}) => {
  // 2-step confirmation state with 3-second auto-revert
  const [confirmLockUser, setConfirmLockUser] = useState<string | null>(null);
  const [confirmMarkAll, setConfirmMarkAll] = useState(false);
  const [confirmResetAll, setConfirmResetAll] = useState(false);

  const lockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const markAllTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const resetAllTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
      if (markAllTimerRef.current) clearTimeout(markAllTimerRef.current);
      if (resetAllTimerRef.current) clearTimeout(resetAllTimerRef.current);
    };
  }, []);

  const handleLockUser = (username: string) => {
    if (confirmLockUser === username) {
      onUserAction?.(username, 'lock');
      setConfirmLockUser(null);
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    } else {
      setConfirmLockUser(username);
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
      lockTimerRef.current = setTimeout(() => setConfirmLockUser(null), 3000);
    }
  };

  const handleMarkAll = () => {
    if (confirmMarkAll) {
      onMarkAllReviewed();
      setConfirmMarkAll(false);
      if (markAllTimerRef.current) clearTimeout(markAllTimerRef.current);
    } else {
      setConfirmMarkAll(true);
      if (markAllTimerRef.current) clearTimeout(markAllTimerRef.current);
      markAllTimerRef.current = setTimeout(() => setConfirmMarkAll(false), 3000);
    }
  };

  const handleResetAll = () => {
    if (confirmResetAll) {
      onResetAllAfterAudit();
      setConfirmResetAll(false);
      if (resetAllTimerRef.current) clearTimeout(resetAllTimerRef.current);
    } else {
      setConfirmResetAll(true);
      if (resetAllTimerRef.current) clearTimeout(resetAllTimerRef.current);
      resetAllTimerRef.current = setTimeout(() => setConfirmResetAll(false), 3000);
    }
  };

  const breakdown = useMemo(() => computeAttackBreakdown(alerts), [alerts]);

  const reviewedAlertsCount = useMemo(() => alerts.filter((a) => a.reviewed).length, [alerts]);
  const reviewedFgaCount = useMemo(() => fgaEvents.filter((f) => f.reviewed).length, [fgaEvents]);
  const reviewedTriggersCount = useMemo(() => triggers.filter((t) => t.reviewed).length, [triggers]);
  const totalReviewed = reviewedAlertsCount + reviewedFgaCount + reviewedTriggersCount;
  const totalEventsAndAlerts = alerts.length + fgaEvents.length + triggers.length;
  const pendingReviewCount = totalEventsAndAlerts - totalReviewed;

  // Sorted recent alerts (descending by time, top 8)
  const sortedRecentAlerts = useMemo(() => {
    return [...alerts]
      .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
      .slice(0, 8);
  }, [alerts]);

  // Sorted users by risk descending
  const sortedUsers = useMemo(() => {
    return [...users].sort((a, b) => b.RISK_SCORE - a.RISK_SCORE);
  }, [users]);

  // Contained users count
  const containedCount = useMemo(
    () =>
      users.filter(
        (u) =>
          u.ACCOUNT_STATUS.toUpperCase().includes('LOCK') ||
          u.DML_STATUS.toUpperCase() === 'READ-ONLY'
      ).length,
    [users]
  );

  const cleanAttackName = (type: string) => {
    return type.replace(/^\[.*?\]\s*/, '').trim();
  };

  const formatEventTime = (time: string) => {
    if (!time) return '';
    const parts = time.split(' ');
    return parts.length > 1 ? parts[1] : time;
  };

  const getRiskStatus = (risk: number): 'danger' | 'warn' | 'ok' => {
    if (risk >= 80) return 'danger';
    if (risk >= 50) return 'warn';
    return 'ok';
  };

  return (
    <div className="space-y-4">
      {/* =========================================================================
          HANG 1: 4 THE KPI TOI GIAN (Icon nho, Nhan, So lon, 1 dong phu)
          ========================================================================= */}
      <KpiCards metrics={metrics} onNavigateTab={onNavigateTab} />

      {/* =========================================================================
          HANG 2: (xl: 3/5 + 2/5)
          Trái: Sự kiện gần đây (1 dòng / sự kiện, hover actions)
          Phải: Tài khoản bị hạn chế (Gộp containment banner + radar, scrollable)
          ========================================================================= */}
      <section className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        {/* Trai 3/5: Card "Sự kiện gần đây" */}
        <Card
          title="Sự kiện gần đây"
          className="xl:col-span-3 flex flex-col justify-between"
          bodyClassName="p-3 sm:p-4 space-y-1"
          right={
            <button
              onClick={() => onNavigateTab('alerts')}
              aria-label="Xem tất cả cảnh báo"
              className="inline-flex items-center gap-1 text-xs font-medium text-[var(--accent)] hover:underline cursor-pointer focus-visible:ring"
            >
              <span>Xem tất cả ({alerts.length})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          }
        >
          {sortedRecentAlerts.length === 0 ? (
            <div className="py-8 text-center text-xs text-[var(--text-3)] font-medium">
              Không có sự kiện bất thường nào.
            </div>
          ) : (
            <div className="space-y-1">
              {sortedRecentAlerts.map((a) => {
                const isCritical = a.risk_score >= 80;
                const isHigh = a.risk_score >= 50 && a.risk_score < 80;
                const severityLabel = a.severity || (isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : 'MED');

                return (
                  <div
                    key={a.key}
                    className="group flex items-center justify-between gap-2 py-1.5 px-2 rounded-lg hover:bg-[var(--surface-hover)] transition-colors border border-transparent hover:border-[var(--line)]"
                  >
                    <button
                      type="button"
                      onClick={() => onOpenAlertModal(a)}
                      className="flex-1 flex items-center gap-2.5 min-w-0 text-left cursor-pointer focus-visible:ring rounded"
                    >
                      <StatusDot status={getRiskStatus(a.risk_score)} size="sm" />
                      <span className="font-mono text-xs text-[var(--text-3)] tabular-nums shrink-0">
                        {formatEventTime(a.time)}
                      </span>
                      <span
                        className="text-xs font-medium text-[var(--text-1)] truncate flex-1"
                        title={a.attack_type}
                      >
                        {cleanAttackName(a.attack_type)}
                      </span>
                      <span className="font-mono text-xs text-[var(--text-2)] shrink-0">
                        {maskUsername(a.user, privacyMode)}
                      </span>
                      <span
                        className={`text-xs font-mono font-semibold shrink-0 ${
                          isCritical
                            ? 'text-[var(--danger)]'
                            : isHigh
                            ? 'text-[var(--warn)]'
                            : 'text-[var(--ok)]'
                        }`}
                      >
                        {severityLabel}
                      </span>
                      {a.reviewed && (
                        <span title="Đã duyệt" className="shrink-0 text-[var(--ok)]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        </span>
                      )}
                    </button>

                    {/* Actions: only visible on hover or focus-within */}
                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity shrink-0">
                      <button
                        type="button"
                        onClick={() => onToggleReviewAlert(a.key)}
                        aria-label={a.reviewed ? 'Bỏ đánh dấu đã duyệt' : 'Đánh dấu đã duyệt'}
                        title={a.reviewed ? 'Đã duyệt (Nhấn để hủy)' : 'Đánh dấu đã duyệt'}
                        className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--ok)] hover:bg-[var(--surface)] transition-colors cursor-pointer focus-visible:ring"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={() => onDismissAlert(a.key)}
                        aria-label={`Xóa cảnh báo ${cleanAttackName(a.attack_type)}`}
                        title="Xóa cảnh báo này"
                        className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--surface)] transition-colors cursor-pointer focus-visible:ring"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Phải 2/5: Card "Tài khoản bị hạn chế" (Gộp containment banner + radar, cuộn) */}
        <Card
          title={`Tài khoản bị hạn chế (${containedCount})`}
          className="xl:col-span-2 flex flex-col justify-between"
          bodyClassName="p-3 sm:p-4"
          right={
            <button
              onClick={() => onNavigateTab('ips')}
              aria-label="Xem ma trận IPS"
              className="inline-flex items-center gap-1 text-xs font-medium text-[var(--accent)] hover:underline cursor-pointer focus-visible:ring"
            >
              <span>Ma trận IPS</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          }
        >
          <div className="space-y-2 max-h-[340px] overflow-y-auto pr-1">
            {sortedUsers.length === 0 ? (
              <div className="py-8 text-center text-xs text-[var(--text-3)]">
                Không có tài khoản nào trong hệ thống.
              </div>
            ) : (
              sortedUsers.map((u) => {
                const isLocked = u.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
                const isReadOnly = !isLocked && u.DML_STATUS.toUpperCase() === 'READ-ONLY';
                const isOpen = !isLocked && !isReadOnly;
                const isConfirmingLock = confirmLockUser === u.USERNAME;
                const color = getRiskColorHex(u.RISK_SCORE);

                return (
                  <div
                    key={u.USERNAME}
                    className={`p-2.5 rounded-lg border transition-colors ${
                      isLocked
                        ? 'bg-[var(--danger-soft)]/10 border-[var(--danger)]/30'
                        : isReadOnly
                        ? 'bg-[var(--warn-soft)]/10 border-[var(--warn)]/30'
                        : 'bg-[var(--surface-hover)] border-[var(--line)]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono font-semibold text-xs text-[var(--text-1)]">
                          {maskUsername(u.USERNAME, privacyMode)}
                        </span>
                        <span
                          className={`text-xs font-mono font-semibold px-1.5 py-0.2 rounded border ${
                            isLocked
                              ? 'bg-[var(--danger-soft)] text-[var(--danger)] border-[var(--danger)]/30'
                              : isReadOnly
                              ? 'bg-[var(--warn-soft)] text-[var(--warn)] border-[var(--warn)]/30'
                              : 'bg-[var(--ok-soft)] text-[var(--ok)] border-[var(--ok)]/30'
                          }`}
                        >
                          {isLocked ? 'LOCKED' : isReadOnly ? 'READ-ONLY' : 'OPEN'}
                        </span>
                      </div>
                      <span className="font-mono text-xs font-semibold tabular-nums shrink-0" style={{ color }}>
                        {u.RISK_SCORE}/100
                      </span>
                    </div>

                    {/* Action buttons (strict non-contradictory logic) */}
                    {onUserAction && (
                      <div className="flex items-center justify-end gap-1.5 mt-2">
                        {/* 1. LOCKED: Only Unlock */}
                        {isLocked && (
                          <button
                            type="button"
                            onClick={() => onUserAction(u.USERNAME, 'unlock')}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[var(--ok-soft)] border border-[var(--ok)]/30 text-[var(--ok)] hover:bg-[var(--ok-soft)]/80 text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
                            title={`Mở khóa tài khoản ${u.USERNAME}`}
                          >
                            <Unlock className="w-3 h-3" />
                            <span>Mở khóa</span>
                          </button>
                        )}

                        {/* 2. READ-ONLY: Restore DML + Lock L3 */}
                        {isReadOnly && (
                          <>
                            <button
                              type="button"
                              onClick={() => onUserAction(u.USERNAME, 'grant_dml')}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[var(--surface)] border border-[var(--line)] text-[var(--text-1)] hover:border-[var(--accent)] text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
                              title={`Khôi phục quyền DML cho ${u.USERNAME}`}
                            >
                              <ShieldCheck className="w-3 h-3 text-[var(--accent)]" />
                              <span>Khôi phục DML</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleLockUser(u.USERNAME)}
                              className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium cursor-pointer transition-colors focus-visible:ring ${
                                isConfirmingLock
                                  ? 'bg-[var(--danger)] text-white border border-[var(--danger)] animate-pulse'
                                  : 'bg-[var(--danger-soft)] border border-[var(--danger)]/30 text-[var(--danger)] hover:bg-[var(--danger)] hover:text-white'
                              }`}
                              title={`Khóa tài khoản ${u.USERNAME}`}
                            >
                              <Lock className="w-3 h-3" />
                              <span>{isConfirmingLock ? 'Bấm lại để xác nhận' : 'Khóa'}</span>
                            </button>
                          </>
                        )}

                        {/* 3. OPEN: Revoke DML (Read-Only) + Lock L3 */}
                        {isOpen && (
                          <>
                            <button
                              type="button"
                              onClick={() => onUserAction(u.USERNAME, 'revoke_dml')}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[var(--surface)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--warn)] text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
                              title={`Hạ quyền tạm thời về Read-Only cho ${u.USERNAME}`}
                            >
                              <ShieldAlert className="w-3 h-3 text-[var(--warn)]" />
                              <span>Hạ quyền</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleLockUser(u.USERNAME)}
                              className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium cursor-pointer transition-colors focus-visible:ring ${
                                isConfirmingLock
                                  ? 'bg-[var(--danger)] text-white border border-[var(--danger)] animate-pulse'
                                  : 'bg-[var(--danger-soft)] border border-[var(--danger)]/30 text-[var(--danger)] hover:bg-[var(--danger)] hover:text-white'
                              }`}
                              title={`Khóa tài khoản ${u.USERNAME}`}
                            >
                              <Lock className="w-3 h-3" />
                              <span>{isConfirmingLock ? 'Bấm lại để xác nhận' : 'Khóa'}</span>
                            </button>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </Card>
      </section>

      {/* =========================================================================
          HANG 3:
          Trái: Heatmap + Thanh phân bổ kỹ thuật tấn công xếp chồng (DBMS vs SDB)
          Phải: Card "Thao tác nhanh" (Xuất PDF, Duyệt tất cả, Dọn hàng đợi, Kết nối Oracle)
          ========================================================================= */}
      <section className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        {/* Trai 3/5: Heatmap & Phân bổ kỹ thuật */}
        <div className="xl:col-span-3 space-y-3">
          {/* Stacked DBMS vs SDB vector ratio bar */}
          <div className="bg-[var(--surface)] border border-[var(--line)] rounded-xl p-3 sm:px-4">
            <div className="flex items-center justify-between text-xs font-medium mb-1.5">
              <span className="flex items-center gap-1.5 text-[var(--danger)] font-mono">
                <span className="w-2 h-2 rounded-full bg-[var(--danger)]" />
                <span>Nhóm I (DBMS): {breakdown.dbmsCount} ({breakdown.dbmsPercent}%)</span>
              </span>
              <span className="flex items-center gap-1.5 text-[var(--warn)] font-mono">
                <span className="w-2 h-2 rounded-full bg-[var(--warn)]" />
                <span>Nhóm II (SDB): {breakdown.sdbCount} ({breakdown.sdbPercent}%)</span>
              </span>
            </div>
            <div
              role="progressbar"
              aria-label="Tỷ lệ phân bổ kỹ thuật tấn công DBMS và SDB"
              aria-valuenow={breakdown.dbmsPercent}
              className="w-full h-1.5 bg-[var(--surface-hover)] rounded-full overflow-hidden flex"
            >
              <div
                className="h-full bg-[var(--danger)] transition-all duration-300"
                style={{ width: `${breakdown.dbmsPercent}%` }}
              />
              <div
                className="h-full bg-[var(--warn)] transition-all duration-300"
                style={{ width: `${breakdown.sdbPercent}%` }}
              />
            </div>
          </div>

          {/* Heatmap */}
          <AttackHeatmap
            alerts={alerts}
            users={users}
            privacyMode={privacyMode}
            onOpenAlertModal={onOpenAlertModal}
            onOpenOracleBridge={onOpenOracleBridge}
          />
        </div>

        {/* Phải 2/5: Card "Thao tác nhanh" (Post-Audit Bar converted here) */}
        <Card
          title="Thao tác nhanh"
          className="xl:col-span-2 flex flex-col justify-between"
          bodyClassName="p-3 sm:p-4 space-y-2.5"
          right={
            <span
              title="Thực hiện duyệt, reset hoặc xuất báo cáo sau khi hoàn tất kiểm tra kịch bản"
              className="text-[var(--text-3)] cursor-help"
            >
              <Info className="w-3.5 h-3.5" />
            </span>
          }
        >
          <div className="space-y-2">
            {/* 1. Duyệt tất cả (2-step confirm) */}
            <button
              type="button"
              onClick={handleMarkAll}
              disabled={pendingReviewCount === 0}
              className={`w-full flex items-center justify-between p-2.5 rounded-lg border text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed focus-visible:ring ${
                confirmMarkAll
                  ? 'bg-[var(--ok)] text-white border-[var(--ok)] animate-pulse'
                  : 'bg-[var(--surface-hover)] border-[var(--line)] text-[var(--text-1)] hover:border-[var(--ok)]'
              }`}
            >
              <span className="flex items-center gap-2">
                <CheckCheck className="w-4 h-4 text-[var(--ok)]" />
                <span>{confirmMarkAll ? 'Bấm lại để xác nhận' : 'Duyệt tất cả'}</span>
              </span>
              <span className="font-mono text-xs text-[var(--text-3)]">
                {pendingReviewCount} chờ
              </span>
            </button>

            {/* 2. Reset mục đã duyệt */}
            <button
              type="button"
              onClick={onResetReviewedAll}
              disabled={totalReviewed === 0}
              className="w-full flex items-center justify-between p-2.5 rounded-lg border border-[var(--line)] bg-[var(--surface-hover)] hover:border-[var(--warn)] text-xs font-medium text-[var(--text-1)] transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed focus-visible:ring"
            >
              <span className="flex items-center gap-2">
                <Trash2 className="w-4 h-4 text-[var(--warn)]" />
                <span>Reset mục đã duyệt</span>
              </span>
              <span className="font-mono text-xs text-[var(--text-3)]">
                {totalReviewed} mục
              </span>
            </button>

            {/* 3. Dọn hàng đợi / Reset toàn bộ (2-step confirm) */}
            <button
              type="button"
              onClick={handleResetAll}
              disabled={totalEventsAndAlerts === 0}
              className={`w-full flex items-center justify-between p-2.5 rounded-lg border text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed focus-visible:ring ${
                confirmResetAll
                  ? 'bg-[var(--danger)] text-white border-[var(--danger)] animate-pulse'
                  : 'bg-[var(--surface-hover)] border-[var(--line)] text-[var(--text-1)] hover:border-[var(--danger)]'
              }`}
            >
              <span className="flex items-center gap-2">
                <Trash2 className="w-4 h-4 text-[var(--danger)]" />
                <span>{confirmResetAll ? 'Bấm lại để xác nhận' : 'Dọn hàng đợi'}</span>
              </span>
              <span className="font-mono text-xs text-[var(--text-3)]">
                {totalEventsAndAlerts} sự kiện
              </span>
            </button>

            {/* 4. Xuất PDF */}
            {onOpenPdfExport && (
              <button
                type="button"
                onClick={onOpenPdfExport}
                className="w-full flex items-center justify-between p-2.5 rounded-lg border border-[var(--line)] bg-[var(--surface-hover)] hover:border-[var(--accent)] text-xs font-medium text-[var(--text-1)] transition-colors cursor-pointer focus-visible:ring"
              >
                <span className="flex items-center gap-2">
                  <FileDown className="w-4 h-4 text-[var(--accent)]" />
                  <span>Xuất báo cáo PDF</span>
                </span>
                <span className="text-xs text-[var(--text-3)]">SOC Report</span>
              </button>
            )}

            {/* 5. Kết nối Oracle Bridge */}
            <button
              type="button"
              onClick={onOpenOracleBridge}
              className="w-full flex items-center justify-between p-2.5 rounded-lg border border-[var(--line)] bg-[var(--surface-hover)] hover:border-[var(--accent)] text-xs font-medium text-[var(--text-1)] transition-colors cursor-pointer focus-visible:ring"
            >
              <span className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[var(--ok)]" />
                <span>Kết nối Oracle Bridge</span>
              </span>
              <span className="font-mono text-xs text-[var(--text-3)]">FREEPDB1</span>
            </button>
          </div>
        </Card>
      </section>
    </div>
  );
};
