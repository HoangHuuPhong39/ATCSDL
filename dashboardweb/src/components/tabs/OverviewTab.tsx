import React, { useMemo } from 'react';
import {
  ShieldAlert,
  ArrowRight,
  Target,
  Zap,
  Database,
  Activity,
  Layers,
  Users,
  Eye,
  CheckCircle2,
  CheckCheck,
  RotateCcw,
  FileDown,
} from 'lucide-react';
import { AlertItem, DbUser, FgaEvent, Metrics, TriggerAlert, ActiveTab } from '../../types/ids';
import { KpiCards } from '../KpiCards';
import { AttackHeatmap } from '../AttackHeatmap';
import { computeAttackBreakdown, getRiskColorHex } from '../../utils/analytics';
import { maskUsername } from '../../utils/privacy';

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
}) => {
  const breakdown = useMemo(() => computeAttackBreakdown(alerts), [alerts]);

  const reviewedAlertsCount = useMemo(() => alerts.filter((a) => a.reviewed).length, [alerts]);
  const reviewedFgaCount = useMemo(() => fgaEvents.filter((f) => f.reviewed).length, [fgaEvents]);
  const reviewedTriggersCount = useMemo(() => triggers.filter((t) => t.reviewed).length, [triggers]);
  const totalReviewed = reviewedAlertsCount + reviewedFgaCount + reviewedTriggersCount;
  const totalEventsAndAlerts = alerts.length + fgaEvents.length + triggers.length;
  const pendingReviewCount = totalEventsAndAlerts - totalReviewed;

  return (
    <div className="space-y-5">
      {/* 1. Primary System KPI Strip (Shown ONLY on OverviewTab) */}
      <KpiCards metrics={metrics} />

      {/* 1.5 SOC Audit Review & Reset Command Bar */}
      <section className="bg-[#101b2e] border border-emerald-500/25 rounded-xl p-3.5 sm:px-5 flex flex-col lg:flex-row lg:items-center justify-between gap-3 shadow-lg shadow-black/25">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/15 border border-emerald-500/35 flex items-center justify-center text-emerald-400 shrink-0">
            <CheckCircle2 className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[13px] font-bold text-slate-100">
                Kiểm duyệt, Lưu trữ PDF &amp; Reset Sự kiện An ninh (Post-Audit Control)
              </span>
              <span className="text-[10.5px] font-mono px-2 py-0.5 rounded bg-[#0b1322] border border-white/10 text-slate-300">
                Chờ duyệt: <strong className="text-amber-300 tabular-nums">{pendingReviewCount}</strong> · Đã duyệt:{' '}
                <strong className="text-emerald-400 tabular-nums">{totalReviewed}</strong>
              </span>
            </div>
            <p className="text-[11px] text-slate-400 truncate">
              Xuất hồ sơ bảo mật sang PDF để lưu trữ trước hoặc sau khi kiểm duyệt và Reset hàng đợi sự kiện.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap shrink-0">
          {onOpenPdfExport && (
            <button
              onClick={onOpenPdfExport}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/15 border border-purple-500/40 text-purple-200 hover:bg-purple-500/25 text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap"
              title="Xuất báo cáo Cảnh báo & Nhật ký Kiểm toán sang định dạng PDF"
            >
              <FileDown className="w-3.5 h-3.5 text-purple-300" />
              <span>Xuất Hồ sơ PDF</span>
            </button>
          )}

          {pendingReviewCount > 0 && (
            <button
              onClick={onMarkAllReviewed}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>Duyệt tất cả ({pendingReviewCount})</span>
            </button>
          )}

          {totalReviewed > 0 && (
            <button
              onClick={onResetReviewedAll}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/20 border border-amber-500/45 text-amber-200 hover:bg-amber-500/30 text-[11.5px] font-bold transition-all cursor-pointer whitespace-nowrap"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset mục đã duyệt ({totalReviewed})</span>
            </button>
          )}

          {totalEventsAndAlerts > 0 && (
            <button
              onClick={onResetAllAfterAudit}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/15 border border-red-500/35 text-red-300 hover:bg-red-500/25 text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Đã duyệt xong · Reset toàn bộ</span>
            </button>
          )}
        </div>
      </section>

      {/* 2. Recharts Attack Intensity Heatmap (Time x User) */}
      <AttackHeatmap
        alerts={alerts}
        users={users}
        privacyMode={privacyMode}
        onOpenAlertModal={onOpenAlertModal}
        onOpenOracleBridge={onOpenOracleBridge}
      />

      {/* 3. Analytical Grid: Attack Vector Distribution (DBMS vs SDB) & User Risk Radar */}
      <section className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Left 7 cols: Attack Taxonomy Distribution */}
        <div className="xl:col-span-7 bg-[#101b2e] border border-sky-500/20 rounded-xl p-4 sm:p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between flex-wrap gap-2 pb-3.5 border-b border-white/5">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0">
                  <Layers className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-[13.5px] font-bold text-slate-100">
                    Bản đồ Phân bổ Kỹ thuật Tấn công (DBMS Technical vs. SDB Inference)
                  </h2>
                  <p className="text-[11px] text-slate-400">
                    Thống kê tỷ trọng 6 dạng tấn công kỹ thuật Hệ quản trị CSDL và 4 kiểu tấn công suy diễn CSDL Thống kê
                  </p>
                </div>
              </div>
              <button
                onClick={() => onNavigateTab('alerts')}
                className="inline-flex items-center gap-1 text-[11.5px] font-semibold text-sky-400 hover:text-white transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                <span>Mở bảng cảnh báo</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Dual Ratio Bar */}
            <div className="mt-4 bg-[#0b1322] border border-white/5 rounded-lg p-3.5">
              <div className="flex items-center justify-between text-[11.5px] font-semibold mb-2">
                <span className="text-red-300 font-mono tabular-nums">
                  Nhóm I: Kỹ thuật DBMS · {breakdown.dbmsCount} sự kiện ({breakdown.dbmsPercent}%)
                </span>
                <span className="text-amber-300 font-mono tabular-nums">
                  Nhóm II: Suy diễn SDB · {breakdown.sdbCount} sự kiện ({breakdown.sdbPercent}%)
                </span>
              </div>
              <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden flex">
                <div
                  className="h-full bg-red-500 transition-all duration-300"
                  style={{ width: `${breakdown.dbmsPercent}%` }}
                />
                <div
                  className="h-full bg-amber-400 transition-all duration-300"
                  style={{ width: `${breakdown.sdbPercent}%` }}
                />
              </div>
            </div>

            {/* 10 Attack Techniques Breakdown Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 mt-4">
              {breakdown.byTechnique.map((tech) => {
                const isSdb = tech.group === 'SDB';
                return (
                  <div
                    key={tech.id}
                    className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#0b1322]/80 border border-white/5 text-[11.5px]"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0 ${
                          isSdb
                            ? 'bg-amber-500/15 text-amber-300'
                            : 'bg-red-500/15 text-red-300'
                        }`}
                      >
                        {tech.group}
                      </span>
                      <span className="text-slate-200 truncate" title={tech.label}>
                        {tech.label}
                      </span>
                    </div>
                    <span className="font-mono font-bold text-sky-300 tabular-nums ml-2 shrink-0">
                      {tech.count}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick defense layer summary footer */}
          <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between flex-wrap gap-2 text-[11px] text-slate-400">
            <div className="flex items-center gap-3 flex-wrap">
              <span>
                CRITICAL: <strong className="text-red-400 font-mono tabular-nums">{breakdown.criticalCount}</strong>
              </span>
              <span>·</span>
              <span>
                HIGH: <strong className="text-amber-400 font-mono tabular-nums">{breakdown.highCount}</strong>
              </span>
              <span>·</span>
              <span>
                MEDIUM/LOW: <strong className="text-sky-300 font-mono tabular-nums">{breakdown.mediumLowCount}</strong>
              </span>
            </div>
            <button
              onClick={onOpenOracleBridge}
              className="inline-flex items-center gap-1 text-sky-300 hover:text-white font-semibold transition-colors cursor-pointer"
            >
              <Database className="w-3.5 h-3.5" />
              <span>Cổng nhận lệnh từ Oracle SQL Developer</span>
            </button>
          </div>
        </div>

        {/* Right 5 cols: Live User Risk Posture Radar */}
        <div className="xl:col-span-5 bg-[#101b2e] border border-sky-500/20 rounded-xl p-4 sm:p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between flex-wrap gap-2 pb-3.5 border-b border-white/5">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
                  <Users className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="text-[13.5px] font-bold text-slate-100">
                    Radar Điểm Rủi ro &amp; Cấp độ Phản ứng User
                  </h2>
                  <p className="text-[11px] text-slate-400">
                    Trạng thái định lượng thời gian thực của 4 tài khoản CSDL
                  </p>
                </div>
              </div>
              <button
                onClick={() => onNavigateTab('ips')}
                className="inline-flex items-center gap-1 text-[11.5px] font-semibold text-sky-400 hover:text-white transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                <span>Điều khiển IPS</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="mt-4 space-y-3">
              {users.map((u) => {
                const color = getRiskColorHex(u.RISK_SCORE);
                const isLocked = u.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
                const isReadOnly = u.DML_STATUS.toUpperCase() === 'READ-ONLY';
                return (
                  <div
                    key={u.USERNAME}
                    className="p-3 rounded-lg bg-[#0b1322] border border-white/5 space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-[13px] text-sky-300">
                          {maskUsername(u.USERNAME, privacyMode)}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          · {isLocked ? 'LOCKED (L3)' : isReadOnly ? 'READ-ONLY (L2)' : 'OPEN (FULL DML)'}
                        </span>
                      </div>
                      <span
                        className="font-mono font-bold text-[12px] tabular-nums"
                        style={{ color }}
                      >
                        {u.RISK_SCORE} / 100
                      </span>
                    </div>

                    <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{ width: `${u.RISK_SCORE}%`, backgroundColor: color }}
                      />
                    </div>

                    <div className="flex items-center justify-between text-[10.5px] text-slate-400 font-mono">
                      <span>{u.RESPONSE_LABEL}</span>
                      <span>Quyền: {u.PRIVILEGES}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] text-slate-400">
            <span>
              Bẫy FGA đã kích hoạt: <strong className="text-purple-300 font-mono tabular-nums">{fgaEvents.length}</strong>
            </span>
            <span>
              Trigger chặn tức thời: <strong className="text-amber-300 font-mono tabular-nums">{triggers.length}</strong>
            </span>
          </div>
        </div>
      </section>

      {/* 4. Compact Live Security Stream (Top 4 Latest Alerts + Quick Review/Reset) */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-4 sm:p-5">
        <div className="flex items-center justify-between flex-wrap gap-2 pb-3.5 border-b border-white/5">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400 shrink-0">
              <Activity className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-[13.5px] font-bold text-slate-100">
                Dòng Thời gian Sự kiện An ninh Mới nhất từ Oracle (4 sự kiện gần nhất)
              </h2>
              <p className="text-[11px] text-slate-400">
                Nhấn vào sự kiện để kiểm tra nhanh, đánh dấu đã duyệt hoặc Reset trực tiếp sau khi xử lý
              </p>
            </div>
          </div>

          {/* Direct Navigation Shortcuts to Specialized Tabs */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => onNavigateTab('alerts')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#131e33] border border-sky-500/20 text-slate-200 hover:text-white hover:border-sky-400 text-[11.5px] font-semibold transition-colors cursor-pointer"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              <span>Tất cả Cảnh báo ({alerts.length})</span>
            </button>
            <button
              onClick={() => onNavigateTab('fga')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#131e33] border border-sky-500/20 text-slate-200 hover:text-white hover:border-sky-400 text-[11.5px] font-semibold transition-colors cursor-pointer"
            >
              <Target className="w-3.5 h-3.5 text-purple-400" />
              <span>Bẫy FGA ({fgaEvents.length})</span>
            </button>
            <button
              onClick={() => onNavigateTab('triggers')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#131e33] border border-sky-500/20 text-slate-200 hover:text-white hover:border-sky-400 text-[11.5px] font-semibold transition-colors cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>Trigger ({triggers.length})</span>
            </button>
          </div>
        </div>

        {alerts.length === 0 ? (
          <div className="py-8 text-center flex flex-col items-center gap-2.5">
            <CheckCircle2 className="w-8 h-8 text-emerald-400" />
            <div className="text-[12.5px] font-semibold text-slate-200">
              Hệ thống đang ở trạng thái An toàn (0 cảnh báo). Hãy thực thi câu lệnh trên Oracle SQL Developer để giám sát thời gian thực.
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
            {alerts.slice(0, 4).map((a) => {
              const color = getRiskColorHex(a.risk_score);
              return (
                <div
                  key={a.key}
                  onClick={() => onOpenAlertModal(a)}
                  className={`p-3.5 rounded-lg bg-[#0b1322] border transition-all cursor-pointer flex items-start justify-between gap-3 group ${
                    a.reviewed
                      ? 'border-emerald-500/30 bg-emerald-950/10 opacity-80'
                      : 'border-white/5 hover:border-sky-500/35'
                  }`}
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400 flex-wrap">
                      <span className="font-bold text-sky-300">{a.user}</span>
                      <span>·</span>
                      <span className="tabular-nums">{a.time}</span>
                      <span>·</span>
                      <span style={{ color }} className="font-bold tabular-nums">
                        Risk {a.risk_score}/100
                      </span>
                      {a.reviewed && (
                        <span className="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[9.5px] font-bold">
                          ĐÃ DUYỆT
                        </span>
                      )}
                    </div>
                    <div className="text-[12.5px] font-bold text-slate-100 truncate group-hover:text-sky-300 transition-colors">
                      {a.attack_type}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 truncate">
                      {a.details}
                    </div>
                  </div>
                  <div
                    className="flex items-center gap-1 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      onClick={() => onToggleReviewAlert(a.key)}
                      aria-label={a.reviewed ? 'Bỏ đánh dấu đã duyệt' : 'Đánh dấu đã kiểm duyệt'}
                      title={a.reviewed ? 'Đã kiểm duyệt (Nhấn để hoàn tác)' : 'Đánh dấu đã kiểm duyệt'}
                      className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
                        a.reviewed
                          ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                          : 'bg-[#131e33] border-white/10 text-slate-400 hover:text-emerald-300'
                      }`}
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => onDismissAlert(a.key)}
                      aria-label={`Reset cảnh báo ${a.attack_type}`}
                      title="Đã duyệt & Reset cảnh báo này"
                      className="p-1.5 rounded-lg bg-[#131e33] border border-amber-500/25 text-amber-300 hover:bg-amber-500/20 transition-colors cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => onOpenAlertModal(a)}
                      aria-label={`Xem chi tiết cảnh báo ${a.attack_type}`}
                      title="Xem chi tiết"
                      className="p-1.5 rounded-lg bg-[#131e33] border border-sky-500/20 text-slate-300 group-hover:text-white cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
};
