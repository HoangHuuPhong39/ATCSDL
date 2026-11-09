import React from 'react';
import { Database, AlertTriangle, Zap, ShieldAlert, ArrowUpRight } from 'lucide-react';
import { ActiveTab, Metrics } from '../types/ids';
import { StatusDot } from './ui/StatusDot';

interface KpiCardsProps {
  metrics: Metrics;
  onNavigateTab?: (tab: ActiveTab) => void;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ metrics, onNavigateTab }) => {
  const unifiedCount = Math.max(0, metrics.audit_count - metrics.fga_count);

  const isCritical = metrics.max_risk >= 80;
  const isElevated = metrics.max_risk >= 50 && metrics.max_risk < 80;

  return (
    <section aria-label="Chỉ số an ninh cốt lõi" className="soc-kpi-grid">
      {/* Card 1: Tổng sự kiện Audit & FGA */}
      <button
        type="button"
        onClick={() => onNavigateTab && onNavigateTab('audit')}
        className="bg-[var(--surface)] border border-[var(--line)] hover:border-[var(--border-hover)] rounded-xl p-4 text-left flex flex-col justify-between transition-colors cursor-pointer focus-visible:ring group"
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-[var(--text-3)] flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-[var(--accent)]" />
            <span>Tổng sự kiện</span>
          </span>
          <ArrowUpRight className="w-3.5 h-3.5 text-[var(--text-3)] opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
        <div className="mt-3">
          <div className="text-2xl sm:text-3xl font-semibold text-[var(--text-1)] font-mono tracking-tight tabular-nums">
            {metrics.audit_count}
          </div>
          <div className="text-xs text-[var(--text-3)] font-mono mt-1 truncate">
            FGA: {metrics.fga_count} · Unified: {unifiedCount}
          </div>
        </div>
      </button>

      {/* Card 2: Cảnh báo IDS */}
      <button
        type="button"
        onClick={() => onNavigateTab && onNavigateTab('alerts')}
        className="bg-[var(--surface)] border border-[var(--line)] hover:border-[var(--border-hover)] rounded-xl p-4 text-left flex flex-col justify-between transition-colors cursor-pointer focus-visible:ring group"
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-[var(--text-3)] flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-[var(--warn)]" />
            <span>Cảnh báo IDS</span>
          </span>
          <ArrowUpRight className="w-3.5 h-3.5 text-[var(--text-3)] opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
        <div className="mt-3">
          <div className="text-2xl sm:text-3xl font-semibold text-[var(--text-1)] font-mono tracking-tight tabular-nums">
            {metrics.alert_count}
          </div>
          <div className="text-xs text-[var(--text-3)] mt-1 truncate flex items-center gap-1.5">
            <StatusDot status={metrics.alert_count > 0 ? 'danger' : 'ok'} size="sm" />
            <span>{metrics.alert_count > 0 ? `${metrics.alert_count} sự kiện cần duyệt` : 'An toàn'}</span>
          </div>
        </div>
      </button>

      {/* Card 3: Vi phạm bị chặn */}
      <button
        type="button"
        onClick={() => onNavigateTab && onNavigateTab('triggers')}
        className="bg-[var(--surface)] border border-[var(--line)] hover:border-[var(--border-hover)] rounded-xl p-4 text-left flex flex-col justify-between transition-colors cursor-pointer focus-visible:ring group"
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-[var(--text-3)] flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-[var(--accent)]" />
            <span>Vi phạm bị chặn</span>
          </span>
          <ArrowUpRight className="w-3.5 h-3.5 text-[var(--text-3)] opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
        <div className="mt-3">
          <div className="text-2xl sm:text-3xl font-semibold text-[var(--text-1)] font-mono tracking-tight tabular-nums">
            {metrics.trigger_count}
          </div>
          <div className="text-xs text-[var(--text-3)] mt-1 truncate">
            Autonomous Trigger (ORA-20001/2)
          </div>
        </div>
      </button>

      {/* Card 4: Thẻ rủi ro cao nhất (Đổi màu theo POSTURE - chỉ báo chính của trang) */}
      <button
        type="button"
        onClick={() => onNavigateTab && onNavigateTab('ips')}
        className={`rounded-xl p-4 text-left flex flex-col justify-between transition-colors cursor-pointer focus-visible:ring group ${
          isCritical
            ? 'bg-[var(--danger-soft)]/20 border border-[var(--danger)]/50'
            : isElevated
            ? 'bg-[var(--warn-soft)]/20 border border-[var(--warn)]/50'
            : 'bg-[var(--surface)] border border-[var(--line)] hover:border-[var(--border-hover)]'
        }`}
      >
        <div className="flex items-center justify-between">
          <span
            className={`text-xs font-medium flex items-center gap-1.5 ${
              isCritical
                ? 'text-[var(--danger)]'
                : isElevated
                ? 'text-[var(--warn)]'
                : 'text-[var(--text-3)]'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>
              {isCritical
                ? 'POSTURE: CRITICAL'
                : isElevated
                ? 'POSTURE: ELEVATED'
                : 'POSTURE: SECURE'}
            </span>
          </span>
          <ArrowUpRight className="w-3.5 h-3.5 text-[var(--text-3)] opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
        <div className="mt-3">
          <div
            className={`text-2xl sm:text-3xl font-semibold font-mono tracking-tight tabular-nums ${
              isCritical
                ? 'text-[var(--danger)]'
                : isElevated
                ? 'text-[var(--warn)]'
                : 'text-[var(--text-1)]'
            }`}
          >
            {metrics.max_risk}
            <span className="text-sm font-normal text-[var(--text-3)] ml-1">/100</span>
          </div>
          <div className="text-xs text-[var(--text-3)] font-mono mt-1 truncate">
            L3 Khóa: {metrics.locked_count} · L2 Read-Only: {metrics.readonly_count}
          </div>
        </div>
      </button>
    </section>
  );
};
