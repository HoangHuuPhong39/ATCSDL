import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Trash2,
  Eye,
  Search,
  CheckCircle2,
  CheckCheck,
} from 'lucide-react';
import { AlertItem, Severity } from '../../types/ids';
import { classifyAlertGroup, computeAttackBreakdown, getRiskColorHex, AttackGroup } from '../../utils/analytics';
import { maskUsername } from '../../utils/privacy';
import { StatusDot } from '../ui/StatusDot';

interface AlertsTabProps {
  alerts: AlertItem[];
  privacyMode?: boolean;
  onOpenAlertModal: (alert: AlertItem) => void;
  onDismissAlert: (key: string) => void;
  onToggleReviewAlert: (key: string) => void;
  onMarkAllAlertsReviewed: () => void;
  onResetReviewedAlerts: () => void;
  onClearAlerts: (target: 'ids' | 'triggers' | 'all') => void;
  onOpenOracleBridge?: () => void;
  onExportAlertsPdf?: () => void;
}

export const AlertsTab: React.FC<AlertsTabProps> = ({
  alerts,
  privacyMode = false,
  onOpenAlertModal,
  onDismissAlert,
  onToggleReviewAlert,
  onMarkAllAlertsReviewed,
  onResetReviewedAlerts,
  onClearAlerts,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | Severity>('ALL');
  const [filterGroup, setFilterGroup] = useState<'ALL' | AttackGroup>('ALL');
  const [filterReview, setFilterReview] = useState<'ALL' | 'PENDING' | 'REVIEWED'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [confirmClearAll, setConfirmClearAll] = useState(false);

  const breakdown = useMemo(() => computeAttackBreakdown(alerts), [alerts]);
  const reviewedCount = useMemo(() => alerts.filter((a) => a.reviewed).length, [alerts]);
  const pendingCount = alerts.length - reviewedCount;

  const filtered = useMemo(() => {
    return alerts.filter((a) => {
      if (filterSeverity !== 'ALL' && a.severity !== filterSeverity) return false;
      if (filterGroup !== 'ALL' && classifyAlertGroup(a) !== filterGroup) return false;
      if (filterReview === 'PENDING' && a.reviewed) return false;
      if (filterReview === 'REVIEWED' && !a.reviewed) return false;
      if (!searchTerm) return true;
      const term = searchTerm.toLowerCase();
      return (
        a.user.toLowerCase().includes(term) ||
        a.attack_type.toLowerCase().includes(term) ||
        a.details.toLowerCase().includes(term) ||
        a.context.toLowerCase().includes(term)
      );
    });
  }, [alerts, filterSeverity, filterGroup, filterReview, searchTerm]);

  return (
    <div className="space-y-4">
      {/* 1-Row Compact Filter & Action Toolbar */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl p-3 flex flex-col md:flex-row md:items-center justify-between gap-3 transition-colors">
        {/* Filters Group (Single clean row) */}
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          {/* Attack Group Segmented */}
          <div className="flex items-center bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setFilterGroup('ALL')}
              className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                filterGroup === 'ALL'
                  ? 'bg-[var(--surface)] text-[var(--text-1)] font-medium shadow-sm'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              Tất cả ({breakdown.total})
            </button>
            <button
              type="button"
              onClick={() => setFilterGroup('DBMS')}
              className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                filterGroup === 'DBMS'
                  ? 'bg-[var(--surface)] text-[var(--danger)] font-medium shadow-sm'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              DBMS ({breakdown.dbmsCount})
            </button>
            <button
              type="button"
              onClick={() => setFilterGroup('SDB')}
              className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                filterGroup === 'SDB'
                  ? 'bg-[var(--surface)] text-[var(--warn)] font-medium shadow-sm'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              SDB ({breakdown.sdbCount})
            </button>
          </div>

          {/* Review Filter Dropdown/Segmented */}
          <select
            value={filterReview}
            onChange={(e) => setFilterReview(e.target.value as 'ALL' | 'PENDING' | 'REVIEWED')}
            className="bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] text-xs rounded-lg px-2.5 py-1.5 outline-none focus-visible:ring cursor-pointer"
          >
            <option value="ALL">Mọi trạng thái</option>
            <option value="PENDING">Chờ duyệt ({pendingCount})</option>
            <option value="REVIEWED">Đã duyệt ({reviewedCount})</option>
          </select>

          {/* Severity Filter Dropdown */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value as 'ALL' | Severity)}
            className="bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] text-xs rounded-lg px-2.5 py-1.5 outline-none focus-visible:ring cursor-pointer"
          >
            <option value="ALL">Mọi mức độ</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>

          {/* Search box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[var(--text-3)] absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Tìm user, SQL..."
              className="bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg text-[var(--text-1)] pl-8 pr-3 py-1 text-xs outline-none focus:border-[var(--accent)] w-36 sm:w-48 font-sans transition-all"
            />
          </div>
        </div>

        {/* Action Buttons (Consistent ghost + trash styling) */}
        <div className="flex items-center gap-1.5 shrink-0">
          {pendingCount > 0 && (
            <button
              type="button"
              onClick={onMarkAllAlertsReviewed}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[var(--ok-soft)] border border-[var(--ok)]/30 text-[var(--ok)] hover:bg-[var(--ok-soft)]/80 text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
              title="Đánh dấu tất cả cảnh báo đã duyệt"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>Duyệt ({pendingCount})</span>
            </button>
          )}

          {reviewedCount > 0 && (
            <button
              type="button"
              onClick={onResetReviewedAlerts}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[var(--line)] hover:border-[var(--danger)] text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
              title="Reset các cảnh báo đã kiểm duyệt"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Reset đã duyệt ({reviewedCount})</span>
            </button>
          )}

          {alerts.length > 0 && (
            confirmClearAll ? (
              <div className="inline-flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => {
                    onClearAlerts('ids');
                    setConfirmClearAll(false);
                  }}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-[var(--danger)] text-white text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Xác nhận xóa?</span>
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmClearAll(false)}
                  className="px-2 py-1.5 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] text-xs cursor-pointer focus-visible:ring"
                >
                  Hủy
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmClearAll(true)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[var(--line)] hover:border-[var(--danger)] text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
                title="Xóa toàn bộ cảnh báo"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Xóa hết</span>
              </button>
            )
          )}
        </div>
      </section>

      {/* Main Alerts Table (Essential columns only, non-overflowing, sticky header) */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="overflow-x-auto">
          {filtered.length === 0 ? (
            <div className="py-12 text-center text-[var(--text-3)] flex flex-col items-center gap-2 text-xs">
              <CheckCircle2 className="w-8 h-8 text-[var(--ok)]" />
              <span>Không có cảnh báo nào phù hợp với bộ lọc hiện tại.</span>
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5 w-12 text-center">Duyệt</th>
                  <th className="py-2.5 px-3.5 w-24">Giờ</th>
                  <th className="py-2.5 px-3.5 w-24">User</th>
                  <th className="py-2.5 px-3.5 min-w-[260px] flex-1">Loại tấn công</th>
                  <th className="py-2.5 px-3.5 max-w-[280px]">Câu lệnh SQL</th>
                  <th className="py-2.5 px-3.5 w-28">Mức độ / Risk</th>
                  <th className="py-2.5 px-3.5 w-20 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--line)]">
                {filtered.map((a) => {
                  const color = getRiskColorHex(a.risk_score);
                  const isCritical = a.risk_score >= 80;
                  const isHigh = a.risk_score >= 50 && a.risk_score < 80;

                  return (
                    <tr
                      key={a.key}
                      onClick={() => onOpenAlertModal(a)}
                      className={`hover:bg-[var(--surface-hover)] transition-colors cursor-pointer group ${
                        a.reviewed ? 'opacity-70 bg-[var(--surface-subtle)]/40' : ''
                      }`}
                    >
                      {/* 1. Review status toggle */}
                      <td className="py-2.5 px-3.5 text-center" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => onToggleReviewAlert(a.key)}
                          aria-label={a.reviewed ? 'Bỏ đánh dấu đã duyệt' : 'Đánh dấu đã duyệt'}
                          className={`w-6 h-6 rounded flex items-center justify-center transition-colors cursor-pointer focus-visible:ring mx-auto ${
                            a.reviewed
                              ? 'text-[var(--ok)]'
                              : 'text-[var(--text-3)] hover:text-[var(--ok)]'
                          }`}
                        >
                          <CheckCircle2 className="w-4 h-4" />
                        </button>
                      </td>

                      {/* 2. Time */}
                      <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)] whitespace-nowrap tabular-nums">
                        {a.time ? (a.time.includes(' ') ? a.time.split(' ')[1] : a.time) : '—'}
                      </td>

                      {/* 3. User */}
                      <td className="py-2.5 px-3.5 font-mono font-semibold text-[var(--text-1)] whitespace-nowrap">
                        {maskUsername(a.user, privacyMode)}
                      </td>

                      {/* 4. Attack Type (Expanded width) */}
                      <td className="py-2.5 px-3.5 font-medium text-[var(--text-1)]" title={a.attack_type}>
                        <div className="flex items-center gap-1.5">
                          <StatusDot status={isCritical ? 'danger' : isHigh ? 'warn' : 'ok'} size="sm" />
                          <span className="truncate max-w-md">{a.attack_type}</span>
                        </div>
                      </td>

                      {/* 5. SQL Text (Truncated to 1 line) */}
                      <td className="py-2.5 px-3.5 max-w-[280px]">
                        <span className="soc-sql-chip truncate block" title={a.details}>
                          {a.details}
                        </span>
                      </td>

                      {/* 6. Severity & Risk Score */}
                      <td className="py-2.5 px-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 font-mono">
                          <span
                            className="font-semibold tabular-nums"
                            style={{ color }}
                          >
                            {a.risk_score}
                          </span>
                          <span className="text-[var(--text-3)] text-xs">/ 100</span>
                        </div>
                      </td>

                      {/* 7. Action buttons (Ghost + Trash icon) */}
                      <td className="py-2.5 px-3.5 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            onClick={() => onOpenAlertModal(a)}
                            className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--accent)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer focus-visible:ring"
                            title="Xem chi tiết"
                            aria-label="Xem chi tiết cảnh báo"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onDismissAlert(a.key)}
                            className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] transition-colors cursor-pointer focus-visible:ring"
                            title="Xóa cảnh báo này"
                            aria-label="Xóa cảnh báo"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
};
