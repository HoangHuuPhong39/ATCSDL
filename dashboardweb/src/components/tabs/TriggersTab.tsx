import React, { useMemo, useState } from 'react';
import {
  Zap,
  Trash2,
  CheckCircle2,
  CheckCheck,
  Eye,
  BookOpen,
} from 'lucide-react';
import { TriggerAlert, ActiveTab } from '../../types/ids';
import { maskUsername } from '../../utils/privacy';

interface TriggersTabProps {
  triggers: TriggerAlert[];
  onToggleReviewTrigger: (id: number) => void;
  onMarkAllTriggersReviewed: () => void;
  onResetReviewedTriggers: () => void;
  onClearSingleTrigger: (id: number) => void;
  onClearAllTriggers: () => void;
  onOpenOracleBridge?: () => void;
  onNavigateTab?: (tab: ActiveTab) => void;
  onOpenTriggerModal?: (trigger: TriggerAlert) => void;
}

export const TriggersTab: React.FC<TriggersTabProps> = ({
  triggers,
  onToggleReviewTrigger,
  onMarkAllTriggersReviewed,
  onResetReviewedTriggers,
  onClearSingleTrigger,
  onClearAllTriggers,
  onNavigateTab,
  onOpenTriggerModal,
}) => {
  const [confirmClearAll, setConfirmClearAll] = useState(false);
  const reviewedCount = useMemo(() => triggers.filter((t) => t.reviewed).length, [triggers]);
  const pendingCount = triggers.length - reviewedCount;

  return (
    <div className="space-y-4">
      {/* Trigger Architecture Overview (1-line description + 2 compact rules) */}
      <div className="bg-[var(--surface)] border border-[var(--line)] rounded-xl p-3.5 transition-colors">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Zap className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <h2 className="text-sm font-semibold text-[var(--text-1)] truncate">
              Trigger bảo vệ nội sinh (SYS.TRG_PROTECT_NV)
            </h2>
          </div>

          {onNavigateTab && (
            <button
              type="button"
              onClick={() => onNavigateTab('docs')}
              className="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline cursor-pointer focus-visible:ring"
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Xem mã PL/SQL tại Báo cáo</span>
            </button>
          )}
        </div>

        <p className="text-xs text-[var(--text-3)] mt-1.5 truncate">
          Ghi log độc lập bằng <code className="text-[var(--accent)] font-mono">PRAGMA AUTONOMOUS_TRANSACTION</code> trước khi ném ngoại lệ chặn giao dịch.
        </p>

        {/* 2 Rules Compact Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 mt-3">
          <div className="bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg p-2.5 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <span className="font-semibold text-[var(--text-1)] text-xs block truncate">
                Chặn xóa nhân viên (DELETE)
              </span>
              <span className="text-xs text-[var(--text-3)] truncate block">
                Ngăn chặn phá hoại dữ liệu gốc
              </span>
            </div>
            <span className="font-mono text-xs text-[var(--danger)] font-bold shrink-0">
              ORA-20001
            </span>
          </div>

          <div className="bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg p-2.5 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <span className="font-semibold text-[var(--text-1)] text-xs block truncate">
                Chặn tăng lương &gt; 50% (UPDATE)
              </span>
              <span className="text-xs text-[var(--text-3)] truncate block">
                Chống can thiệp biển thủ lương
              </span>
            </div>
            <span className="font-mono text-xs text-[var(--warn)] font-bold shrink-0">
              ORA-20002
            </span>
          </div>
        </div>
      </div>

      {/* Main Triggers Table */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="p-3 px-4 border-b border-[var(--line)] flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2 min-w-0">
            <Zap className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <h2 className="text-sm font-semibold text-[var(--text-1)] truncate">
              Nhật ký trigger chặn ({triggers.length})
            </h2>
          </div>

          {/* Action buttons (Ghost + Trash icon) */}
          <div className="flex items-center gap-1.5 shrink-0">
            {triggers.length > 0 && pendingCount > 0 && (
              <button
                type="button"
                onClick={onMarkAllTriggersReviewed}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[var(--ok-soft)] border border-[var(--ok)]/30 text-[var(--ok)] hover:bg-[var(--ok-soft)]/80 text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
                title="Đánh dấu tất cả vi phạm trigger đã duyệt"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Duyệt ({pendingCount})</span>
              </button>
            )}

            {reviewedCount > 0 && (
              <button
                type="button"
                onClick={onResetReviewedTriggers}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[var(--line)] hover:border-[var(--danger)] text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
                title="Reset các sự kiện đã kiểm duyệt"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Reset đã duyệt ({reviewedCount})</span>
              </button>
            )}

            {triggers.length > 0 && (
              confirmClearAll ? (
                <div className="inline-flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => {
                      onClearAllTriggers();
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
                  title="Xóa toàn bộ bản ghi trigger"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Xóa hết</span>
                </button>
              )
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          {triggers.length === 0 ? (
            <div className="py-12 text-center text-[var(--text-3)] flex flex-col items-center gap-2 text-xs">
              <CheckCircle2 className="w-8 h-8 text-[var(--ok)]" />
              <span>Chưa có vi phạm nào bị trigger chặn đứng.</span>
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5 w-12 text-center">Duyệt</th>
                  <th className="py-2.5 px-3.5 w-24">Giờ</th>
                  <th className="py-2.5 px-3.5 w-24">User</th>
                  <th className="py-2.5 px-3.5 w-28">Mã lỗi</th>
                  <th className="py-2.5 px-3.5 w-24">Hành động</th>
                  <th className="py-2.5 px-3.5 max-w-[320px]">Chi tiết câu lệnh</th>
                  <th className="py-2.5 px-3.5 w-20 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--line)]">
                {triggers.map((t) => (
                  <tr
                    key={t.ALERT_ID}
                    onClick={() => onOpenTriggerModal && onOpenTriggerModal(t)}
                    className={`hover:bg-[var(--surface-hover)] transition-colors cursor-pointer group ${
                      t.reviewed ? 'opacity-70 bg-[var(--surface-subtle)]/40' : ''
                    }`}
                  >
                    {/* Review Toggle */}
                    <td className="py-2.5 px-3.5 text-center" onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => onToggleReviewTrigger(t.ALERT_ID)}
                        aria-label={t.reviewed ? 'Bỏ đánh dấu đã duyệt' : 'Đánh dấu đã duyệt'}
                        className={`w-6 h-6 rounded flex items-center justify-center transition-colors cursor-pointer focus-visible:ring mx-auto ${
                          t.reviewed
                            ? 'text-[var(--ok)]'
                            : 'text-[var(--text-3)] hover:text-[var(--ok)]'
                        }`}
                      >
                        <CheckCircle2 className="w-4 h-4" />
                      </button>
                    </td>

                    {/* Time */}
                    <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)] whitespace-nowrap tabular-nums">
                      {t.EVENT_TIME ? (t.EVENT_TIME.includes(' ') ? t.EVENT_TIME.split(' ')[1] : t.EVENT_TIME) : '—'}
                    </td>

                    {/* User */}
                    <td className="py-2.5 px-3.5 font-mono font-semibold text-[var(--text-1)] whitespace-nowrap">
                      {maskUsername(t.DB_USER)}
                    </td>

                    {/* Error Code */}
                    <td className="py-2.5 px-3.5 font-mono font-bold whitespace-nowrap text-[var(--danger)]">
                      {t.ATTACK_TYPE?.includes('SALARY') ? 'ORA-20002' : 'ORA-20001'}
                    </td>

                    {/* Attack Type */}
                    <td className="py-2.5 px-3.5 font-mono font-medium text-[var(--accent)] whitespace-nowrap">
                      {t.ATTACK_TYPE}
                    </td>

                    {/* SQL Details (Truncated) */}
                    <td className="py-2.5 px-3.5 max-w-[320px]">
                      <span className="soc-sql-chip truncate block" title={t.DETAILS}>
                        {t.DETAILS}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-2.5 px-3.5 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <div className="inline-flex items-center gap-1">
                        {onOpenTriggerModal && (
                          <button
                            type="button"
                            onClick={() => onOpenTriggerModal(t)}
                            className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--accent)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer focus-visible:ring"
                            title="Xem chi tiết"
                            aria-label="Xem chi tiết bản ghi trigger"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => onClearSingleTrigger(t.ALERT_ID)}
                          className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] transition-colors cursor-pointer focus-visible:ring"
                          title="Xóa bản ghi này"
                          aria-label="Xóa bản ghi trigger"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
};
