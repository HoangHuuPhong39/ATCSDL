import React, { useMemo, useState } from 'react';
import {
  Target,
  CheckCircle2,
  CheckCheck,
  Trash2,
  Eye,
  Code,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { FgaEvent } from '../../types/ids';
import { maskUsername } from '../../utils/privacy';

interface FgaTabProps {
  fgaEvents: FgaEvent[];
  onToggleReviewFga: (index: number) => void;
  onMarkAllFgaReviewed: () => void;
  onResetReviewedFga: () => void;
  onClearSingleFga: (index: number) => void;
  onClearAllFga: () => void;
  onOpenOracleBridge?: () => void;
  onOpenFgaModal?: (event: FgaEvent) => void;
}

export const FgaTab: React.FC<FgaTabProps> = ({
  fgaEvents,
  onToggleReviewFga,
  onMarkAllFgaReviewed,
  onResetReviewedFga,
  onClearSingleFga,
  onClearAllFga,
  onOpenFgaModal,
}) => {
  const [confirmClearAll, setConfirmClearAll] = useState(false);
  const [showCode1, setShowCode1] = useState(false);
  const [showCode2, setShowCode2] = useState(false);

  const reviewedCount = useMemo(() => fgaEvents.filter((e) => e.reviewed).length, [fgaEvents]);
  const pendingCount = fgaEvents.length - reviewedCount;

  return (
    <div className="space-y-4">
      {/* Policy Concept Cards (1-line description + Collapsible Code block) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Policy 1: Honeytoken Trap */}
        <div className="bg-[var(--surface)] border border-[var(--line)] rounded-xl p-3.5 transition-colors">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="w-2 h-2 rounded-full bg-[var(--danger)] shrink-0" />
              <h3 className="font-semibold text-[var(--text-1)] text-xs truncate">
                FGA_HONEYTOKEN_TRAP
              </h3>
            </div>
            <button
              type="button"
              onClick={() => setShowCode1((prev) => !prev)}
              className="inline-flex items-center gap-1 text-xs text-[var(--text-3)] hover:text-[var(--text-1)] cursor-pointer focus-visible:ring"
            >
              <Code className="w-3 h-3" />
              <span>{showCode1 ? 'Ẩn mã' : 'Xem mã'}</span>
              {showCode1 ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
          <p className="text-xs text-[var(--text-3)] mt-1.5 truncate">
            Bẫy Canary Token trên bản ghi <code className="text-[var(--danger)] font-mono font-semibold">MANV = &apos;NV_TRAP&apos;</code> (Lương 99,999) — Zero False Positive.
          </p>
          {showCode1 && (
            <div className="mt-2.5 bg-[var(--surface-hover)] p-2 rounded-lg border border-[var(--line)] font-mono text-xs text-[var(--accent)] break-all select-all">
              DBMS_FGA.ADD_POLICY(object_name=&gt;&apos;NV&apos;, policy_name=&gt;&apos;FGA_HONEYTOKEN_TRAP&apos;, audit_condition=&gt;&apos;manv=&apos;&apos;NV_TRAP&apos;&apos;&apos;);
            </div>
          )}
        </div>

        {/* Policy 2: High Salary Access */}
        <div className="bg-[var(--surface)] border border-[var(--line)] rounded-xl p-3.5 transition-colors">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="w-2 h-2 rounded-full bg-[var(--accent)] shrink-0" />
              <h3 className="font-semibold text-[var(--text-1)] text-xs truncate">
                FGA_HIGH_SALARY_ACCESS
              </h3>
            </div>
            <button
              type="button"
              onClick={() => setShowCode2((prev) => !prev)}
              className="inline-flex items-center gap-1 text-xs text-[var(--text-3)] hover:text-[var(--text-1)] cursor-pointer focus-visible:ring"
            >
              <Code className="w-3 h-3" />
              <span>{showCode2 ? 'Ẩn mã' : 'Xem mã'}</span>
              {showCode2 ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          </div>
          <p className="text-xs text-[var(--text-3)] mt-1.5 truncate">
            Giám sát truy vấn cột nhạy cảm <code className="text-[var(--accent)] font-mono">LUONG, CMND</code> khi <code className="text-[var(--accent)] font-mono font-semibold">LUONG &gt;= 1000</code>.
          </p>
          {showCode2 && (
            <div className="mt-2.5 bg-[var(--surface-hover)] p-2 rounded-lg border border-[var(--line)] font-mono text-xs text-[var(--accent)] break-all select-all">
              DBMS_FGA.ADD_POLICY(object_name=&gt;&apos;NV&apos;, policy_name=&gt;&apos;FGA_HIGH_SALARY_ACCESS&apos;, audit_condition=&gt;&apos;luong&gt;=1000&apos;, audit_column=&gt;&apos;LUONG, CMND&apos;);
            </div>
          )}
        </div>
      </div>

      {/* Main FGA Events Table */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        {/* Header Toolbar */}
        <div className="p-3 px-4 border-b border-[var(--line)] flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2 min-w-0">
            <Target className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <h2 className="text-sm font-semibold text-[var(--text-1)] truncate">
              Nhật ký bẫy FGA ({fgaEvents.length})
            </h2>
          </div>

          {/* Action buttons (Ghost + Trash icon) */}
          <div className="flex items-center gap-1.5 shrink-0">
            {fgaEvents.length > 0 && pendingCount > 0 && (
              <button
                type="button"
                onClick={onMarkAllFgaReviewed}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[var(--ok-soft)] border border-[var(--ok)]/30 text-[var(--ok)] hover:bg-[var(--ok-soft)]/80 text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
                title="Đánh dấu tất cả sự kiện FGA đã duyệt"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Duyệt ({pendingCount})</span>
              </button>
            )}

            {reviewedCount > 0 && (
              <button
                type="button"
                onClick={onResetReviewedFga}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[var(--line)] hover:border-[var(--danger)] text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
                title="Reset các sự kiện đã kiểm duyệt"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Reset đã duyệt ({reviewedCount})</span>
              </button>
            )}

            {fgaEvents.length > 0 && (
              confirmClearAll ? (
                <div className="inline-flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => {
                      onClearAllFga();
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
                  title="Xóa toàn bộ sự kiện FGA"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Xóa hết</span>
                </button>
              )
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          {fgaEvents.length === 0 ? (
            <div className="py-12 text-center text-[var(--text-3)] flex flex-col items-center gap-2 text-xs">
              <CheckCircle2 className="w-8 h-8 text-[var(--ok)]" />
              <span>Chưa có sự kiện bẫy FGA nào được kích hoạt.</span>
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5 w-12 text-center">Duyệt</th>
                  <th className="py-2.5 px-3.5 w-24">Giờ</th>
                  <th className="py-2.5 px-3.5 w-24">User</th>
                  <th className="py-2.5 px-3.5 w-44">Policy</th>
                  <th className="py-2.5 px-3.5 max-w-[320px]">Câu lệnh SQL</th>
                  <th className="py-2.5 px-3.5 w-20 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--line)]">
                {fgaEvents.map((e, idx) => {
                  const isTrap = String(e.FGA_POLICY_NAME || '').includes('HONEYTOKEN') || String(e.SQL_TEXT || '').includes('NV_TRAP');
                  return (
                    <tr
                      key={`${e.EVENT_TIMESTAMP}-${e.DBUSERNAME}-${idx}`}
                      onClick={() => onOpenFgaModal && onOpenFgaModal(e)}
                      className={`hover:bg-[var(--surface-hover)] transition-colors cursor-pointer group ${
                        isTrap ? 'bg-[var(--danger-soft)]/20' : ''
                      } ${e.reviewed ? 'opacity-70 bg-[var(--surface-subtle)]/40' : ''}`}
                    >
                      {/* Review Toggle */}
                      <td className="py-2.5 px-3.5 text-center" onClick={(ev) => ev.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => onToggleReviewFga(idx)}
                          aria-label={e.reviewed ? 'Bỏ đánh dấu đã duyệt' : 'Đánh dấu đã duyệt'}
                          className={`w-6 h-6 rounded flex items-center justify-center transition-colors cursor-pointer focus-visible:ring mx-auto ${
                            e.reviewed
                              ? 'text-[var(--ok)]'
                              : 'text-[var(--text-3)] hover:text-[var(--ok)]'
                          }`}
                        >
                          <CheckCircle2 className="w-4 h-4" />
                        </button>
                      </td>

                      {/* Time */}
                      <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)] whitespace-nowrap tabular-nums">
                        {e.EVENT_TIMESTAMP ? (e.EVENT_TIMESTAMP.includes(' ') ? e.EVENT_TIMESTAMP.split(' ')[1] : e.EVENT_TIMESTAMP) : '—'}
                      </td>

                      {/* User */}
                      <td className="py-2.5 px-3.5 font-mono font-semibold text-[var(--text-1)] whitespace-nowrap">
                        {maskUsername(e.DBUSERNAME)}
                      </td>

                      {/* Policy Name */}
                      <td className="py-2.5 px-3.5 font-mono font-medium whitespace-nowrap">
                        <span className={isTrap ? 'text-[var(--danger)]' : 'text-[var(--text-1)]'}>
                          {e.FGA_POLICY_NAME}
                        </span>
                      </td>

                      {/* SQL (Truncated) */}
                      <td className="py-2.5 px-3.5 max-w-[320px]">
                        <span className="soc-sql-chip truncate block" title={e.SQL_TEXT}>
                          {e.SQL_TEXT}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-2.5 px-3.5 text-right whitespace-nowrap" onClick={(ev) => ev.stopPropagation()}>
                        <div className="inline-flex items-center gap-1">
                          {onOpenFgaModal && (
                            <button
                              type="button"
                              onClick={() => onOpenFgaModal(e)}
                              className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--accent)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer focus-visible:ring"
                              title="Xem chi tiết"
                              aria-label="Xem chi tiết sự kiện FGA"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => onClearSingleFga(idx)}
                            className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] transition-colors cursor-pointer focus-visible:ring"
                            title="Xóa sự kiện này"
                            aria-label="Xóa sự kiện FGA"
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
