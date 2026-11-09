import React, { useState, useMemo } from 'react';
import {
  FileText,
  Search,
  Eye,
  CheckCircle2,
  CheckCheck,
  Trash2,
} from 'lucide-react';
import { AuditLogRow } from '../../types/ids';

interface AuditTabProps {
  auditLogs: AuditLogRow[];
  onOpenAuditModal: (row: AuditLogRow) => void;
  onToggleReviewAudit: (index: number) => void;
  onMarkAllAuditReviewed: () => void;
  onResetReviewedAudit: () => void;
  onClearSingleAudit: (index: number) => void;
  onClearAllAudit: () => void;
  onOpenOracleBridge?: () => void;
  onExportAuditPdf?: () => void;
}

export const AuditTab: React.FC<AuditTabProps> = ({
  auditLogs,
  onOpenAuditModal,
  onToggleReviewAudit,
  onMarkAllAuditReviewed,
  onResetReviewedAudit,
  onClearSingleAudit,
  onClearAllAudit,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterReview, setFilterReview] = useState<'ALL' | 'PENDING' | 'REVIEWED'>('ALL');
  const [confirmClearAll, setConfirmClearAll] = useState(false);

  const reviewedCount = useMemo(() => auditLogs.filter((r) => r.reviewed).length, [auditLogs]);
  const pendingCount = auditLogs.length - reviewedCount;

  const filteredWithIndex = useMemo(() => {
    return auditLogs
      .map((row, originalIndex) => ({ row, originalIndex }))
      .filter(({ row }) => {
        if (filterReview === 'PENDING' && row.reviewed) return false;
        if (filterReview === 'REVIEWED' && !row.reviewed) return false;
        if (!searchTerm) return true;
        const term = searchTerm.toLowerCase();
        return (
          (row.DBUSERNAME || '').toLowerCase().includes(term) ||
          (row.ACTION_NAME || '').toLowerCase().includes(term) ||
          (row.OBJECT_NAME || '').toLowerCase().includes(term) ||
          (row.FGA_POLICY_NAME || '').toLowerCase().includes(term) ||
          (row.CLIENT_PROGRAM_NAME || '').toLowerCase().includes(term) ||
          (row.USERHOST || '').toLowerCase().includes(term) ||
          (row.SQL_TEXT || '').toLowerCase().includes(term) ||
          String(row.RETURN_CODE || '').toLowerCase().includes(term)
        );
      });
  }, [auditLogs, searchTerm, filterReview]);

  return (
    <div className="space-y-4">
      {/* 1-Row Compact Filter & Action Toolbar */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl p-3 flex flex-col md:flex-row md:items-center justify-between gap-3 transition-colors">
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          {/* Review Filter Dropdown */}
          <select
            value={filterReview}
            onChange={(e) => setFilterReview(e.target.value as 'ALL' | 'PENDING' | 'REVIEWED')}
            className="bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] text-xs rounded-lg px-2.5 py-1.5 outline-none focus-visible:ring cursor-pointer"
          >
            <option value="ALL">Mọi trạng thái ({auditLogs.length})</option>
            <option value="PENDING">Chờ duyệt ({pendingCount})</option>
            <option value="REVIEWED">Đã duyệt ({reviewedCount})</option>
          </select>

          {/* Search box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[var(--text-3)] absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Tìm user, policy, SQL..."
              className="bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg text-[var(--text-1)] pl-8 pr-3 py-1 text-xs outline-none focus:border-[var(--accent)] w-48 sm:w-64 font-sans transition-all"
            />
          </div>
        </div>

        {/* Action Buttons (Ghost + Trash icon) */}
        <div className="flex items-center gap-1.5 shrink-0">
          {auditLogs.length > 0 && pendingCount > 0 && (
            <button
              type="button"
              onClick={onMarkAllAuditReviewed}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[var(--ok-soft)] border border-[var(--ok)]/30 text-[var(--ok)] hover:bg-[var(--ok-soft)]/80 text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
              title="Đánh dấu tất cả nhật ký đã duyệt"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>Duyệt ({pendingCount})</span>
            </button>
          )}

          {reviewedCount > 0 && (
            <button
              type="button"
              onClick={onResetReviewedAudit}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[var(--line)] hover:border-[var(--danger)] text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
              title="Reset các bản ghi đã kiểm duyệt"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Reset đã duyệt ({reviewedCount})</span>
            </button>
          )}

          {auditLogs.length > 0 && (
            confirmClearAll ? (
              <div className="inline-flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => {
                    onClearAllAudit();
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
                title="Xóa toàn bộ nhật ký kiểm toán"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Xóa hết</span>
              </button>
            )
          )}
        </div>
      </section>

      {/* Main Audit Trail Table */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="overflow-x-auto">
          {filteredWithIndex.length === 0 ? (
            <div className="py-12 text-center text-[var(--text-3)] flex flex-col items-center gap-2 text-xs">
              <CheckCircle2 className="w-8 h-8 text-[var(--ok)]" />
              <span>Không có bản ghi kiểm toán nào khớp bộ lọc.</span>
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5 w-12 text-center">Duyệt</th>
                  <th className="py-2.5 px-3.5 w-24">Giờ</th>
                  <th className="py-2.5 px-3.5 w-24">User</th>
                  <th className="py-2.5 px-3.5 w-36">Loại / Policy</th>
                  <th className="py-2.5 px-3.5 w-20">Action</th>
                  <th className="py-2.5 px-3.5 w-28">Đối tượng</th>
                  <th className="py-2.5 px-3.5 max-w-[280px]">Câu lệnh SQL</th>
                  <th className="py-2.5 px-3.5 w-20">Mã</th>
                  <th className="py-2.5 px-3.5 w-20 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--line)]">
                {filteredWithIndex.map(({ row: r, originalIndex }) => {
                  const code = Number(r.RETURN_CODE || 0);
                  const isTrap = String(r.FGA_POLICY_NAME || '').includes('HONEYTOKEN');
                  const objFull =
                    r.OBJECT_SCHEMA && r.OBJECT_NAME
                      ? `${r.OBJECT_SCHEMA}.${r.OBJECT_NAME}`
                      : r.OBJECT_NAME || '—';

                  return (
                    <tr
                      key={`${r.EVENT_TIMESTAMP}-${r.DBUSERNAME}-${originalIndex}`}
                      onClick={() => onOpenAuditModal(r)}
                      className={`hover:bg-[var(--surface-hover)] transition-colors cursor-pointer group ${
                        isTrap ? 'bg-[var(--danger-soft)]/20' : ''
                      } ${r.reviewed ? 'opacity-70 bg-[var(--surface-subtle)]/40' : ''}`}
                    >
                      {/* Review toggle */}
                      <td className="py-2.5 px-3.5 text-center" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => onToggleReviewAudit(originalIndex)}
                          aria-label={r.reviewed ? 'Bỏ đánh dấu đã duyệt' : 'Đánh dấu đã duyệt'}
                          className={`w-6 h-6 rounded flex items-center justify-center transition-colors cursor-pointer focus-visible:ring mx-auto ${
                            r.reviewed
                              ? 'text-[var(--ok)]'
                              : 'text-[var(--text-3)] hover:text-[var(--ok)]'
                          }`}
                        >
                          <CheckCircle2 className="w-4 h-4" />
                        </button>
                      </td>

                      {/* Time */}
                      <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)] whitespace-nowrap tabular-nums">
                        {r.EVENT_TIMESTAMP ? (r.EVENT_TIMESTAMP.includes(' ') ? r.EVENT_TIMESTAMP.split(' ')[1] : r.EVENT_TIMESTAMP) : '—'}
                      </td>

                      {/* User */}
                      <td className="py-2.5 px-3.5 font-mono font-semibold text-[var(--text-1)] whitespace-nowrap">
                        {r.DBUSERNAME}
                      </td>

                      {/* Policy / Audit Type */}
                      <td className="py-2.5 px-3.5 whitespace-nowrap font-mono text-[var(--text-2)]">
                        <span className="truncate block max-w-[130px]" title={r.FGA_POLICY_NAME || r.AUDIT_TYPE || 'Standard'}>
                          {r.FGA_POLICY_NAME || r.AUDIT_TYPE || 'Standard'}
                        </span>
                      </td>

                      {/* Action */}
                      <td className="py-2.5 px-3.5 font-mono font-medium text-[var(--accent)]">
                        {r.ACTION_NAME}
                      </td>

                      {/* Object */}
                      <td className="py-2.5 px-3.5 font-mono text-[var(--text-2)] truncate max-w-[110px]" title={objFull}>
                        {objFull}
                      </td>

                      {/* SQL Text (Truncated) */}
                      <td className="py-2.5 px-3.5 max-w-[280px]">
                        {r.SQL_TEXT ? (
                          <span className="soc-sql-chip truncate block" title={r.SQL_TEXT}>
                            {r.SQL_TEXT}
                          </span>
                        ) : (
                          <span className="text-[var(--text-3)] font-mono">—</span>
                        )}
                      </td>

                      {/* Return Code */}
                      <td className="py-2.5 px-3.5 font-mono whitespace-nowrap">
                        <span className={code === 0 ? 'text-[var(--ok)]' : 'text-[var(--danger)] font-semibold'}>
                          {code === 0 ? '0' : `ORA-${code}`}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-2.5 px-3.5 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="inline-flex items-center gap-1">
                          <button
                            type="button"
                            onClick={() => onOpenAuditModal(r)}
                            className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--accent)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer focus-visible:ring"
                            title="Xem chi tiết"
                            aria-label="Xem chi tiết bản ghi"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onClearSingleAudit(originalIndex)}
                            className="w-7 h-7 rounded flex items-center justify-center text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] transition-colors cursor-pointer focus-visible:ring"
                            title="Xóa bản ghi này"
                            aria-label="Xóa bản ghi"
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
