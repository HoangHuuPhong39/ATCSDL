import React, { useState, useMemo } from 'react';
import {
  FileText,
  Search,
  Eye,
  CheckCircle2,
  CheckCheck,
  RotateCcw,
  Trash2,
  Terminal,
  FileDown,
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
  onOpenOracleBridge,
  onExportAuditPdf,
}) => {
  const [searchTerm, setSearchTerm] = useState('');

  const reviewedCount = useMemo(() => auditLogs.filter((r) => r.reviewed).length, [auditLogs]);
  const pendingCount = auditLogs.length - reviewedCount;

  const filteredWithIndex = useMemo(() => {
    return auditLogs
      .map((row, originalIndex) => ({ row, originalIndex }))
      .filter(({ row }) => {
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
  }, [auditLogs, searchTerm]);

  return (
    <div className="space-y-5">
      {/* Search & Review Reset Header */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60 flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[13.5px] font-bold text-slate-100">
                Nhật ký Kiểm toán Hợp nhất Thời gian thực (UNIFIED_AUDIT_TRAIL)
              </div>
              <div className="text-[11px] text-slate-400">
                Hiển thị <strong className="text-sky-300 font-mono">{filteredWithIndex.length}</strong> / {auditLogs.length} sự kiện · Đã duyệt:{' '}
                <strong className="text-emerald-400 font-mono">{reviewedCount}</strong>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Lọc User, Policy, Client, SQL..."
                className="bg-[#0b1322] border border-sky-500/20 rounded-lg text-slate-200 pl-8 pr-3 py-1 text-[11.5px] outline-none focus:border-sky-400 w-48 sm:w-56 font-sans transition-all"
              />
            </div>

            {onExportAuditPdf && (
              <button
                onClick={onExportAuditPdf}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-purple-500/15 border border-purple-500/40 text-purple-200 hover:bg-purple-500/25 text-[11.5px] font-semibold transition-all cursor-pointer"
                title="Xuất Nhật ký Kiểm toán (UNIFIED_AUDIT_TRAIL) sang định dạng PDF"
              >
                <FileDown className="w-3.5 h-3.5 text-purple-300" />
                <span>Xuất PDF Audit Log</span>
              </button>
            )}

            {auditLogs.length > 0 && pendingCount > 0 && (
              <button
                onClick={onMarkAllAuditReviewed}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11.5px] font-semibold transition-all cursor-pointer"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Duyệt tất cả ({pendingCount})</span>
              </button>
            )}

            {reviewedCount > 0 && (
              <button
                onClick={onResetReviewedAudit}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/20 border border-amber-500/45 text-amber-200 hover:bg-amber-500/30 text-[11.5px] font-bold transition-all cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset đã duyệt ({reviewedCount})</span>
              </button>
            )}

            {auditLogs.length > 0 ? (
              <button
                onClick={onClearAllAudit}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-transparent border border-red-500/35 text-red-300 hover:bg-red-500/15 text-[11.5px] font-semibold transition-all cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Reset Audit Log</span>
              </button>
            ) : (
              onOpenOracleBridge && (
                <button
                  onClick={onOpenOracleBridge}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11.5px] font-semibold transition-all cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Kết nối Oracle SQL Developer</span>
                </button>
              )
            )}
          </div>
        </div>

        <div className="overflow-x-auto max-h-[580px]">
          {filteredWithIndex.length === 0 ? (
            <div className="p-10 text-center text-slate-400 flex flex-col items-center gap-3">
              <CheckCircle2 className="w-8 h-8 text-emerald-400" />
              <div className="text-[12.5px] text-slate-200 font-semibold">
                {auditLogs.length === 0
                  ? 'Toàn bộ bản ghi Unified Audit Trail đã được kiểm duyệt và Reset hoàn tất.'
                  : 'Không có bản ghi kiểm toán nào khớp bộ lọc.'}
              </div>
              {auditLogs.length === 0 && onOpenOracleBridge && (
                <button
                  onClick={onOpenOracleBridge}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 text-[12px] font-semibold transition-all cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Kết nối Oracle SQL Developer</span>
                </button>
              )}
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-sky-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5">Trạng thái</th>
                  <th className="py-2.5 px-3.5">Thời gian</th>
                  <th className="py-2.5 px-3.5">DB User</th>
                  <th className="py-2.5 px-3.5">Loại Audit / Policy</th>
                  <th className="py-2.5 px-3.5">Action</th>
                  <th className="py-2.5 px-3.5">Đối tượng</th>
                  <th className="py-2.5 px-3.5">Ngữ cảnh (Client / Host)</th>
                  <th className="py-2.5 px-3.5">Câu lệnh SQL</th>
                  <th className="py-2.5 px-3.5">Mã trả về</th>
                  <th className="py-2.5 px-3.5 text-right">Kiểm duyệt &amp; Reset</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredWithIndex.map(({ row: r, originalIndex }) => {
                  const code = Number(r.RETURN_CODE || 0);
                  const isFga = r.AUDIT_TYPE === 'FineGrainedAudit' || !!r.FGA_POLICY_NAME;
                  const isTrap = String(r.FGA_POLICY_NAME || '').includes('HONEYTOKEN');
                  const objFull =
                    r.OBJECT_SCHEMA && r.OBJECT_NAME
                      ? `${r.OBJECT_SCHEMA}.${r.OBJECT_NAME}`
                      : r.OBJECT_NAME || '—';
                  const ctx = `${r.CLIENT_PROGRAM_NAME || '—'} @ ${r.USERHOST || '—'}`;

                  return (
                    <tr
                      key={`${r.EVENT_TIMESTAMP}-${r.DBUSERNAME}-${originalIndex}`}
                      onClick={() => onOpenAuditModal(r)}
                      className={`hover:bg-sky-500/5 transition-colors cursor-pointer ${
                        isTrap ? 'honeytoken-row' : ''
                      } ${r.reviewed ? 'opacity-75 bg-emerald-950/10' : ''}`}
                    >
                      <td className="py-2.5 px-3.5 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => onToggleReviewAudit(originalIndex)}
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold border transition-all cursor-pointer ${
                            r.reviewed
                              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                              : 'bg-slate-800/80 text-slate-400 border-white/10 hover:border-emerald-500/40 hover:text-emerald-300'
                          }`}
                        >
                          <CheckCircle2 className="w-3 h-3" />
                          <span>{r.reviewed ? 'ĐÃ DUYỆT' : 'CHỜ DUYỆT'}</span>
                        </button>
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-slate-300 text-[11px] whitespace-nowrap">
                        {r.EVENT_TIMESTAMP}
                      </td>
                      <td className="py-2.5 px-3.5 font-bold font-mono text-sky-300">{r.DBUSERNAME}</td>
                      <td className="py-2.5 px-3.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
                            isTrap
                              ? 'bg-red-500/20 text-red-300 border-red-500/40'
                              : isFga
                              ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                              : 'bg-slate-700/40 text-slate-300 border-slate-600'
                          }`}
                        >
                          {r.FGA_POLICY_NAME || r.AUDIT_TYPE || 'Standard'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-mono text-[11px]">
                          {r.ACTION_NAME}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-slate-300 text-[11.5px]">{objFull}</td>
                      <td
                        className="py-2.5 px-3.5 font-mono text-[11px] text-slate-400 truncate max-w-[170px]"
                        title={ctx}
                      >
                        {ctx}
                      </td>
                      <td className="py-2.5 px-3.5">
                        {r.SQL_TEXT ? (
                          <span
                            className="font-mono text-[11px] bg-[#0b1322] border border-white/5 px-2 py-0.5 rounded text-sky-300 block max-w-xs truncate"
                            title={r.SQL_TEXT}
                          >
                            {r.SQL_TEXT}
                          </span>
                        ) : (
                          <span className="text-slate-500 font-mono">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-[11px]">
                        <span
                          className={`px-2 py-0.5 rounded border ${
                            code === 0
                              ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                              : 'bg-red-500/15 text-red-300 border-red-500/30'
                          }`}
                        >
                          {code === 0 ? '0 (OK)' : `ORA-${code}`}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            onClick={() => onToggleReviewAudit(originalIndex)}
                            className={`p-1 rounded border transition-colors cursor-pointer ${
                              r.reviewed
                                ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                                : 'bg-[#131e33] border-white/10 text-slate-400 hover:text-emerald-300'
                            }`}
                            title={r.reviewed ? 'Bỏ dấu đã kiểm duyệt' : 'Đánh dấu đã kiểm duyệt'}
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => onOpenAuditModal(r)}
                            className="p-1 rounded bg-[#131e33] border border-sky-500/20 text-slate-300 hover:text-white transition-colors cursor-pointer"
                            title="Xem chi tiết bản ghi"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => onClearSingleAudit(originalIndex)}
                            className="p-1 rounded bg-transparent border border-red-500/30 text-red-300 hover:bg-red-500/15 transition-colors cursor-pointer"
                            title="Đã kiểm duyệt & Reset bản ghi này"
                          >
                            <RotateCcw className="w-3.5 h-3.5" />
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
