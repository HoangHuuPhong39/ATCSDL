import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Trash2,
  Eye,
  Search,
  CheckCircle2,
  Filter,
  CheckCheck,
  RotateCcw,
  Terminal,
  FileDown,
} from 'lucide-react';
import { AlertItem, Severity } from '../../types/ids';
import { classifyAlertGroup, computeAttackBreakdown, getRiskColorHex, AttackGroup } from '../../utils/analytics';

interface AlertsTabProps {
  alerts: AlertItem[];
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
  onOpenAlertModal,
  onDismissAlert,
  onToggleReviewAlert,
  onMarkAllAlertsReviewed,
  onResetReviewedAlerts,
  onClearAlerts,
  onOpenOracleBridge,
  onExportAlertsPdf,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | Severity>('ALL');
  const [filterGroup, setFilterGroup] = useState<'ALL' | AttackGroup>('ALL');
  const [filterReview, setFilterReview] = useState<'ALL' | 'PENDING' | 'REVIEWED'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

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
    <div className="space-y-5">
      {/* Dedicated Alert Filter, Audit Review Status & Taxonomy Summary Bar */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 text-[12px] font-bold text-slate-200">
            <Filter className="w-4 h-4 text-sky-400" />
            <span>Phân nhóm:</span>
          </div>

          <div className="flex items-center bg-[#0b1322] border border-sky-500/20 rounded-lg p-1 gap-1 flex-wrap">
            <button
              onClick={() => setFilterGroup('ALL')}
              className={`px-2.5 py-1 text-[11.5px] font-semibold rounded-md cursor-pointer transition-colors whitespace-nowrap ${
                filterGroup === 'ALL'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Tất cả ({breakdown.total})
            </button>
            <button
              onClick={() => setFilterGroup('DBMS')}
              className={`px-2.5 py-1 text-[11.5px] font-semibold rounded-md cursor-pointer transition-colors whitespace-nowrap ${
                filterGroup === 'DBMS'
                  ? 'bg-red-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Kỹ thuật DBMS ({breakdown.dbmsCount})
            </button>
            <button
              onClick={() => setFilterGroup('SDB')}
              className={`px-2.5 py-1 text-[11.5px] font-semibold rounded-md cursor-pointer transition-colors whitespace-nowrap ${
                filterGroup === 'SDB'
                  ? 'bg-amber-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Suy diễn SDB ({breakdown.sdbCount})
            </button>
          </div>

          {/* Review status filter */}
          <div className="flex items-center bg-[#0b1322] border border-sky-500/20 rounded-lg p-1 gap-1 flex-wrap">
            <button
              onClick={() => setFilterReview('ALL')}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded-md cursor-pointer transition-colors whitespace-nowrap ${
                filterReview === 'ALL'
                  ? 'bg-slate-700 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Mọi trạng thái
            </button>
            <button
              onClick={() => setFilterReview('PENDING')}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded-md cursor-pointer transition-colors whitespace-nowrap ${
                filterReview === 'PENDING'
                  ? 'bg-amber-500/25 text-amber-300 border border-amber-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Chờ duyệt ({pendingCount})
            </button>
            <button
              onClick={() => setFilterReview('REVIEWED')}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded-md cursor-pointer transition-colors whitespace-nowrap ${
                filterReview === 'REVIEWED'
                  ? 'bg-emerald-500/25 text-emerald-300 border border-emerald-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Đã kiểm duyệt ({reviewedCount})
            </button>
          </div>
        </div>

        {/* Review, PDF Export & Post-Audit Reset Actions */}
        <div className="flex items-center gap-2 flex-wrap">
          {onExportAlertsPdf && (
            <button
              onClick={onExportAlertsPdf}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/15 border border-purple-500/40 text-purple-200 hover:bg-purple-500/25 text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap"
              title="Xuất danh sách Cảnh báo Xâm nhập sang định dạng PDF"
            >
              <FileDown className="w-3.5 h-3.5 text-purple-300" />
              <span>Xuất PDF Cảnh báo</span>
            </button>
          )}

          {alerts.length > 0 && pendingCount > 0 && (
            <button
              onClick={onMarkAllAlertsReviewed}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap"
              title="Đánh dấu tất cả cảnh báo là đã kiểm duyệt"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>Duyệt tất cả ({pendingCount})</span>
            </button>
          )}

          {reviewedCount > 0 && (
            <button
              onClick={onResetReviewedAlerts}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/20 border border-amber-500/45 text-amber-200 hover:bg-amber-500/30 text-[11.5px] font-bold transition-all cursor-pointer whitespace-nowrap"
              title="Reset (dọn sạch) các cảnh báo đã kiểm duyệt và tính lại Risk Score"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset mục đã duyệt ({reviewedCount})</span>
            </button>
          )}

          {alerts.length > 0 ? (
            <button
              onClick={() => onClearAlerts('ids')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/15 border border-red-500/35 text-red-300 hover:bg-red-500/25 text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap"
              title="Reset toàn bộ cảnh báo sau khi kiểm duyệt xong"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Reset toàn bộ cảnh báo</span>
            </button>
          ) : (
            onOpenOracleBridge && (
              <button
                onClick={onOpenOracleBridge}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Kết nối Oracle SQL Developer</span>
              </button>
            )
          )}
        </div>
      </section>

      {/* Main Alerts Table */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60 flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400 shrink-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[13.5px] font-bold text-slate-100">
                Bảng Cảnh báo Xâm nhập Đa chiều &amp; Kiểm duyệt Sự kiện (IDS Detection Engine)
              </div>
              <div className="text-[11px] text-slate-400">
                Hiển thị {filtered.length} / {alerts.length} cảnh báo · Đã duyệt:{' '}
                <strong className="text-emerald-400 font-mono">{reviewedCount}</strong> · Nhấn biểu tượng ✓ để duyệt hoặc Reset
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Severity Filter group */}
            <div className="flex items-center bg-[#0b1322] border border-sky-500/20 rounded-lg p-0.5">
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-2.5 py-1 text-[11px] font-semibold rounded cursor-pointer transition-all whitespace-nowrap ${
                    filterSeverity === sev
                      ? 'bg-sky-500/20 text-sky-300 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev === 'ALL' ? 'Mọi mức độ' : sev}
                </button>
              ))}
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Lọc User, Loại tấn công, SQL..."
                className="bg-[#0b1322] border border-sky-500/20 rounded-lg text-slate-200 pl-8 pr-3 py-1 text-[11.5px] outline-none focus:border-sky-400 w-44 sm:w-56 font-sans transition-all"
              />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[580px]">
          {filtered.length === 0 ? (
            <div className="p-10 text-center text-slate-400 flex flex-col items-center gap-3">
              <CheckCircle2 className="w-9 h-9 text-emerald-400" />
              <div className="text-[13px] font-semibold text-slate-200">
                {alerts.length === 0
                  ? 'Tất cả cảnh báo đã được kiểm duyệt và Reset hoàn tất! Hệ thống đang chờ lệnh mới từ Oracle SQL Developer.'
                  : 'Không có cảnh báo nào phù hợp với bộ lọc hiện tại.'}
              </div>
              {alerts.length === 0 && onOpenOracleBridge && (
                <button
                  onClick={onOpenOracleBridge}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 text-[12px] font-semibold transition-all cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Mở Kết nối Oracle SQL Developer</span>
                </button>
              )}
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-sky-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5">Trạng thái</th>
                  <th className="py-2.5 px-3.5">Mức độ</th>
                  <th className="py-2.5 px-3.5">Phân nhóm</th>
                  <th className="py-2.5 px-3.5">Risk Score</th>
                  <th className="py-2.5 px-3.5">Thời gian</th>
                  <th className="py-2.5 px-3.5">User</th>
                  <th className="py-2.5 px-3.5 min-w-[230px]">Loại tấn công / Bất thường</th>
                  <th className="py-2.5 px-3.5">Chi tiết / Câu lệnh SQL</th>
                  <th className="py-2.5 px-3.5 text-right">Kiểm duyệt &amp; Reset</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filtered.map((a) => {
                  const color = getRiskColorHex(a.risk_score);
                  const group = classifyAlertGroup(a);
                  return (
                    <tr
                      key={a.key}
                      onClick={() => onOpenAlertModal(a)}
                      className={`hover:bg-sky-500/5 transition-colors cursor-pointer group ${
                        a.reviewed ? 'bg-emerald-950/10 opacity-80' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3.5 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => onToggleReviewAlert(a.key)}
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold border transition-all cursor-pointer ${
                            a.reviewed
                              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                              : 'bg-slate-800/80 text-slate-400 border-white/10 hover:border-emerald-500/40 hover:text-emerald-300'
                          }`}
                          title={a.reviewed ? 'Đã kiểm duyệt (Nhấn để hoàn tác)' : 'Đánh dấu đã kiểm duyệt'}
                        >
                          <CheckCircle2 className="w-3 h-3" />
                          <span>{a.reviewed ? 'ĐÃ DUYỆT' : 'CHỜ DUYỆT'}</span>
                        </button>
                      </td>
                      <td className="py-2.5 px-3.5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
                            a.severity === 'CRITICAL'
                              ? 'bg-red-500/20 text-red-300 border-red-500/40'
                              : a.severity === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                              : 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                          }`}
                        >
                          ▲ {a.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 whitespace-nowrap font-mono text-[10.5px]">
                        <span
                          className={
                            group === 'SDB' ? 'text-amber-300 font-bold' : 'text-red-300 font-bold'
                          }
                        >
                          {group === 'SDB' ? 'SDB Inference' : 'DBMS Tech'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 whitespace-nowrap">
                        <div className="inline-flex items-center gap-2 min-w-[90px]">
                          <span className="font-mono font-bold text-[11px] tabular-nums" style={{ color }}>
                            {a.risk_score}/100
                          </span>
                          <div className="w-10 h-1 bg-white/10 rounded-full overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${a.risk_score}%`, backgroundColor: color }} />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-slate-300 text-[11px] whitespace-nowrap tabular-nums">
                        {a.time}
                      </td>
                      <td className="py-2.5 px-3.5 font-bold font-mono text-sky-300">{a.user}</td>
                      <td className="py-2.5 px-3.5 text-slate-200 font-medium min-w-[230px] max-w-md">{a.attack_type}</td>
                      <td className="py-2.5 px-3.5">
                        <span
                          className="font-mono text-[11px] bg-[#0b1322] border border-white/5 px-2 py-0.5 rounded text-sky-300 block max-w-xs truncate"
                          title={a.details}
                        >
                          {a.details}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            onClick={() => onToggleReviewAlert(a.key)}
                            className={`p-1 rounded border transition-colors cursor-pointer ${
                              a.reviewed
                                ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                                : 'bg-[#131e33] border-white/10 text-slate-400 hover:text-emerald-300 hover:border-emerald-500/35'
                            }`}
                            title={a.reviewed ? 'Bỏ đánh dấu đã duyệt' : 'Đánh dấu đã kiểm duyệt'}
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => onOpenAlertModal(a)}
                            className="p-1 rounded bg-[#131e33] border border-sky-500/20 text-slate-300 hover:text-white transition-colors cursor-pointer"
                            title="Xem chi tiết"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => onDismissAlert(a.key)}
                            className="p-1 rounded bg-transparent border border-red-500/30 text-red-300 hover:bg-red-500/15 transition-colors cursor-pointer"
                            title="Đã kiểm duyệt & Reset cảnh báo này"
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
