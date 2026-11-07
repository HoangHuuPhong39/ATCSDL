import React, { useMemo } from 'react';
import {
  Zap,
  Trash2,
  CheckCircle2,
  ShieldAlert,
  BookOpen,
  ArrowRight,
  CheckCheck,
  RotateCcw,
  Terminal,
} from 'lucide-react';
import { TriggerAlert, ActiveTab } from '../../types/ids';

interface TriggersTabProps {
  triggers: TriggerAlert[];
  onToggleReviewTrigger: (id: number) => void;
  onMarkAllTriggersReviewed: () => void;
  onResetReviewedTriggers: () => void;
  onClearSingleTrigger: (id: number) => void;
  onClearAllTriggers: () => void;
  onOpenOracleBridge?: () => void;
  onNavigateTab?: (tab: ActiveTab) => void;
}

export const TriggersTab: React.FC<TriggersTabProps> = ({
  triggers,
  onToggleReviewTrigger,
  onMarkAllTriggersReviewed,
  onResetReviewedTriggers,
  onClearSingleTrigger,
  onClearAllTriggers,
  onOpenOracleBridge,
  onNavigateTab,
}) => {
  const reviewedCount = useMemo(() => triggers.filter((t) => t.reviewed).length, [triggers]);
  const pendingCount = triggers.length - reviewedCount;

  return (
    <div className="space-y-5">
      {/* Trigger Architecture Overview */}
      <div className="bg-[#101b2e] border border-amber-500/25 rounded-xl p-4.5 shadow-lg shadow-black/30">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/15 border border-amber-500/35 flex items-center justify-center text-amber-400 shrink-0">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-slate-100 text-[14px]">
                Trigger Bảo vệ Dữ liệu Nội sinh (SYS.TRG_PROTECT_NV)
              </h3>
              <p className="text-[11.5px] text-slate-400">
                Sử dụng <code className="text-amber-300 font-mono">PRAGMA AUTONOMOUS_TRANSACTION</code> để ghi log độc lập vào bảng <code className="text-sky-300 font-mono">SYS.IDS_TRIGGER_ALERTS</code> trước khi ném ngoại lệ chặn đứng giao dịch
              </p>
            </div>
          </div>

          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('docs')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#131e33] border border-sky-500/20 text-sky-300 hover:text-white hover:border-sky-400 text-[11.5px] font-semibold transition-colors cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Xem mã nguồn PL/SQL tại Báo cáo</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* 2 Security rules handled by trigger */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
          <div className="bg-[#0b1322] border border-white/5 rounded-lg p-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-200 text-[12px]">Quy tắc 1: Ngăn chặn Xóa nhân viên</span>
              <span className="font-mono text-[10.5px] text-red-400 font-bold">ORA-20001</span>
            </div>
            <p className="text-[11.5px] text-slate-400 mt-1">
              Bất kỳ câu lệnh <code className="text-sky-300 font-mono">DELETE</code> nào trên bảng nhân viên đều bị chặn tức thời. Hệ thống ghi lại mã nhân viên bị nhắm tới và người thực hiện.
            </p>
          </div>

          <div className="bg-[#0b1322] border border-white/5 rounded-lg p-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-200 text-[12px]">Quy tắc 2: Chặn tăng lương gian lận &gt; 50%</span>
              <span className="font-mono text-[10.5px] text-red-400 font-bold">ORA-20002</span>
            </div>
            <p className="text-[11.5px] text-slate-400 mt-1">
              Phát hiện can thiệp số liệu lương bất thường khi <code className="text-sky-300 font-mono">:NEW.luong &gt; :OLD.luong * 1.5</code>. Chặn đứng hành vi biển thủ quỹ lương.
            </p>
          </div>
        </div>
      </div>

      {/* Trigger Alerts Table */}
      <section className="bg-[#101b2e] border border-amber-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60 flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[13.5px] font-bold text-slate-100">
                Nhật ký Vi phạm Bị chặn Tức thời (SYS.IDS_TRIGGER_ALERTS)
              </div>
              <div className="text-[11px] text-slate-400">
                Tổng bản ghi: <strong className="text-amber-300 font-mono">{triggers.length}</strong> · Đã kiểm duyệt:{' '}
                <strong className="text-emerald-400 font-mono">{reviewedCount}</strong>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {triggers.length > 0 && pendingCount > 0 && (
              <button
                onClick={onMarkAllTriggersReviewed}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11.5px] font-semibold transition-all cursor-pointer"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Duyệt tất cả ({pendingCount})</span>
              </button>
            )}

            {reviewedCount > 0 && (
              <button
                onClick={onResetReviewedTriggers}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/20 border border-amber-500/45 text-amber-200 hover:bg-amber-500/30 text-[11.5px] font-bold transition-all cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset đã duyệt ({reviewedCount})</span>
              </button>
            )}

            {triggers.length > 0 ? (
              <button
                onClick={onClearAllTriggers}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-transparent border border-amber-500/35 text-amber-300 hover:bg-amber-500/15 text-[11.5px] font-semibold transition-all cursor-pointer"
                title="Reset toàn bộ log Trigger"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Reset log Trigger</span>
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

        <div className="overflow-x-auto max-h-[480px]">
          {triggers.length === 0 ? (
            <div className="p-10 text-center text-slate-400 flex flex-col items-center gap-3">
              <CheckCircle2 className="w-9 h-9 text-emerald-400" />
              <div className="text-[12.5px] text-slate-200 font-semibold">
                Tất cả nhật ký vi phạm Trigger đã được kiểm duyệt và Reset hoàn tất.
              </div>
              {onOpenOracleBridge && (
                <button
                  onClick={onOpenOracleBridge}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 text-[12px] font-semibold transition-all cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Thực thi UPDATE / DELETE trên Oracle SQL Developer</span>
                </button>
              )}
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-amber-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5">Trạng thái</th>
                  <th className="py-2.5 px-3.5">ID</th>
                  <th className="py-2.5 px-3.5">Thời gian</th>
                  <th className="py-2.5 px-3.5">User</th>
                  <th className="py-2.5 px-3.5">Loại vi phạm</th>
                  <th className="py-2.5 px-3.5">Chi tiết ngăn chặn</th>
                  <th className="py-2.5 px-3.5 text-right">Kiểm duyệt &amp; Reset</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {triggers.map((t) => (
                  <tr
                    key={t.ALERT_ID}
                    className={`hover:bg-amber-500/5 transition-colors ${
                      t.reviewed ? 'opacity-75 bg-emerald-950/10' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      <button
                        onClick={() => onToggleReviewTrigger(t.ALERT_ID)}
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold border transition-all cursor-pointer ${
                          t.reviewed
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                            : 'bg-slate-800/80 text-slate-400 border-white/10 hover:border-emerald-500/40 hover:text-emerald-300'
                        }`}
                      >
                        <CheckCircle2 className="w-3 h-3" />
                        <span>{t.reviewed ? 'ĐÃ DUYỆT' : 'CHỜ DUYỆT'}</span>
                      </button>
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-slate-400 tabular-nums">#{t.ALERT_ID}</td>
                    <td className="py-2.5 px-3.5 font-mono text-slate-300 text-[11px] whitespace-nowrap tabular-nums">{t.EVENT_TIME}</td>
                    <td className="py-2.5 px-3.5 font-bold font-mono text-sky-300">{t.DB_USER}</td>
                    <td className="py-2.5 px-3.5">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-bold font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40">
                        <ShieldAlert className="w-3 h-3 text-amber-400" />
                        {t.ATTACK_TYPE}
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 text-slate-200">{t.DETAILS}</td>
                    <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          onClick={() => onToggleReviewTrigger(t.ALERT_ID)}
                          className={`p-1 rounded border transition-colors cursor-pointer ${
                            t.reviewed
                              ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                              : 'bg-[#131e33] border-white/10 text-slate-400 hover:text-emerald-300'
                          }`}
                          title={t.reviewed ? 'Bỏ dấu đã kiểm duyệt' : 'Đánh dấu đã kiểm duyệt'}
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onClearSingleTrigger(t.ALERT_ID)}
                          className="p-1 rounded bg-transparent border border-red-500/30 text-red-300 hover:bg-red-500/15 transition-colors cursor-pointer"
                          title="Đã kiểm duyệt & Reset dòng này"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
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
