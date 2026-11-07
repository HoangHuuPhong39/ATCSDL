import React, { useMemo } from 'react';
import {
  Target,
  ShieldAlert,
  CheckCircle2,
  CheckCheck,
  RotateCcw,
  Trash2,
  Terminal,
} from 'lucide-react';
import { FgaEvent } from '../../types/ids';

interface FgaTabProps {
  fgaEvents: FgaEvent[];
  onToggleReviewFga: (index: number) => void;
  onMarkAllFgaReviewed: () => void;
  onResetReviewedFga: () => void;
  onClearSingleFga: (index: number) => void;
  onClearAllFga: () => void;
  onOpenOracleBridge?: () => void;
}

export const FgaTab: React.FC<FgaTabProps> = ({
  fgaEvents,
  onToggleReviewFga,
  onMarkAllFgaReviewed,
  onResetReviewedFga,
  onClearSingleFga,
  onClearAllFga,
  onOpenOracleBridge,
}) => {
  const reviewedCount = useMemo(() => fgaEvents.filter((e) => e.reviewed).length, [fgaEvents]);
  const pendingCount = fgaEvents.length - reviewedCount;

  return (
    <div className="space-y-5">
      {/* Policy Concept Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Policy 1: Honeytoken Trap */}
        <div className="bg-[#101b2e] border border-red-500/30 rounded-xl p-4 shadow-lg shadow-black/30 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-400 animate-pulse" />
              <h3 className="font-bold text-slate-100 text-[13.5px]">Policy: FGA_HONEYTOKEN_TRAP</h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10.5px] font-bold font-mono bg-red-500/20 text-red-300 border border-red-500/40">
              TRAP / CANARY
            </span>
          </div>
          <p className="text-[12px] text-slate-300 mt-2 leading-relaxed">
            Bẫy dữ liệu mồi nhử (Canary Token) gài vào bảng <code className="text-sky-300 font-mono">SYS.NV</code> với mã nhân viên{' '}
            <code className="text-red-300 font-mono font-bold">MANV = &apos;NV_TRAP&apos;</code> (Lương 99,999). Mọi truy vấn đọc hoặc sửa đổi bản ghi này đều là hành vi xâm nhập ác ý (Zero False Positive).
          </p>
          <div className="mt-3 bg-[#080d17] p-2.5 rounded-lg border border-white/5 font-mono text-[11px] text-purple-300">
            DBMS_FGA.ADD_POLICY(object_name=&gt;&apos;NV&apos;, policy_name=&gt;&apos;FGA_HONEYTOKEN_TRAP&apos;, audit_condition=&gt;&apos;manv=&apos;&apos;NV_TRAP&apos;&apos;&apos;);
          </div>
        </div>

        {/* Policy 2: High Salary Access */}
        <div className="bg-[#101b2e] border border-purple-500/30 rounded-xl p-4 shadow-lg shadow-black/30 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-400" />
              <h3 className="font-bold text-slate-100 text-[13.5px]">Policy: FGA_HIGH_SALARY_ACCESS</h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10.5px] font-bold font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40">
              SENSITIVE DATA
            </span>
          </div>
          <p className="text-[12px] text-slate-300 mt-2 leading-relaxed">
            Giám sát mịn các truy vấn vào cột thông tin nhạy cảm <code className="text-sky-300 font-mono">LUONG, CMND</code> khi thỏa mãn điều kiện mức lương{' '}
            <code className="text-purple-300 font-mono font-bold">LUONG &gt;= 1000</code>. Hỗ trợ phát hiện rò rỉ dữ liệu lương lãnh đạo và tấn công suy diễn thống kê.
          </p>
          <div className="mt-3 bg-[#080d17] p-2.5 rounded-lg border border-white/5 font-mono text-[11px] text-purple-300">
            DBMS_FGA.ADD_POLICY(object_name=&gt;&apos;NV&apos;, policy_name=&gt;&apos;FGA_HIGH_SALARY_ACCESS&apos;, audit_condition=&gt;&apos;luong&gt;=1000&apos;, audit_column=&gt;&apos;LUONG, CMND&apos;);
          </div>
        </div>
      </div>

      {/* Main FGA Events Table */}
      <section className="bg-[#101b2e] border border-purple-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60 flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
              <Target className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[13.5px] font-bold text-slate-100">
                Nhật ký Sự kiện Kiểm toán Mịn (DBMS_FGA &amp; Honeytoken Traps)
              </div>
              <div className="text-[11px] text-slate-400">
                Tổng sự kiện: <strong className="text-purple-300 font-mono">{fgaEvents.length}</strong> · Đã kiểm duyệt:{' '}
                <strong className="text-emerald-400 font-mono">{reviewedCount}</strong>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {fgaEvents.length > 0 && pendingCount > 0 && (
              <button
                onClick={onMarkAllFgaReviewed}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11.5px] font-semibold transition-all cursor-pointer"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Duyệt tất cả ({pendingCount})</span>
              </button>
            )}

            {reviewedCount > 0 && (
              <button
                onClick={onResetReviewedFga}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/20 border border-amber-500/45 text-amber-200 hover:bg-amber-500/30 text-[11.5px] font-bold transition-all cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset đã duyệt ({reviewedCount})</span>
              </button>
            )}

            {fgaEvents.length > 0 ? (
              <button
                onClick={onClearAllFga}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-transparent border border-purple-500/35 text-purple-300 hover:bg-purple-500/15 text-[11.5px] font-semibold transition-all cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Reset sự kiện FGA</span>
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

        <div className="overflow-x-auto max-h-[500px]">
          {fgaEvents.length === 0 ? (
            <div className="p-10 text-center text-slate-400 flex flex-col items-center gap-3">
              <CheckCircle2 className="w-9 h-9 text-emerald-400" />
              <div className="text-[12.5px] text-slate-200 font-semibold">
                Các sự kiện FGA_HONEYTOKEN_TRAP và FGA_HIGH_SALARY_ACCESS đã được kiểm duyệt và Reset sạch sẽ.
              </div>
              {onOpenOracleBridge && (
                <button
                  onClick={onOpenOracleBridge}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 text-[12px] font-semibold transition-all cursor-pointer"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Thực thi SQL từ Oracle SQL Developer</span>
                </button>
              )}
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-purple-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider sticky top-0 z-10">
                  <th className="py-2.5 px-3.5">Trạng thái</th>
                  <th className="py-2.5 px-3.5">Thời gian</th>
                  <th className="py-2.5 px-3.5">User</th>
                  <th className="py-2.5 px-3.5">Chính sách FGA</th>
                  <th className="py-2.5 px-3.5">Ngữ cảnh (Client / Host)</th>
                  <th className="py-2.5 px-3.5">Câu lệnh kích hoạt (SQL_TEXT)</th>
                  <th className="py-2.5 px-3.5">Mã trả về</th>
                  <th className="py-2.5 px-3.5 text-right">Kiểm duyệt &amp; Reset</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {fgaEvents.map((r, i) => {
                  const isTrap = String(r.FGA_POLICY_NAME).includes('HONEYTOKEN');
                  const ctx = `${r.CLIENT_PROGRAM_NAME || 'Unknown'} (${r.OS_USERNAME || 'os'}@${r.USERHOST || 'host'})`;
                  return (
                    <tr
                      key={`${r.EVENT_TIMESTAMP}-${r.DBUSERNAME}-${i}`}
                      className={`hover:bg-purple-500/5 transition-colors ${isTrap ? 'honeytoken-row' : ''} ${
                        r.reviewed ? 'opacity-75 bg-emerald-950/10' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3.5 whitespace-nowrap">
                        <button
                          onClick={() => onToggleReviewFga(i)}
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
                      <td className="py-2.5 px-3.5 font-mono text-slate-300 text-[11px] whitespace-nowrap">{r.EVENT_TIMESTAMP}</td>
                      <td className="py-2.5 px-3.5 font-bold font-mono text-sky-300">{r.DBUSERNAME}</td>
                      <td className="py-2.5 px-3.5">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10.5px] font-bold font-mono border ${
                            isTrap
                              ? 'bg-red-500/20 text-red-300 border-red-500/40'
                              : 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                          }`}
                        >
                          {isTrap && <ShieldAlert className="w-3 h-3 text-red-400" />}
                          {r.FGA_POLICY_NAME}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-[11px] text-slate-400 truncate max-w-[200px]">{ctx}</td>
                      <td className="py-2.5 px-3.5">
                        <span
                          className="font-mono text-[11px] bg-[#0b1322] border border-white/5 px-2 py-0.5 rounded text-sky-300 block max-w-md truncate"
                          title={r.SQL_TEXT}
                        >
                          {r.SQL_TEXT || r.ACTION_NAME}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-[11px]">
                        <span
                          className={`px-2 py-0.5 rounded border ${
                            Number(r.RETURN_CODE) === 0
                              ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                              : 'bg-red-500/15 text-red-300 border-red-500/30'
                          }`}
                        >
                          {Number(r.RETURN_CODE) === 0 ? '0 (OK)' : `ORA-${r.RETURN_CODE}`}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            onClick={() => onToggleReviewFga(i)}
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
                            onClick={() => onClearSingleFga(i)}
                            className="p-1 rounded bg-transparent border border-red-500/30 text-red-300 hover:bg-red-500/15 transition-colors cursor-pointer"
                            title="Đã kiểm duyệt & Reset sự kiện này"
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
