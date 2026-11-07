import React from 'react';
import {
  ShieldAlert,
  RotateCcw,
  Lock,
  Unlock,
  ShieldCheck,
  Sliders,
} from 'lucide-react';
import { DbUser } from '../../types/ids';
import { maskUsername } from '../../utils/privacy';

interface IpsTabProps {
  users: DbUser[];
  privacyMode?: boolean;
  autoResponse: boolean;
  onToggleAutoResponse: (enabled: boolean) => void;
  autoRefresh: boolean;
  onToggleAutoRefresh: (enabled: boolean) => void;
  onClearAll: () => void;
  onUserAction: (username: string, action: 'lock' | 'unlock' | 'revoke_dml' | 'grant_dml') => void;
}

export const IpsTab: React.FC<IpsTabProps> = ({
  users,
  privacyMode = false,
  autoResponse,
  onToggleAutoResponse,
  autoRefresh,
  onToggleAutoRefresh,
  onClearAll,
  onUserAction,
}) => {
  const getRiskColor = (score: number) => {
    if (score >= 80) return '#ef4444';
    if (score >= 50) return '#f97316';
    if (score >= 20) return '#eab308';
    return '#10b981';
  };

  return (
    <div className="space-y-6">
      {/* Control Panel */}
      <section className="bg-[#101b2e] border border-purple-500/30 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60 flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
              <Sliders className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[13.5px] font-bold text-slate-100">
                Trung tâm Điều khiển Phản ứng Đa cấp (Graduated Active Response &amp; IPS)
              </div>
              <div className="text-[11px] text-slate-400">
                Cấu hình tự động hóa phân cấp xử lý vi phạm dựa trên Risk Score thời gian thực
              </div>
            </div>
          </div>

          <button
            onClick={onClearAll}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 border border-amber-500/35 text-amber-300 hover:bg-amber-500/25 text-[11.5px] font-semibold transition-all cursor-pointer"
            title="Đặt lại toàn bộ Risk Score về 0 & khôi phục quyền User"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Risk Score &amp; Lịch sử</span>
          </button>
        </div>

        <div className="p-4 space-y-3">
          {/* Switch 1: Auto Response */}
          <div className="flex items-center justify-between p-3.5 bg-[#0b1322] border border-white/5 rounded-xl">
            <div>
              <div className="font-bold text-slate-100 text-[13px]">
                Tự động Phản ứng theo Risk Score (Graduated IPS Engine)
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Tự động hạ quyền Read-Only (Level 2: Score 50–79) hoặc Khóa tài khoản &amp; ngắt kết nối (Level 3: Score &gt;= 80)
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={autoResponse}
                onChange={(e) => onToggleAutoResponse(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-sky-600"></div>
            </label>
          </div>

          {/* Switch 2: Auto Refresh */}
          <div className="flex items-center justify-between p-3.5 bg-[#0b1322] border border-white/5 rounded-xl">
            <div>
              <div className="font-bold text-slate-100 text-[13px]">
                Tự động đồng bộ dữ liệu thời gian thực từ Oracle (Polling 3 giây)
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Tự động nhận cảnh báo ngay khi thực thi câu lệnh trên Oracle SQL Developer
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => onToggleAutoRefresh(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-sky-600"></div>
            </label>
          </div>
        </div>
      </section>

      {/* Defense Matrix Table */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60">
          <div className="text-[13.5px] font-bold text-slate-100">
            Ma trận Phân cấp Bảo vệ Chủ động (IPS Defense Level Matrix)
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-sky-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider">
                <th className="py-2.5 px-3.5">Cấp độ</th>
                <th className="py-2.5 px-3.5">Phạm vi Risk Score</th>
                <th className="py-2.5 px-3.5">Hành vi Kích hoạt</th>
                <th className="py-2.5 px-3.5">Biện pháp Can thiệp Tự động</th>
                <th className="py-2.5 px-3.5">Khả năng thao tác CSDL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-[12px]">
              <tr>
                <td className="py-3 px-3.5">
                  <span className="px-2 py-0.5 rounded-full text-[10.5px] font-bold font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/35">
                    Level 0: Normal
                  </span>
                </td>
                <td className="py-3 px-3.5 font-mono text-slate-300">0 – 19</td>
                <td className="py-3 px-3.5 text-slate-200">Hoạt động bình thường, đúng nghiệp vụ</td>
                <td className="py-3 px-3.5 text-slate-400">Ghi nhận kiểm toán tiêu chuẩn</td>
                <td className="py-3 px-3.5 text-emerald-400 font-semibold font-mono">Đầy đủ quyền SELECT, INSERT, UPDATE, DELETE</td>
              </tr>
              <tr>
                <td className="py-3 px-3.5">
                  <span className="px-2 py-0.5 rounded-full text-[10.5px] font-bold font-mono bg-sky-500/15 text-sky-300 border border-sky-500/35">
                    Level 1: Warning
                  </span>
                </td>
                <td className="py-3 px-3.5 font-mono text-slate-300">20 – 49</td>
                <td className="py-3 px-3.5 text-slate-200">Thử mật khẩu sai 1-2 lần, truy cập cột lương cao FGA đơn lẻ, thăm dò thống kê 1-2 lần</td>
                <td className="py-3 px-3.5 text-slate-400">Cảnh báo SOC, tăng tần suất theo dõi</td>
                <td className="py-3 px-3.5 text-sky-300 font-semibold font-mono">Duy trì quyền hiện tại</td>
              </tr>
              <tr>
                <td className="py-3 px-3.5">
                  <span className="px-2 py-0.5 rounded-full text-[10.5px] font-bold font-mono bg-amber-500/15 text-amber-300 border border-amber-500/35">
                    Level 2: Containment
                  </span>
                </td>
                <td className="py-3 px-3.5 font-mono text-slate-300">50 – 79</td>
                <td className="py-3 px-3.5 text-slate-200">
                  Giả mạo/Giả danh (Masquerading), Tấn công Suy diễn SDB (Count-based COUNT=1&amp;SUM, Tracker Attack, Linear System A·X=B), Trigger chặn sửa lương/xóa NV
                </td>
                <td className="py-3 px-3.5 text-amber-300 font-medium">Thu hồi quyền DML (REVOKE INSERT, UPDATE, DELETE)</td>
                <td className="py-3 px-3.5 text-amber-400 font-semibold font-mono">Chỉ cho phép đọc (READ-ONLY)</td>
              </tr>
              <tr>
                <td className="py-3 px-3.5">
                  <span className="px-2 py-0.5 rounded-full text-[10.5px] font-bold font-mono bg-red-500/15 text-red-300 border border-red-500/35">
                    Level 3: Isolation
                  </span>
                </td>
                <td className="py-3 px-3.5 font-mono text-slate-300">80 – 100</td>
                <td className="py-3 px-3.5 text-slate-200">
                  SQL Injection, Leo thang đặc quyền, Đăng nhập thất bại liên tiếp (Brute-Force), Truy cập khóa mã hóa trái phép (Trực tiếp &amp; Gián tiếp), Tấn công trực tiếp SDB &amp; Chạm bẫy Honeytoken (NV_TRAP)
                </td>
                <td className="py-3 px-3.5 text-red-300 font-medium">Khóa tài khoản (ALTER USER LOCK) &amp; Kill session (ALTER SYSTEM KILL SESSION)</td>
                <td className="py-3 px-3.5 text-red-400 font-semibold font-mono">Toàn bộ kết nối bị từ chối và chặn đứng</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* User Status under IPS */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60">
          <div className="text-[13.5px] font-bold text-slate-100">
            Trạng thái Cách ly &amp; Phản ứng Thực tế Từng User
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-sky-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider">
                <th className="py-2.5 px-3.5">Tài khoản</th>
                <th className="py-2.5 px-3.5">Risk Score</th>
                <th className="py-2.5 px-3.5">Cấp độ Phản ứng Hiện tại</th>
                <th className="py-2.5 px-3.5">Chế độ Quyền</th>
                <th className="py-2.5 px-3.5">Trạng thái Tài khoản</th>
                <th className="py-2.5 px-3.5 text-right">Hành động Phản ứng Thủ công</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {users.map((u) => {
                const isLocked = u.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
                const isReadOnly = u.DML_STATUS.toUpperCase() === 'READ-ONLY';
                const color = getRiskColor(u.RISK_SCORE);

                return (
                  <tr key={u.USERNAME} className="hover:bg-sky-500/5 transition-colors">
                    <td className="py-3 px-3.5 font-bold font-mono text-sky-300">
                      {maskUsername(u.USERNAME, privacyMode)}
                    </td>
                    <td className="py-3 px-3.5">
                      <div className="inline-flex items-center gap-2 min-w-[90px]">
                        <span className="font-mono font-bold text-[11px]" style={{ color }}>
                          {u.RISK_SCORE}/100
                        </span>
                        <div className="w-12 h-1 bg-white/10 rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${u.RISK_SCORE}%`, backgroundColor: color }} />
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-3.5">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10.5px] font-bold font-mono border ${
                          u.RESPONSE_LEVEL >= 3
                            ? 'bg-red-500/15 text-red-300 border-red-500/40'
                            : u.RESPONSE_LEVEL === 2
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                            : 'bg-sky-500/15 text-sky-300 border-sky-500/40'
                        }`}
                      >
                        {u.RESPONSE_LABEL}
                      </span>
                    </td>
                    <td className="py-3 px-3.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${
                          isReadOnly
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                            : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                        }`}
                      >
                        {u.DML_STATUS}
                      </span>
                    </td>
                    <td className="py-3 px-3.5 font-mono text-slate-300">{u.ACCOUNT_STATUS}</td>
                    <td className="py-3 px-3.5 text-right">
                      <div className="inline-flex items-center gap-1.5 justify-end">
                        {isReadOnly ? (
                          <button
                            onClick={() => onUserAction(u.USERNAME, 'grant_dml')}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[#131e33] border border-sky-500/25 text-sky-300 hover:bg-[#1a2942] text-[11px] font-semibold cursor-pointer"
                          >
                            <ShieldCheck className="w-3 h-3" />
                            <span>Khôi phục DML</span>
                          </button>
                        ) : (
                          <button
                            onClick={() => onUserAction(u.USERNAME, 'revoke_dml')}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-500/15 border border-amber-500/35 text-amber-300 hover:bg-amber-500/25 text-[11px] font-semibold cursor-pointer"
                          >
                            <ShieldAlert className="w-3 h-3" />
                            <span>Read-Only</span>
                          </button>
                        )}
                        {isLocked ? (
                          <button
                            onClick={() => onUserAction(u.USERNAME, 'unlock')}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 text-[11px] font-semibold cursor-pointer"
                          >
                            <Unlock className="w-3 h-3" />
                            <span>Mở khóa User</span>
                          </button>
                        ) : (
                          <button
                            onClick={() => onUserAction(u.USERNAME, 'lock')}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-500/15 border border-red-500/35 text-red-300 hover:bg-red-500/25 text-[11px] font-semibold cursor-pointer"
                          >
                            <Lock className="w-3 h-3" />
                            <span>Khóa L3 (Isolation)</span>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
