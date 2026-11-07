import React from 'react';
import {
  Users,
  Table,
  AlertTriangle,
  ArrowRight,
  Fingerprint,
  EyeOff,
} from 'lucide-react';
import { DbUser, Employee, ActiveTab } from '../../types/ids';
import { maskUsername, maskHost, maskOsUser, maskCmnd } from '../../utils/privacy';

interface UsersTabProps {
  users: DbUser[];
  employees: Employee[];
  privacyMode?: boolean;
  onNavigateTab?: (tab: ActiveTab) => void;
}

const BASELINE_PROFILES: Record<
  string,
  { role: string; trustedHost: string; trustedOsUser: string; trustedClient: string }
> = {
  U1: {
    role: 'Chuyên viên Nhân sự (HR Officer)',
    trustedHost: 'LAPTOP-R03ORTGV',
    trustedOsUser: 'pc',
    trustedClient: 'SQL Developer',
  },
  U2: {
    role: 'Kế toán Tiền lương (Payroll Analyst)',
    trustedHost: 'WORKSTATION-FIN02',
    trustedOsUser: 'fin_u2',
    trustedClient: 'SQL Developer',
  },
  U3: {
    role: 'Cán bộ Thống kê (SDB Researcher)',
    trustedHost: 'ANALYST-PC03',
    trustedOsUser: 'stat_u3',
    trustedClient: 'SQL Developer',
  },
  U4: {
    role: 'Thực tập sinh Kiểm thử (Sandbox User)',
    trustedHost: 'LAB-CLIENT-04',
    trustedOsUser: 'intern_u4',
    trustedClient: 'sqlplus.exe',
  },
};

export const UsersTab: React.FC<UsersTabProps> = ({
  users,
  employees,
  privacyMode = false,
  onNavigateTab,
}) => {
  return (
    <div className="space-y-6">
      {/* 1. Sensitive Employees Table (SYS.NV) & Honeytoken Trap */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60 flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
              <Table className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[13.5px] font-bold text-slate-100">
                Dữ liệu Bảng Nhạy cảm SYS.NV &amp; Bản ghi Bẫy Honeytoken (NV_TRAP)
              </div>
              <div className="text-[11px] text-slate-400">
                Bảo vệ đa tầng: Trigger TRG_PROTECT_NV + FGA_HONEYTOKEN_TRAP + FGA_HIGH_SALARY_ACCESS
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2.5">
            {privacyMode && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/15 border border-purple-500/35 text-purple-300 text-[10.5px] font-mono">
                <EyeOff className="w-3 h-3" />
                Đã ẩn CMND &amp; Định danh
              </span>
            )}
            <span className="text-[11px] font-mono text-slate-400 tabular-nums">
              Số bản ghi: <strong className="text-emerald-400">{employees.length}</strong> (4 NV thực + 1 Honeytoken)
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-sky-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider">
                <th className="py-2.5 px-3.5">Mã NV</th>
                <th className="py-2.5 px-3.5">Phân loại Bản ghi</th>
                <th className="py-2.5 px-3.5">Họ và Tên</th>
                <th className="py-2.5 px-3.5">Lương ($x_i$)</th>
                <th className="py-2.5 px-3.5">Giới tính</th>
                <th className="py-2.5 px-3.5">CMND / CCCD (TDE / DBMS_CRYPTO)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {employees.map((r) => {
                const isTrap = r.MANV.toUpperCase() === 'NV_TRAP';
                return (
                  <tr
                    key={r.MANV}
                    className={`hover:bg-white/5 transition-colors ${
                      isTrap ? 'honeytoken-row' : ''
                    }`}
                  >
                    <td className="py-3 px-3.5 font-bold font-mono text-sky-300">{r.MANV}</td>
                    <td className="py-3 px-3.5">
                      {isTrap ? (
                        <span className="inline-flex items-center gap-1.5 text-[11px] font-bold font-mono text-red-300">
                          <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                          <span>HONEYTOKEN CANARY TRAP</span>
                        </span>
                      ) : (
                        <span className="text-[11.5px] text-slate-300">
                          Bản ghi Nghiệp vụ
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3.5 font-bold text-slate-200">{r.HOTEN}</td>
                    <td
                      className={`py-3 px-3.5 font-mono font-bold text-[13px] tabular-nums ${
                        isTrap ? 'text-red-400' : 'text-emerald-400'
                      }`}
                    >
                      {r.LUONG.toLocaleString()}
                    </td>
                    <td className="py-3 px-3.5 text-slate-300">{r.GIOITINH}</td>
                    <td className="py-3 px-3.5 font-mono text-slate-400 tabular-nums">
                      {maskCmnd(r.CMND, privacyMode)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* 2. Database User Baseline Profiles & Object Privileges */}
      <section className="bg-[#101b2e] border border-sky-500/20 rounded-xl shadow-lg shadow-black/30 overflow-hidden">
        <div className="p-3.5 px-4.5 border-b border-white/5 bg-[#0e1626]/60 flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-7 h-7 rounded-lg bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0">
              <Fingerprint className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[13.5px] font-bold text-slate-100">
                Hồ sơ Định danh Chuẩn (Baseline Profile) &amp; Phân quyền Đối tượng (DBA_TAB_PRIVS)
              </div>
              <div className="text-[11px] text-slate-400">
                Mật khẩu xác thực được băm một chiều (SHA-512 Salt) trong <code className="text-sky-300 font-mono">SYS.USER$</code> và ẩn hoàn toàn khỏi giao diện giám sát
              </div>
            </div>
          </div>

          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('ips')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#131e33] border border-sky-500/25 text-sky-300 hover:text-white hover:border-sky-400 text-[11.5px] font-semibold transition-colors cursor-pointer"
            >
              <Users className="w-3.5 h-3.5" />
              <span>Điều khiển Khóa / Hạ quyền tại tab IPS</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-sky-500/15 bg-[#0b1322] text-slate-400 uppercase text-[10.5px] font-bold tracking-wider">
                <th className="py-2.5 px-3.5">DB User</th>
                <th className="py-2.5 px-3.5">Mật khẩu (SYS.USER$)</th>
                <th className="py-2.5 px-3.5">Vai trò Nghiệp vụ</th>
                <th className="py-2.5 px-3.5">Host Chuẩn (Trusted Host)</th>
                <th className="py-2.5 px-3.5">OS User &amp; Client Chuẩn</th>
                <th className="py-2.5 px-3.5">Quyền hiện hành trên SYS.NV</th>
                <th className="py-2.5 px-3.5">Trạng thái &amp; Thời điểm khóa</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {users.map((u) => {
                const profile = BASELINE_PROFILES[u.USERNAME] || {
                  role: 'Database User',
                  trustedHost: 'LAPTOP-R03ORTGV',
                  trustedOsUser: 'pc',
                  trustedClient: 'SQL Developer',
                };
                const isLocked = u.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
                return (
                  <tr key={u.USERNAME} className="hover:bg-sky-500/5 transition-colors">
                    <td className="py-3 px-3.5 font-bold font-mono text-sky-300 text-[13px]">
                      {maskUsername(u.USERNAME, privacyMode)}
                    </td>
                    <td className="py-3 px-3.5 font-mono text-slate-500 text-[11.5px]">
                      •••••••• (SHA-512)
                    </td>
                    <td className="py-3 px-3.5 text-slate-200 font-medium">{profile.role}</td>
                    <td className="py-3 px-3.5 font-mono text-slate-300 text-[11.5px]">
                      {maskHost(profile.trustedHost, privacyMode)}
                    </td>
                    <td className="py-3 px-3.5 font-mono text-slate-400 text-[11.5px]">
                      {maskOsUser(profile.trustedOsUser, privacyMode)} · {profile.trustedClient}
                    </td>
                    <td className="py-3 px-3.5 font-mono text-[11.5px] text-emerald-300">
                      {u.PRIVILEGES} ({u.DML_STATUS})
                    </td>
                    <td className="py-3 px-3.5 font-mono text-[11.5px] tabular-nums">
                      <span className={isLocked ? 'text-red-400 font-bold' : 'text-emerald-400 font-semibold'}>
                        {u.ACCOUNT_STATUS}
                      </span>
                      {u.LOCK_DATE && (
                        <span className="text-slate-400 ml-1.5">({u.LOCK_DATE})</span>
                      )}
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
