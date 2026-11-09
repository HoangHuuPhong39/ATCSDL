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
import { maskUsername, maskHost, maskOsUser, maskCmnd, maskEmployeeName, maskSalary } from '../../utils/privacy';

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

const VI_NAME_MAP: Record<string, string> = {
  'Nguyen Van A': 'Nguyễn Văn A',
  'Tran Thi B': 'Trần Thị B',
  'Le Van C': 'Lê Văn C',
  'Pham Thi D': 'Phạm Thị D',
  'Hoang Van Sếp (VIP)': 'Hoàng Văn Sếp (VIP)',
};

export const UsersTab: React.FC<UsersTabProps> = ({
  users,
  employees,
  privacyMode = false,
  onNavigateTab,
}) => {
  return (
    <div className="space-y-5">
      {/* 1. Sensitive Employees Table (SYS.NV) & Honeytoken Trap */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="p-3.5 px-4 border-b border-[var(--line)] flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2 min-w-0">
            <Table className="w-4 h-4 text-[var(--ok)] shrink-0" />
            <h2 className="text-sm font-semibold text-[var(--text-1)] truncate">
              Dữ liệu bảng SYS.NV
            </h2>
          </div>
          <div className="flex items-center gap-2.5">
            {privacyMode && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--accent)] text-xs font-mono">
                <EyeOff className="w-3 h-3" />
                <span>Đã ẩn PII &amp; Lương</span>
              </span>
            )}
            <span className="text-xs font-mono text-[var(--text-3)] tabular-nums">
              Tổng số: <strong className="text-[var(--text-1)]">{employees.length}</strong> ({employees.filter((e) => e.MANV !== 'NV_TRAP').length} NV + {employees.filter((e) => e.MANV === 'NV_TRAP').length} Trap)
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                <th className="py-2.5 px-3.5">Mã NV</th>
                <th className="py-2.5 px-3.5">Phân loại</th>
                <th className="py-2.5 px-3.5">Họ và Tên</th>
                <th className="py-2.5 px-3.5">Lương</th>
                <th className="py-2.5 px-3.5">Giới tính</th>
                <th className="py-2.5 px-3.5">CMND / CCCD</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]">
              {employees.map((r) => {
                const isTrap = r.MANV.toUpperCase() === 'NV_TRAP';
                const displayName = VI_NAME_MAP[r.HOTEN] || r.HOTEN;
                const displayGender = r.GIOITINH === 'Nu' ? 'Nữ' : r.GIOITINH;

                return (
                  <tr
                    key={r.MANV}
                    className={`hover:bg-[var(--surface-hover)] transition-colors ${
                      isTrap ? 'bg-[var(--danger-soft)]/20' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3.5 font-semibold font-mono text-[var(--accent)]">{r.MANV}</td>
                    <td className="py-2.5 px-3.5">
                      {isTrap ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-semibold font-mono text-[var(--danger)]">
                          <AlertTriangle className="w-3.5 h-3.5 text-[var(--danger)]" />
                          <span>HONEYTOKEN TRAP</span>
                        </span>
                      ) : (
                        <span className="text-xs text-[var(--text-3)]">Bản ghi nghiệp vụ</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3.5 font-medium text-[var(--text-1)]">
                      {maskEmployeeName(displayName, privacyMode)}
                    </td>
                    <td
                      className={`py-2.5 px-3.5 font-mono font-semibold tabular-nums ${
                        isTrap ? 'text-[var(--danger)]' : 'text-[var(--ok)]'
                      }`}
                    >
                      {maskSalary(r.LUONG, privacyMode)}
                    </td>
                    <td className="py-2.5 px-3.5 text-[var(--text-2)]">{displayGender}</td>
                    <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)] tabular-nums">
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
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="p-3.5 px-4 border-b border-[var(--line)] flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2 min-w-0">
            <Fingerprint className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <h2 className="text-sm font-semibold text-[var(--text-1)] truncate">
              Hồ sơ định danh &amp; Phân quyền
            </h2>
          </div>

          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('ips')}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--accent)] hover:underline cursor-pointer focus-visible:ring"
            >
              <Users className="w-3.5 h-3.5" />
              <span>Quản trị quyền tại IPS</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                <th className="py-2.5 px-3.5">DB User</th>
                <th className="py-2.5 px-3.5">Mật khẩu</th>
                <th className="py-2.5 px-3.5">Vai trò</th>
                <th className="py-2.5 px-3.5">Trusted Host</th>
                <th className="py-2.5 px-3.5">OS User &amp; Client</th>
                <th className="py-2.5 px-3.5">Quyền SYS.NV</th>
                <th className="py-2.5 px-3.5">Trạng thái</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]">
              {users.map((u) => {
                const profile = BASELINE_PROFILES[u.USERNAME] || {
                  role: 'Database User',
                  trustedHost: 'LAPTOP-R03ORTGV',
                  trustedOsUser: 'pc',
                  trustedClient: 'SQL Developer',
                };
                const isLocked = u.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
                return (
                  <tr key={u.USERNAME} className="hover:bg-[var(--surface-hover)] transition-colors">
                    <td className="py-2.5 px-3.5 font-semibold font-mono text-[var(--accent)]">
                      {maskUsername(u.USERNAME, privacyMode)}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)] whitespace-nowrap">
                      •••••••• (SHA-512)
                    </td>
                    <td className="py-2.5 px-3.5 text-[var(--text-2)] font-medium">{profile.role}</td>
                    <td className="py-2.5 px-3.5 font-mono text-[var(--text-2)]">
                      {maskHost(profile.trustedHost, privacyMode)}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)]">
                      {maskOsUser(profile.trustedOsUser, privacyMode)} · {profile.trustedClient}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[var(--ok)]">
                      {u.PRIVILEGES} ({u.DML_STATUS})
                    </td>
                    <td className="py-2.5 px-3.5 font-mono tabular-nums">
                      <span className={isLocked ? 'text-[var(--danger)] font-semibold' : 'text-[var(--ok)] font-medium'}>
                        {u.ACCOUNT_STATUS}
                      </span>
                      {u.LOCK_DATE && (
                        <span className="text-[var(--text-3)] ml-1.5 text-xs">({u.LOCK_DATE})</span>
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
