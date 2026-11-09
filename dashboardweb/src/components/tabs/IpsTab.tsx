import React, { useState, useRef, useEffect } from 'react';
import {
  Sliders,
  Lock,
  Unlock,
  ShieldCheck,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import { DbUser } from '../../types/ids';
import { maskUsername } from '../../utils/privacy';
import { getRiskColorHex } from '../../utils/analytics';

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
  const [confirmClearAll, setConfirmClearAll] = useState(false);
  const [confirmLockUser, setConfirmLockUser] = useState<string | null>(null);
  const lockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    };
  }, []);

  const handleLockUser = (username: string) => {
    if (confirmLockUser === username) {
      onUserAction(username, 'lock');
      setConfirmLockUser(null);
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
    } else {
      setConfirmLockUser(username);
      if (lockTimerRef.current) clearTimeout(lockTimerRef.current);
      lockTimerRef.current = setTimeout(() => setConfirmLockUser(null), 3000);
    }
  };

  return (
    <div className="space-y-4">
      {/* Control Panel */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="p-3.5 px-4 border-b border-[var(--line)] flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2 min-w-0">
            <Sliders className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <h2 className="text-sm font-semibold text-[var(--text-1)] truncate">
              Điều khiển phản ứng đa cấp (Active IPS)
            </h2>
          </div>

          {/* Reset button: ghost + trash */}
          {confirmClearAll ? (
            <div className="inline-flex items-center gap-1">
              <button
                type="button"
                onClick={() => {
                  onClearAll();
                  setConfirmClearAll(false);
                }}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-[var(--danger)] text-white text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Xác nhận Reset toàn bộ?</span>
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
              title="Đặt lại toàn bộ Risk Score về 0 & khôi phục quyền User"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Reset Risk Score &amp; Lịch sử</span>
            </button>
          )}
        </div>

        <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Switch 1: Auto Response */}
          <div className="flex items-center justify-between p-3 bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg">
            <div className="min-w-0 pr-3">
              <div className="font-medium text-[var(--text-1)] text-xs">
                Tự động phản ứng theo Risk Score
              </div>
              <div className="text-xs text-[var(--text-3)] mt-0.5 truncate">
                L2: Read-Only (50–79) · L3: Khóa tài khoản (&ge; 80)
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer shrink-0">
              <input
                type="checkbox"
                aria-label="Tự động Phản ứng theo Risk Score"
                checked={autoResponse}
                onChange={(e) => onToggleAutoResponse(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-10 h-5.5 bg-[var(--line)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4.5 after:w-4.5 after:transition-all peer-checked:bg-[var(--ok)]"></div>
            </label>
          </div>

          {/* Switch 2: Auto Refresh */}
          <div className="flex items-center justify-between p-3 bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg">
            <div className="min-w-0 pr-3">
              <div className="font-medium text-[var(--text-1)] text-xs">
                Tự động đồng bộ thời gian thực
              </div>
              <div className="text-xs text-[var(--text-3)] mt-0.5 truncate">
                Polling định kỳ 3 giây từ Oracle FREEPDB1
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer shrink-0">
              <input
                type="checkbox"
                aria-label="Tự động đồng bộ dữ liệu thời gian thực từ Oracle"
                checked={autoRefresh}
                onChange={(e) => onToggleAutoRefresh(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-10 h-5.5 bg-[var(--line)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4.5 after:w-4.5 after:transition-all peer-checked:bg-[var(--ok)]"></div>
            </label>
          </div>
        </div>
      </section>

      {/* Defense Matrix Table */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="p-3 px-4 border-b border-[var(--line)]">
          <h2 className="text-sm font-semibold text-[var(--text-1)]">
            Ma trận phân cấp bảo vệ chủ động (L0–L3)
          </h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                <th className="py-2.5 px-3.5 w-36">Cấp độ</th>
                <th className="py-2.5 px-3.5 w-24">Risk Score</th>
                <th className="py-2.5 px-3.5 min-w-[200px]">Hành vi kích hoạt</th>
                <th className="py-2.5 px-3.5 min-w-[180px]">Biện pháp can thiệp</th>
                <th className="py-2.5 px-3.5 w-44">Quyền CSDL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]">
              <tr className="hover:bg-[var(--surface-hover)] transition-colors">
                <td className="py-2.5 px-3.5 font-semibold text-[var(--ok)] whitespace-nowrap">
                  Level 0: Normal
                </td>
                <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)]">0 – 19</td>
                <td className="py-2.5 px-3.5 text-[var(--text-2)]">Hoạt động bình thường</td>
                <td className="py-2.5 px-3.5 text-[var(--text-3)]">Ghi nhận kiểm toán tiêu chuẩn</td>
                <td className="py-2.5 px-3.5 text-[var(--ok)] font-mono font-medium">FULL DML</td>
              </tr>
              <tr className="hover:bg-[var(--surface-hover)] transition-colors">
                <td className="py-2.5 px-3.5 font-semibold text-[var(--accent)] whitespace-nowrap">
                  Level 1: Warning
                </td>
                <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)]">20 – 49</td>
                <td className="py-2.5 px-3.5 text-[var(--text-2)]">Sai mật khẩu 1-2 lần, đọc lương cao FGA</td>
                <td className="py-2.5 px-3.5 text-[var(--text-3)]">Cảnh báo SOC, tăng giám sát</td>
                <td className="py-2.5 px-3.5 text-[var(--accent)] font-mono font-medium">Duy trì quyền</td>
              </tr>
              <tr className="hover:bg-[var(--surface-hover)] transition-colors">
                <td className="py-2.5 px-3.5 font-semibold text-[var(--warn)] whitespace-nowrap">
                  Level 2: Containment
                </td>
                <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)]">50 – 79</td>
                <td className="py-2.5 px-3.5 text-[var(--text-2)]">Giả mạo Host, Suy diễn SDB, Trigger chặn</td>
                <td className="py-2.5 px-3.5 text-[var(--warn)] font-medium">Thu hồi quyền DML (REVOKE DML)</td>
                <td className="py-2.5 px-3.5 text-[var(--warn)] font-mono font-medium">READ-ONLY</td>
              </tr>
              <tr className="hover:bg-[var(--surface-hover)] transition-colors">
                <td className="py-2.5 px-3.5 font-semibold text-[var(--danger)] whitespace-nowrap">
                  Level 3: Isolation
                </td>
                <td className="py-2.5 px-3.5 font-mono text-[var(--text-3)]">80 – 100</td>
                <td className="py-2.5 px-3.5 text-[var(--text-2)]">SQLi, Leo thang quyền, Chạm bẫy NV_TRAP</td>
                <td className="py-2.5 px-3.5 text-[var(--danger)] font-medium">Khóa tài khoản &amp; Kill session</td>
                <td className="py-2.5 px-3.5 text-[var(--danger)] font-mono font-medium">LOCKED (TỪ CHỐI)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* User Status Table under IPS */}
      <section className="bg-[var(--surface)] border border-[var(--line)] rounded-xl overflow-hidden transition-colors">
        <div className="p-3 px-4 border-b border-[var(--line)]">
          <h2 className="text-sm font-semibold text-[var(--text-1)]">
            Trạng thái phản ứng từng tài khoản
          </h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--line)] bg-[var(--surface-subtle)] text-[var(--text-3)] uppercase text-xs font-semibold tracking-wider sticky top-0 z-10">
                <th className="py-2.5 px-3.5 w-24">User</th>
                <th className="py-2.5 px-3.5 w-28">Risk Score</th>
                <th className="py-2.5 px-3.5 min-w-[160px]">Cấp độ hiện tại</th>
                <th className="py-2.5 px-3.5 w-28">Quyền</th>
                <th className="py-2.5 px-3.5 w-24">Trạng thái</th>
                <th className="py-2.5 px-3.5 text-right w-48">Thao tác thủ công</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--line)]">
              {users.map((u) => {
                const isLocked = u.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
                const isReadOnly = !isLocked && u.DML_STATUS.toUpperCase() === 'READ-ONLY';
                const isOpen = !isLocked && !isReadOnly;
                const isConfirmingLock = confirmLockUser === u.USERNAME;
                const color = getRiskColorHex(u.RISK_SCORE);

                return (
                  <tr key={u.USERNAME} className="hover:bg-[var(--surface-hover)] transition-colors">
                    <td className="py-2.5 px-3.5 font-semibold font-mono text-[var(--text-1)] whitespace-nowrap">
                      {maskUsername(u.USERNAME, privacyMode)}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono">
                      <span className="font-semibold tabular-nums" style={{ color }}>
                        {u.RISK_SCORE}/100
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[var(--text-2)]">
                      {u.RESPONSE_LABEL}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono whitespace-nowrap">
                      <span className={isReadOnly ? 'text-[var(--warn)]' : 'text-[var(--ok)]'}>
                        {u.DML_STATUS}
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 font-mono whitespace-nowrap">
                      <span className={isLocked ? 'text-[var(--danger)] font-semibold' : 'text-[var(--ok)]'}>
                        {u.ACCOUNT_STATUS}
                      </span>
                    </td>

                    {/* Non-contradictory action buttons */}
                    <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-1.5 justify-end">
                        {isLocked && (
                          <button
                            type="button"
                            onClick={() => onUserAction(u.USERNAME, 'unlock')}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[var(--ok-soft)] border border-[var(--ok)]/30 text-[var(--ok)] hover:bg-[var(--ok-soft)]/80 text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
                            title="Mở khóa tài khoản & đặt lại Risk"
                          >
                            <Unlock className="w-3 h-3" />
                            <span>Mở khóa</span>
                          </button>
                        )}

                        {isReadOnly && (
                          <>
                            <button
                              type="button"
                              onClick={() => onUserAction(u.USERNAME, 'grant_dml')}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[var(--surface)] border border-[var(--line)] text-[var(--text-1)] hover:border-[var(--accent)] text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
                              title="Khôi phục quyền DML"
                            >
                              <ShieldCheck className="w-3 h-3 text-[var(--accent)]" />
                              <span>Khôi phục DML</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleLockUser(u.USERNAME)}
                              className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium cursor-pointer transition-colors focus-visible:ring ${
                                isConfirmingLock
                                  ? 'bg-[var(--danger)] text-white border border-[var(--danger)] animate-pulse'
                                  : 'bg-[var(--danger-soft)] border border-[var(--danger)]/30 text-[var(--danger)] hover:bg-[var(--danger)] hover:text-white'
                              }`}
                              title="Khóa tài khoản"
                            >
                              <Lock className="w-3 h-3" />
                              <span>{isConfirmingLock ? 'Bấm lại để xác nhận' : 'Khóa'}</span>
                            </button>
                          </>
                        )}

                        {isOpen && (
                          <>
                            <button
                              type="button"
                              onClick={() => onUserAction(u.USERNAME, 'revoke_dml')}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[var(--surface)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--warn)] text-xs font-medium cursor-pointer transition-colors focus-visible:ring"
                              title="Hạ quyền Read-Only"
                            >
                              <ShieldAlert className="w-3 h-3 text-[var(--warn)]" />
                              <span>Hạ quyền</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleLockUser(u.USERNAME)}
                              className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium cursor-pointer transition-colors focus-visible:ring ${
                                isConfirmingLock
                                  ? 'bg-[var(--danger)] text-white border border-[var(--danger)] animate-pulse'
                                  : 'bg-[var(--danger-soft)] border border-[var(--danger)]/30 text-[var(--danger)] hover:bg-[var(--danger)] hover:text-white'
                              }`}
                              title="Khóa tài khoản"
                            >
                              <Lock className="w-3 h-3" />
                              <span>{isConfirmingLock ? 'Bấm lại để xác nhận' : 'Khóa'}</span>
                            </button>
                          </>
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
