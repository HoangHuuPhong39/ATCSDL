import React, { useState, useEffect } from 'react';
import {
  X,
  Database,
  Radio,
  Download,
  Send,
  ShieldCheck,
  Terminal,
  Copy,
  Check,
  CheckCircle2,
  AlertTriangle,
  LogOut,
} from 'lucide-react';
import { DataSourceMode, DbUser } from '../types/ids';
import { maskHost, maskUsername } from '../utils/privacy';

interface OracleBridgeModalProps {
  isOpen: boolean;
  onClose: () => void;
  users: DbUser[];
  isBridgeConnected: boolean;
  lastSyncTime: string | null;
  privacyMode: boolean;
  onExecuteOracleSql: (sql: string, dbUser: string) => Promise<string[]>;
  dsn?: string;
  dataSource?: DataSourceMode;
  activeMode?: DataSourceMode;
  onSwitchMode?: (mode: 'oracle_live' | 'simulation') => Promise<void> | void;
  csrfToken?: string | null;
  onNotify?: (message: string, type?: 'success' | 'error' | 'info') => void;
  onLogout?: () => void;
}

function formatDsnDisplay(rawDsn: string, privacyMode: boolean): string {
  if (!privacyMode) return rawDsn;
  const colonIdx = rawDsn.indexOf(':');
  if (colonIdx > 0) {
    return `${maskHost(rawDsn.slice(0, colonIdx), true)}${rawDsn.slice(colonIdx)}`;
  }
  const slashIdx = rawDsn.indexOf('/');
  if (slashIdx > 0) {
    return `${maskHost(rawDsn.slice(0, slashIdx), true)}${rawDsn.slice(slashIdx)}`;
  }
  return maskHost(rawDsn, true);
}

const WORKSHEET_PRESETS = [
  {
    label: 'Lệnh 1 (User_U1.sql): Gian lận tăng lương NV1 lên 10000 (ORA-20002)',
    user: 'U1',
    sql: "UPDATE SYS.NV SET luong = 10000 WHERE manv = 'NV1';",
  },
  {
    label: 'Lệnh 2 (User_U1.sql): Cố tình xóa nhân viên NV2 (ORA-20001)',
    user: 'U1',
    sql: "DELETE FROM SYS.NV WHERE manv = 'NV2';",
  },
  {
    label: 'Lệnh 3 (User_U1.sql): Tấn công SQL Injection (OR 1=1)',
    user: 'U1',
    sql: "SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;",
  },
  {
    label: 'Lệnh 4 (User_U1.sql): Chuỗi truy vấn Suy diễn Thống kê SDB (COUNT / SUM / AVG)',
    user: 'U3',
    sql: `SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam';
SELECT COUNT(*) FROM SYS.NV WHERE luong > 900;
SELECT SUM(luong) FROM SYS.NV WHERE luong > 900;
SELECT AVG(luong) FROM SYS.NV WHERE gioitinh = 'Nu';`,
  },
  {
    label: 'Lệnh 5: Truy vấn trực tiếp chạm bẫy Honeytoken (NV_TRAP)',
    user: 'U2',
    sql: "SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP';",
  },
  {
    label: 'Lệnh 6: Truy cập trái phép kho khóa mã hóa (V$ENCRYPTION_KEYS)',
    user: 'U4',
    sql: 'SELECT * FROM V$ENCRYPTION_KEYS;',
  },
];

export const OracleBridgeModal: React.FC<OracleBridgeModalProps> = ({
  isOpen,
  onClose,
  users,
  isBridgeConnected,
  lastSyncTime,
  privacyMode,
  onExecuteOracleSql,
  dsn,
  dataSource,
  activeMode: activeDataMode,
  onSwitchMode,
  csrfToken,
  onNotify,
  onLogout,
}) => {
  const [modalTab, setModalTab] = useState<'worksheet' | 'agent'>('worksheet');
  const [selectedUser, setSelectedUser] = useState<string>('U1');
  const [sqlInput, setSqlInput] = useState<string>(
    "UPDATE SYS.NV SET luong = 10000 WHERE manv = 'NV1';\nDELETE FROM SYS.NV WHERE manv = 'NV2';"
  );
  const [isSending, setIsSending] = useState<boolean>(false);
  const [isSwitchingMode, setIsSwitchingMode] = useState<boolean>(false);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [outputs, setOutputs] = useState<string[]>([]);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);

  useEffect(() => {
    if (!isOpen) return;
    setDownloadError(null);
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const appOrigin = typeof window !== 'undefined' ? window.location.origin : '';
  const resolvedDsn = dsn || 'localhost:1521/FREEPDB1';
  const serviceLabel = resolvedDsn.split('/').pop() || 'FREEPDB1';
  const displayDsn = formatDsnDisplay(resolvedDsn, privacyMode);
  const currentTargetMode: 'oracle_live' | 'simulation' =
    (activeDataMode ?? dataSource) === 'oracle_live' ? 'oracle_live' : 'simulation';

  const handleRunSqlSync = async () => {
    if (!sqlInput.trim()) return;
    setIsSending(true);
    try {
      const resOutputs = await onExecuteOracleSql(sqlInput, selectedUser);
      setOutputs(resOutputs);
    } finally {
      setIsSending(false);
    }
  };

  const handleModeSwitch = async (mode: 'oracle_live' | 'simulation') => {
    if (!onSwitchMode || isSwitchingMode || currentTargetMode === mode) return;
    setIsSwitchingMode(true);
    try {
      await onSwitchMode(mode);
    } finally {
      setIsSwitchingMode(false);
    }
  };

  const handleDownloadBridgeScript = async () => {
    setDownloadError(null);
    setIsDownloading(true);
    try {
      const res = await fetch('/api/oracle-bridge-bundle.zip', {
        method: 'GET',
        credentials: 'include',
      });
      if (!res.ok) {
        const msg =
          res.status === 401
            ? 'Phiên đăng nhập SOC đã hết hạn. Vui lòng đăng nhập lại để tải gói cầu nối oracle_ids_bridge_bundle.zip.'
            : `Không thể tải xuống oracle_ids_bridge_bundle.zip (HTTP ${res.status}).`;
        setDownloadError(msg);
        onNotify?.(msg, 'error');
        return;
      }
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      try {
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = 'oracle_ids_bridge_bundle.zip';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      } finally {
        URL.revokeObjectURL(objectUrl);
      }
      onNotify?.('Đã tải xuống oracle_ids_bridge_bundle.zip thành công!', 'success');
    } catch {
      const msg = 'Lỗi kết nối khi tải xuống oracle_ids_bridge_bundle.zip từ máy chủ.';
      setDownloadError(msg);
      onNotify?.(msg, 'error');
    } finally {
      setIsDownloading(false);
    }
  };

  const safeCsrfDisplay = privacyMode ? '••••••••' : csrfToken || '<CSRF_TOKEN>';
  const curlExample = `curl -X POST "${appOrigin}/api/execute-oracle-sql" -b "soc_session=<SESSION>" -H "Content-Type: application/json" -H "X-CSRF-Token: ${safeCsrfDisplay}" -d "{\\"dbUser\\":\\"U1\\",\\"sql\\":\\"SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;\\"}"`;

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(curlExample);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const dataSourceBadge =
    dataSource === 'oracle_live'
      ? {
          label: 'Live Oracle',
          cls: 'bg-[var(--ok-soft)] text-[var(--ok)] border-[var(--ok)]/30',
        }
      : dataSource === 'disconnected'
      ? {
          label: 'Disconnected',
          cls: 'bg-[var(--danger-soft)] text-[var(--danger)] border-[var(--danger)]/30',
        }
      : {
          label: 'Simulator',
          cls: 'bg-[var(--warn-soft)] text-[var(--warn)] border-[var(--warn)]/30',
        };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="oracle-bridge-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-[var(--surface)] border border-[var(--line)] rounded-xl w-full max-w-2xl shadow-2xl shadow-black/80 overflow-hidden flex flex-col max-h-[88vh]">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-[var(--line)] bg-[var(--surface)] flex items-center justify-between gap-2">
          <div id="oracle-bridge-modal-title" className="flex items-center gap-2.5 text-sm font-semibold text-[var(--text-1)] min-w-0">
            <Database className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <span className="truncate">Cổng kết nối Oracle SQL Developer ({serviceLabel})</span>
            {dataSource && (
              <span
                className={`text-xs font-mono px-2 py-0.5 rounded border shrink-0 ${dataSourceBadge.cls}`}
              >
                {dataSourceBadge.label}
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            {onLogout && (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onLogout();
                }}
                title="Đăng xuất phiên SOC"
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] border border-transparent hover:border-[var(--danger)]/30 transition-colors cursor-pointer focus-visible:ring"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Đăng xuất</span>
              </button>
            )}
            <button
              onClick={onClose}
              aria-label="Đóng cổng kết nối Oracle"
              className="w-7 h-7 rounded-md flex items-center justify-center text-[var(--text-3)] hover:text-[var(--text-1)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer focus-visible:ring"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Mode Switcher */}
        <div className="px-5 pt-3.5 bg-[var(--surface)] border-b border-[var(--line)] flex items-center justify-between flex-wrap gap-2 pb-3">
          <div className="flex items-center bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-1 gap-1">
            <button
              type="button"
              onClick={() => setModalTab('worksheet')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 focus-visible:ring ${
                modalTab === 'worksheet'
                  ? 'bg-[var(--accent)] text-white font-semibold'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Đồng bộ từ SQL Worksheet</span>
            </button>
            <button
              type="button"
              onClick={() => setModalTab('agent')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 focus-visible:ring ${
                modalTab === 'agent'
                  ? 'bg-[var(--accent)] text-white font-semibold'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Cầu nối tự động (Python Agent)</span>
            </button>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {(dataSource || onSwitchMode) && onSwitchMode && (
              <div
                role="group"
                aria-label="Chế độ nguồn dữ liệu"
                className="flex items-center bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-0.5 gap-0.5 text-xs"
              >
                <button
                  type="button"
                  disabled={isSwitchingMode}
                  onClick={() => void handleModeSwitch('oracle_live')}
                  className={`px-2 py-1 rounded-md font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                    currentTargetMode === 'oracle_live'
                      ? 'bg-[var(--ok-soft)] text-[var(--ok)] font-semibold'
                      : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                  }`}
                >
                  Live Oracle
                </button>
                <button
                  type="button"
                  disabled={isSwitchingMode}
                  onClick={() => void handleModeSwitch('simulation')}
                  className={`px-2 py-1 rounded-md font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                    currentTargetMode === 'simulation'
                      ? 'bg-[var(--warn-soft)] text-[var(--warn)] font-semibold'
                      : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                  }`}
                >
                  Simulator
                </button>
              </div>
            )}

            <div className="flex items-center gap-2 text-xs font-mono">
              <span
                className={`w-2 h-2 rounded-full ${
                  isBridgeConnected ? 'bg-[var(--ok)] animate-pulse' : 'bg-[var(--accent)]'
                }`}
              />
              <span className="text-[var(--text-3)]">
                {isBridgeConnected
                  ? `Đồng bộ lúc ${lastSyncTime?.substring(11, 19) || 'vừa xong'}`
                  : 'Sẵn sàng nhận sự kiện'}
              </span>
            </div>
          </div>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs">
          {modalTab === 'worksheet' ? (
            <>
              <div className="bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-3 text-xs text-[var(--text-2)] leading-relaxed flex items-start gap-2.5">
                <ShieldCheck className="w-4 h-4 text-[var(--ok)] shrink-0 mt-0.5" />
                <div>
                  Dán câu lệnh vừa thực thi trên <strong>Oracle SQL Developer</strong> (hoặc chọn lệnh mẫu bên dưới) để đồng bộ tức thời sự kiện vào hệ thống IDS. Thông tin đăng nhập được bảo mật tự động.
                </div>
              </div>

              {/* Quick preset selector */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block">
                  Câu lệnh mẫu nhanh (User_U1.sql / DEMO_COMMANDS.sql):
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                  {WORKSHEET_PRESETS.map((preset, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setSelectedUser(preset.user);
                        setSqlInput(preset.sql);
                      }}
                      className="text-left px-3 py-2 rounded-lg bg-[var(--surface-subtle)] hover:bg-[var(--surface-hover)] border border-[var(--line)] text-xs text-[var(--text-2)] hover:text-[var(--text-1)] transition-colors cursor-pointer truncate focus-visible:ring"
                      title={preset.label}
                    >
                      <span className="font-mono font-semibold text-[var(--accent)] mr-1.5">
                        [{maskUsername(preset.user, privacyMode)}]
                      </span>
                      <span>{preset.label.replace(/^Lệnh \d+.*?: /, '')}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Session Connection & SQL Input */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                    Kết nối (Connection)
                  </label>
                  <select
                    value={selectedUser}
                    onChange={(e) => setSelectedUser(e.target.value)}
                    className="w-full bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg text-[var(--text-1)] px-3 py-2 text-xs font-mono outline-none focus:border-[var(--accent)] cursor-pointer"
                  >
                    {users.map((u) => (
                      <option key={u.USERNAME} value={u.USERNAME}>
                        User_{maskUsername(u.USERNAME, privacyMode)} ({u.ACCOUNT_STATUS} · {u.DML_STATUS})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                    Oracle Service (DSN)
                  </label>
                  <div className="w-full bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg text-[var(--text-2)] px-3 py-2 text-xs font-mono truncate" title={displayDsn}>
                    {displayDsn}
                  </div>
                </div>
                <div>
                  <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                    Xác thực phiên
                  </label>
                  <div className="w-full bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg text-[var(--ok)] px-3 py-2 text-xs font-mono flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    <span>Mật khẩu đã mã hóa</span>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)]">
                    Câu lệnh SQL thực thi:
                  </label>
                  <span className="text-xs text-[var(--text-3)] font-mono">
                    Chạy 1 hoặc nhiều lệnh ngăn cách bằng ;
                  </span>
                </div>
                <textarea
                  rows={4}
                  value={sqlInput}
                  onChange={(e) => setSqlInput(e.target.value)}
                  placeholder="Dán câu lệnh SQL vừa chạy trên Oracle SQL Developer..."
                  className="w-full bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg p-3 font-mono text-xs text-[var(--text-1)] outline-none focus:border-[var(--accent)] leading-relaxed"
                />
              </div>

              {outputs.length > 0 && (
                <div className="bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-3 space-y-1.5">
                  <div className="text-xs font-semibold uppercase text-[var(--ok)] font-mono">
                    Kết quả phản hồi từ Oracle DB-IDS:
                  </div>
                  {outputs.map((line, idx) => (
                    <div key={idx} className="font-mono text-xs text-[var(--text-2)]">
                      • {line}
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="space-y-4">
              <div className="bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-3.5 space-y-2.5">
                <div className="font-semibold text-[var(--text-1)] text-xs flex items-center gap-2">
                  <Download className="w-4 h-4 text-[var(--accent)]" />
                  <span>Cách 1: Tải gói Bridge hoàn chỉnh &amp; chạy Agent (<code className="font-mono text-[var(--accent)]">python oracle/bridge.py</code>)</span>
                </div>
                <p className="text-xs text-[var(--text-2)] leading-relaxed">
                  Tải và giải nén gói <code className="text-[var(--accent)] font-mono">oracle_ids_bridge_bundle.zip</code> (bao gồm đầy đủ <code className="font-mono">oracle/*.py</code>, <code className="font-mono">shared/detection_policy.json</code>, <code className="font-mono">oracle/requirements.txt</code>, <code className="font-mono">oracle/SYS_FREEPDB1.sql</code>, <code className="font-mono">.env.example</code>) trên máy chạy Oracle. Sau khi giải nén, cấu hình <code className="font-mono">.env</code> từ <code className="font-mono">.env.example</code>, cài đặt thư viện bằng <code className="font-mono text-[var(--accent)]">pip install -r oracle/requirements.txt</code> rồi chạy <code className="font-mono text-[var(--accent)]">python oracle/bridge.py</code> từ thư mục gốc vừa giải nén để đồng bộ Audit Trail &amp; Triggers tự động về Dashboard.
                </p>
                <div className="pt-1 space-y-2">
                  <button
                    type="button"
                    onClick={() => void handleDownloadBridgeScript()}
                    disabled={isDownloading}
                    className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[var(--accent)] hover:opacity-90 text-white font-semibold text-xs transition-all cursor-pointer focus-visible:ring shadow-xs disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>{isDownloading ? 'Đang tải gói ZIP...' : 'Tải gói Bridge (oracle_ids_bridge_bundle.zip)'}</span>
                  </button>
                  {downloadError && (
                    <div
                      role="alert"
                      className="p-2.5 rounded-lg bg-[var(--danger-soft)] border border-[var(--danger)]/35 text-[var(--danger)] text-xs flex items-start gap-2"
                    >
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      <span>{downloadError}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-[var(--text-1)] text-xs">
                    Cách 2: Gửi sự kiện qua REST Webhook từ Terminal
                  </span>
                  <button
                    onClick={handleCopyCurl}
                    className="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline cursor-pointer"
                  >
                    {copiedCmd ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-[var(--ok)]" />
                        <span className="text-[var(--ok)]">Đã sao chép</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Sao chép lệnh</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-[var(--bg)] p-3 rounded-lg border border-[var(--line)] font-mono text-xs text-[var(--text-2)] overflow-x-auto">
                  {curlExample}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-[var(--line)] bg-[var(--surface)] flex items-center justify-between gap-2">
          <div className="text-xs text-[var(--text-3)] font-mono">
            Tự động làm mới: 3s · Bảo mật thông tin: {privacyMode ? 'Bật' : 'Tắt'}
          </div>
          <div className="flex items-center gap-2">
            {modalTab === 'worksheet' && (
              <button
                onClick={handleRunSqlSync}
                disabled={isSending}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[var(--accent)] hover:opacity-90 text-white text-xs font-semibold transition-all shadow-xs cursor-pointer focus-visible:ring disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isSending ? 'Đang gửi...' : 'Gửi lệnh về Dashboard'}</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-[var(--surface-hover)] hover:bg-[var(--surface-subtle)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
            >
              Đóng
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
