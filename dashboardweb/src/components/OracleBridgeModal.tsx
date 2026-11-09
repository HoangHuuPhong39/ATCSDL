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
} from 'lucide-react';
import { DbUser } from '../types/ids';
import { maskUsername } from '../utils/privacy';

interface OracleBridgeModalProps {
  isOpen: boolean;
  onClose: () => void;
  users: DbUser[];
  isBridgeConnected: boolean;
  lastSyncTime: string | null;
  privacyMode: boolean;
  onExecuteOracleSql: (sql: string, dbUser: string) => Promise<string[]>;
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
}) => {
  const [activeMode, setActiveMode] = useState<'worksheet' | 'agent'>('worksheet');
  const [selectedUser, setSelectedUser] = useState<string>('U1');
  const [sqlInput, setSqlInput] = useState<string>(
    "UPDATE SYS.NV SET luong = 10000 WHERE manv = 'NV1';\nDELETE FROM SYS.NV WHERE manv = 'NV2';"
  );
  const [isSending, setIsSending] = useState<boolean>(false);
  const [outputs, setOutputs] = useState<string[]>([]);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const appOrigin = typeof window !== 'undefined' ? window.location.origin : '';

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

  const curlExample = `curl -X POST "${appOrigin}/api/execute-oracle-sql" -H "Content-Type: application/json" -d "{\\"dbUser\\":\\"U1\\",\\"sql\\":\\"SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;\\"}"`;

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(curlExample);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
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
          <div id="oracle-bridge-modal-title" className="flex items-center gap-2.5 text-sm font-semibold text-[var(--text-1)]">
            <Database className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <span>Cổng kết nối Oracle SQL Developer (FREEPDB1)</span>
          </div>
          <button
            onClick={onClose}
            aria-label="Đóng cổng kết nối Oracle"
            className="w-7 h-7 rounded-md flex items-center justify-center text-[var(--text-3)] hover:text-[var(--text-1)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer focus-visible:ring"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Mode Switcher */}
        <div className="px-5 pt-3.5 bg-[var(--surface)] border-b border-[var(--line)] flex items-center justify-between flex-wrap gap-2 pb-3">
          <div className="flex items-center bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-1 gap-1">
            <button
              onClick={() => setActiveMode('worksheet')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 focus-visible:ring ${
                activeMode === 'worksheet'
                  ? 'bg-[var(--accent)] text-white font-semibold'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Đồng bộ từ SQL Worksheet</span>
            </button>
            <button
              onClick={() => setActiveMode('agent')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 focus-visible:ring ${
                activeMode === 'agent'
                  ? 'bg-[var(--accent)] text-white font-semibold'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Cầu nối tự động (Python Agent)</span>
            </button>
          </div>

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

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs">
          {activeMode === 'worksheet' ? (
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
                  <div className="w-full bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg text-[var(--text-2)] px-3 py-2 text-xs font-mono">
                    {privacyMode ? '••••••••:1521/FREEPDB1' : 'localhost:1521/FREEPDB1'}
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
              <div className="bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-3.5 space-y-2">
                <div className="font-semibold text-[var(--text-1)] text-xs flex items-center gap-2">
                  <Download className="w-4 h-4 text-[var(--accent)]" />
                  <span>Cách 1: Chạy Agent đồng bộ tự động (`oracle_bridge.py`)</span>
                </div>
                <p className="text-xs text-[var(--text-2)] leading-relaxed">
                  Tải file <code className="text-[var(--accent)] font-mono">oracle_bridge.py</code> đặt cùng thư mục trên máy chạy Oracle. Khi thực thi trong <strong>Oracle SQL Developer</strong>, các sự kiện từ Audit Trail và Triggers sẽ tự động gửi thẳng về Dashboard an toàn.
                </p>
                <div className="pt-1">
                  <a
                    href="/api/oracle-bridge.py"
                    download="oracle_bridge.py"
                    className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[var(--accent)] hover:opacity-90 text-white font-semibold text-xs transition-all cursor-pointer focus-visible:ring shadow-xs"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Tải xuống oracle_bridge.py</span>
                  </a>
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
            Tự động làm mới: 3s · Bảo mật thông tin: Bật
          </div>
          <div className="flex items-center gap-2">
            {activeMode === 'worksheet' && (
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
