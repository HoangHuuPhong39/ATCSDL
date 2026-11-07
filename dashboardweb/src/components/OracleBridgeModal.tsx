import React, { useState } from 'react';
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
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-[#0f192b] border border-sky-500/35 rounded-xl w-full max-w-2xl shadow-2xl shadow-black/80 overflow-hidden flex flex-col max-h-[88vh]">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-white/10 bg-[#0c1424] flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5 text-[14px] font-bold text-slate-100">
            <Database className="w-4 h-4 text-sky-400 shrink-0" />
            <span>Cổng Kết nối &amp; Đồng bộ Cảnh báo Oracle SQL Developer (FREEPDB1)</span>
          </div>
          <button
            onClick={onClose}
            aria-label="Đóng cổng kết nối Oracle"
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Mode Switcher */}
        <div className="px-5 pt-3.5 bg-[#0c1424]/60 border-b border-white/5 flex items-center justify-between flex-wrap gap-2 pb-3">
          <div className="flex items-center bg-[#080d17] border border-sky-500/20 rounded-lg p-1 gap-1">
            <button
              onClick={() => setActiveMode('worksheet')}
              className={`px-3 py-1.5 rounded-md text-[12px] font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                activeMode === 'worksheet'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Đồng bộ Lệnh từ SQL Worksheet</span>
            </button>
            <button
              onClick={() => setActiveMode('agent')}
              className={`px-3 py-1.5 rounded-md text-[12px] font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
                activeMode === 'agent'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Cầu nối Tự động (Python Agent / Webhook)</span>
            </button>
          </div>

          <div className="flex items-center gap-2 text-[11px] font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                isBridgeConnected ? 'bg-emerald-400 animate-pulse' : 'bg-sky-400'
              }`}
            />
            <span className="text-slate-300">
              {isBridgeConnected
                ? `Đã đồng bộ lúc ${lastSyncTime?.substring(11, 19) || 'vừa xong'}`
                : 'Sẵn sàng nhận cảnh báo thời gian thực'}
            </span>
          </div>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-[12.5px]">
          {activeMode === 'worksheet' ? (
            <>
              <div className="bg-[#0b1322] border border-sky-500/20 rounded-lg p-3 text-[12px] text-slate-300 leading-relaxed flex items-start gap-2.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  Khi báo cáo thuyết trình cùng <strong>Oracle SQL Developer</strong>, bạn có thể dán trực tiếp câu lệnh vừa chạy trên Worksheet (hoặc chọn nhanh lệnh từ file <code className="text-sky-300 font-mono">User_U1.sql</code> bên dưới) để đẩy tức thời sự kiện vào bộ phân tích <strong>UNIFIED_AUDIT_TRAIL / Trigger / FGA</strong> của Dashboard. Mọi mật khẩu đều được ẩn tự động.
                </div>
              </div>

              {/* Quick preset selector matching User_U1.sql in screenshot */}
              <div className="space-y-1.5">
                <label className="text-[11px] font-bold uppercase text-slate-400 block">
                  Nạp nhanh câu lệnh từ Worksheet (User_U1.sql / DEMO_COMMANDS.sql):
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                  {WORKSHEET_PRESETS.map((preset, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setSelectedUser(preset.user);
                        setSqlInput(preset.sql);
                      }}
                      className="text-left px-3 py-2 rounded-lg bg-[#0b1322] hover:bg-[#131e33] border border-white/5 hover:border-sky-500/35 text-[11.5px] text-slate-200 transition-all cursor-pointer truncate"
                      title={preset.label}
                    >
                      <span className="font-mono font-bold text-sky-400 mr-1.5">
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
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                    Kết nối (Connection)
                  </label>
                  <select
                    value={selectedUser}
                    onChange={(e) => setSelectedUser(e.target.value)}
                    className="w-full bg-[#0b1322] border border-sky-500/25 rounded-lg text-slate-100 px-3 py-2 text-[12px] font-mono outline-none focus:border-sky-400"
                  >
                    {users.map((u) => (
                      <option key={u.USERNAME} value={u.USERNAME}>
                        User_{maskUsername(u.USERNAME, privacyMode)} ({u.ACCOUNT_STATUS} · {u.DML_STATUS})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                    Oracle Service (DSN)
                  </label>
                  <div className="w-full bg-[#0b1322] border border-white/10 rounded-lg text-slate-300 px-3 py-2 text-[12px] font-mono">
                    {privacyMode ? '••••••••:1521/FREEPDB1' : 'localhost:1521/FREEPDB1'}
                  </div>
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                    Xác thực Phiên
                  </label>
                  <div className="w-full bg-[#0b1322] border border-emerald-500/25 rounded-lg text-emerald-300 px-3 py-2 text-[12px] font-mono flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    <span>Mật khẩu đã mã hóa</span>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[11px] font-bold uppercase text-slate-400">
                    Câu lệnh SQL thực thi từ Oracle SQL Developer:
                  </label>
                  <span className="text-[10.5px] text-slate-400 font-mono">
                    Hỗ trợ chạy 1 lệnh hoặc nhiều lệnh cách nhau bởi dấu ;
                  </span>
                </div>
                <textarea
                  rows={4}
                  value={sqlInput}
                  onChange={(e) => setSqlInput(e.target.value)}
                  placeholder="Dán câu lệnh SQL vừa chạy trên Oracle SQL Developer..."
                  className="w-full bg-[#070d18] border border-sky-500/30 rounded-lg p-3 font-mono text-[12px] text-sky-300 outline-none focus:border-sky-400 leading-relaxed"
                />
              </div>

              {outputs.length > 0 && (
                <div className="bg-[#070d18] border border-emerald-500/30 rounded-lg p-3 space-y-1.5">
                  <div className="text-[10.5px] font-bold uppercase text-emerald-400 font-mono">
                    Kết quả Phản hồi từ Động cơ Giám sát Oracle DB-IDS:
                  </div>
                  {outputs.map((line, idx) => (
                    <div key={idx} className="font-mono text-[11.5px] text-slate-200">
                      • {line}
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="space-y-4">
              <div className="bg-[#0b1322] border border-sky-500/20 rounded-lg p-3.5 space-y-2">
                <div className="font-bold text-slate-100 text-[13px] flex items-center gap-2">
                  <Download className="w-4 h-4 text-sky-400" />
                  <span>Cách 1: Chạy Agent Đồng bộ Tự động từ máy cài Oracle (`oracle_bridge.py`)</span>
                </div>
                <p className="text-[12px] text-slate-300 leading-relaxed">
                  Tải file <code className="text-sky-300 font-mono">oracle_bridge.py</code> đặt cùng thư mục với <code className="text-sky-300 font-mono">ids_dashboard.py</code> trên máy tính của bạn. Khi bạn bấm nút Run (Ctrl+Enter) trong <strong>Oracle SQL Developer</strong>, mọi cảnh báo từ <code className="text-sky-300 font-mono">UNIFIED_AUDIT_TRAIL</code> và <code className="text-sky-300 font-mono">SYS.IDS_TRIGGER_ALERTS</code> sẽ tự động đẩy thẳng lên Dashboard này sau 2 giây mà <strong>không lộ bất kỳ mật khẩu hay thông tin nhạy cảm nào</strong>.
                </p>
                <div className="pt-1">
                  <a
                    href="/api/oracle-bridge.py"
                    download="oracle_bridge.py"
                    className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold text-[12px] transition-all cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Tải xuống oracle_bridge.py (Đã cấu hình sẵn URL Dashboard)</span>
                  </a>
                </div>
              </div>

              <div className="bg-[#0b1322] border border-white/10 rounded-lg p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-100 text-[13px]">
                    Cách 2: Gửi sự kiện qua REST Webhook từ Terminal / Script kiểm thử
                  </span>
                  <button
                    onClick={handleCopyCurl}
                    className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-white cursor-pointer"
                  >
                    {copiedCmd ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Đã sao chép</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Sao chép lệnh</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-[#070d18] p-3 rounded-lg border border-white/5 font-mono text-[11px] text-sky-300 overflow-x-auto">
                  {curlExample}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-white/10 bg-[#0c1424] flex items-center justify-between gap-2">
          <div className="text-[11px] text-slate-400 font-mono">
            Tự động làm mới: 3 giây/lần · Bảo mật thông tin đăng nhập: Đang bật
          </div>
          <div className="flex items-center gap-2">
            {activeMode === 'worksheet' && (
              <button
                onClick={handleRunSqlSync}
                disabled={isSending}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 border border-emerald-400 text-white text-[12px] font-bold transition-all cursor-pointer disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isSending ? 'Đang gửi về Dashboard...' : 'Gửi Lệnh & Phát Cảnh báo về Dashboard'}</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[12px] font-semibold transition-all cursor-pointer"
            >
              Đóng
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
