import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Eye,
  EyeOff,
  AlertTriangle,
  ArrowRight,
  KeyRound,
  ShieldCheck,
} from 'lucide-react';

interface SocAuthGateProps {
  onLogin: (token: string) => Promise<boolean>;
  error: string | null;
  isLoading?: boolean;
  themeMode?: 'dark' | 'light';
}

export const SocAuthGate: React.FC<SocAuthGateProps> = ({
  onLogin,
  error,
  isLoading = false,
  themeMode = 'dark',
}) => {
  const [tokenInput, setTokenInput] = useState<string>('');
  const [showToken, setShowToken] = useState<boolean>(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const busy = isLoading || isSubmitting;
  const activeError = localError || error;

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const trimmed = tokenInput.trim();
    if (!trimmed) {
      setLocalError('Vui lòng nhập mã xác thực phiên SOC để tiếp tục.');
      return;
    }

    setLocalError(null);
    setIsSubmitting(true);
    try {
      const ok = await onLogin(trimmed);
      if (ok) {
        setTokenInput('');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      data-theme={themeMode}
      className={`min-h-screen soc-canvas-bg flex items-center justify-center p-4 font-sans ${
        themeMode === 'light' ? 'theme-light' : ''
      }`}
    >
      <div className="w-full max-w-md bg-[var(--surface)] border border-[var(--line)] rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-5 border-b border-[var(--line)] bg-[var(--surface-subtle)] flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-[var(--accent-soft)] border border-[var(--accent)]/30 flex items-center justify-center text-[var(--accent)] shrink-0">
            <Shield className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-base font-semibold text-[var(--text-1)] tracking-tight">
                Oracle DB-IDS 23ai
              </h1>
              <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--accent)]">
                SOC GATE
              </span>
            </div>
            <p className="text-xs text-[var(--text-3)] mt-0.5">
              Xác thực phiên quản trị an ninh CSDL &amp; Active IPS
            </p>
          </div>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4" noValidate>
          <div className="bg-[var(--surface-subtle)] border border-[var(--line)] rounded-xl p-3.5 flex items-start gap-2.5 text-xs text-[var(--text-2)] leading-relaxed">
            <ShieldCheck className="w-4 h-4 text-[var(--ok)] shrink-0 mt-0.5" />
            <div>
              Phiên làm việc được bảo vệ bằng cookie <code className="font-mono text-[var(--accent)]">HttpOnly</code> và mã chống giả mạo yêu cầu <code className="font-mono text-[var(--accent)]">X-CSRF-Token</code>.
            </div>
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="soc-auth-token"
              className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] flex items-center gap-1.5"
            >
              <KeyRound className="w-3.5 h-3.5 text-[var(--accent)]" />
              <span>Mã truy cập SOC (Access Token)</span>
            </label>

            <div className="relative">
              <input
                id="soc-auth-token"
                type={showToken ? 'text' : 'password'}
                value={tokenInput}
                onChange={(e) => {
                  setTokenInput(e.target.value);
                  if (localError) setLocalError(null);
                }}
                placeholder="Nhập SOC_ADMIN_TOKEN..."
                autoComplete="current-password"
                autoFocus
                disabled={busy}
                aria-invalid={Boolean(activeError)}
                aria-describedby={activeError ? 'soc-auth-error' : 'soc-auth-hint'}
                className="w-full bg-[var(--surface-hover)] border border-[var(--line)] rounded-xl px-3.5 py-2.5 pr-10 text-xs font-mono text-[var(--text-1)] placeholder:text-[var(--text-3)] outline-none focus:border-[var(--accent)] transition-colors disabled:opacity-60"
              />
              <button
                type="button"
                onClick={() => setShowToken((prev) => !prev)}
                aria-label={showToken ? 'Ẩn mã xác thực' : 'Hiện mã xác thực'}
                title={showToken ? 'Ẩn mã xác thực' : 'Hiện mã xác thực'}
                disabled={busy}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 rounded-md text-[var(--text-3)] hover:text-[var(--text-1)] hover:bg-[var(--surface)] transition-colors cursor-pointer focus-visible:ring"
              >
                {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            <p id="soc-auth-hint" className="text-xs text-[var(--text-3)]">
              Sử dụng biến môi trường <code className="font-mono">SOC_ADMIN_TOKEN</code> trong file <code className="font-mono">.env</code> hoặc token tạm thời được in trên console máy chủ khi khởi động.
            </p>
          </div>

          {activeError && (
            <div
              id="soc-auth-error"
              role="alert"
              className="p-3 rounded-xl bg-[var(--danger-soft)] border border-[var(--danger)]/35 text-[var(--danger)] text-xs flex items-start gap-2"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span className="font-medium leading-relaxed">{activeError}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--accent)] hover:opacity-90 text-white text-xs font-semibold transition-all cursor-pointer focus-visible:ring disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>{busy ? 'Đang xác thực phiên SOC...' : 'Mở khóa Bảng điều khiển SOC'}</span>
            {!busy && <ArrowRight className="w-3.5 h-3.5" />}
          </button>
        </form>
      </div>
    </div>
  );
};
