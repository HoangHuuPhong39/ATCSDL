import React from 'react';
import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info';
  message: string;
}

interface ToastProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const Toast: React.FC<ToastProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 max-w-md pointer-events-none"
    >
      {toasts.map((t) => {
        const isSuccess = t.type === 'success';
        const isError = t.type === 'error';

        return (
          <div
            key={t.id}
            className={`pointer-events-auto p-3.5 rounded-xl border shadow-xl flex items-start gap-2.5 text-xs leading-relaxed transition-all animate-in slide-in-from-bottom-2 duration-200 ${
              isError
                ? 'bg-[var(--danger-soft)] border-[var(--danger)]/30 text-[var(--danger)]'
                : isSuccess
                ? 'bg-[var(--ok-soft)] border-[var(--ok)]/30 text-[var(--ok)]'
                : 'bg-[var(--surface)] border-[var(--line)] text-[var(--text-1)]'
            }`}
          >
            {isError ? (
              <AlertTriangle className="w-4 h-4 text-[var(--danger)] shrink-0 mt-0.5" />
            ) : isSuccess ? (
              <CheckCircle2 className="w-4 h-4 text-[var(--ok)] shrink-0 mt-0.5" />
            ) : (
              <Info className="w-4 h-4 text-[var(--accent)] shrink-0 mt-0.5" />
            )}
            <div className="flex-1 font-medium">{t.message}</div>
            <button
              onClick={() => onDismiss(t.id)}
              aria-label="Đóng thông báo"
              className="text-[var(--text-3)] hover:text-[var(--text-1)] p-1 rounded cursor-pointer min-w-7 min-h-7 flex items-center justify-center focus-visible:ring"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
