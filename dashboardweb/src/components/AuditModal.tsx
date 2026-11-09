import React, { useState, useEffect } from 'react';
import { X, Copy, Check, FileCode, ShieldAlert, CheckCircle2, Trash2, Unlock, Lock, ShieldCheck } from 'lucide-react';
import { AlertItem, AuditLogRow, DbUser } from '../types/ids';
import { maskUsername } from '../utils/privacy';

interface AuditModalProps {
  isOpen: boolean;
  onClose: () => void;
  alertItem?: AlertItem | null;
  auditRow?: AuditLogRow | null;
  users?: DbUser[];
  privacyMode?: boolean;
  onUserAction?: (username: string, action: 'lock' | 'unlock' | 'revoke_dml' | 'grant_dml') => void;
  onToggleReviewAlert?: (key: string) => void;
  onResolveAndResetAlert?: (key: string) => void;
  onResetAuditRow?: (row: AuditLogRow) => void;
}

export const AuditModal: React.FC<AuditModalProps> = ({
  isOpen,
  onClose,
  alertItem,
  auditRow,
  users = [],
  privacyMode = false,
  onUserAction,
  onToggleReviewAlert,
  onResolveAndResetAlert,
  onResetAuditRow,
}) => {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || (!alertItem && !auditRow)) return null;

  const sqlContent = alertItem?.details || auditRow?.SQL_TEXT || '';

  const handleCopySql = () => {
    if (!sqlContent) return;
    navigator.clipboard.writeText(sqlContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isAlert = !!alertItem;
  const displayedUser = alertItem?.user || auditRow?.DBUSERNAME || '';
  const matchedUser = users.find(
    (u) =>
      u.USERNAME === displayedUser ||
      maskUsername(u.USERNAME, true) === displayedUser ||
      maskUsername(u.USERNAME, privacyMode) === displayedUser
  );
  const isLocked = matchedUser?.ACCOUNT_STATUS.toUpperCase().includes('LOCK');
  const isReadOnly = matchedUser?.DML_STATUS.toUpperCase() === 'READ-ONLY';

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="audit-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-[var(--surface)] border border-[var(--line)] rounded-xl w-full max-w-2xl shadow-2xl shadow-black/80 overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-white/10 bg-[var(--surface)] flex items-center justify-between gap-2">
          <div id="audit-modal-title" className="flex items-center gap-2.5 text-[14px] font-bold text-slate-100">
            {isAlert ? (
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <FileCode className="w-4 h-4 text-sky-400 shrink-0" />
            )}
            <span>
              {isAlert
                ? 'Chi tiết Cảnh báo Xâm nhập Đa chiều (IDS Detection Alert)'
                : 'Chi tiết Bản ghi Kiểm toán (Unified Audit Trail)'}
            </span>
            {isAlert && alertItem?.reviewed && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                <CheckCircle2 className="w-3 h-3" />
                ĐÃ KIỂM DUYỆT
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            aria-label="Đóng hộp thoại chi tiết"
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs">
          {isAlert && alertItem ? (
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Thời gian phát hiện</div>
                <div className="font-mono text-slate-200">{alertItem.time}</div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Tài khoản CSDL vi phạm</div>
                <div className="font-bold text-sky-300 font-mono">{alertItem.user}</div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Mức độ cảnh báo (Severity)</div>
                <div>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold font-mono border ${
                      alertItem.severity === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-300 border-red-500/40'
                        : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                    }`}
                  >
                    {alertItem.severity} (Score: {alertItem.risk_score}/100)
                  </span>
                </div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Mức phản ứng IPS</div>
                <div className="font-semibold text-slate-200">{alertItem.response_label}</div>
              </div>
              <div className="col-span-2 bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Loại tấn công / Hành vi bất thường</div>
                <div className="font-bold text-amber-300">{alertItem.attack_type}</div>
              </div>
              <div className="col-span-2 bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Ngữ cảnh kết nối (Client / Host)</div>
                <div className="font-mono text-slate-300">{alertItem.context || '—'}</div>
              </div>
            </div>
          ) : auditRow ? (
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Thời gian sự kiện</div>
                <div className="font-mono text-slate-200">{auditRow.EVENT_TIMESTAMP}</div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Tài khoản CSDL</div>
                <div className="font-bold text-sky-300 font-mono">{auditRow.DBUSERNAME}</div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Hành động &amp; Loại Audit</div>
                <div className="flex items-center gap-1.5">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-mono text-xs font-semibold">
                    {auditRow.ACTION_NAME}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800 text-xs font-semibold">
                    {auditRow.AUDIT_TYPE || 'Standard'}
                  </span>
                </div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Mã trả về (Return Code)</div>
                <div>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold font-mono border ${
                      Number(auditRow.RETURN_CODE) === 0
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        : 'bg-red-500/20 text-red-300 border-red-500/40'
                    }`}
                  >
                    {Number(auditRow.RETURN_CODE) === 0 ? '0 (OK)' : `ORA-${auditRow.RETURN_CODE}`}
                  </span>
                </div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Đối tượng tác động</div>
                <div className="font-mono text-slate-200">
                  {auditRow.OBJECT_SCHEMA && auditRow.OBJECT_NAME
                    ? `${auditRow.OBJECT_SCHEMA}.${auditRow.OBJECT_NAME}`
                    : auditRow.OBJECT_NAME || '—'}
                </div>
              </div>
              <div className="bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Chính sách FGA / Unified Audit</div>
                <div className="font-mono text-purple-300">
                  {auditRow.FGA_POLICY_NAME || auditRow.UNIFIED_AUDIT_POLICIES || '—'}
                </div>
              </div>
              <div className="col-span-2 bg-[var(--surface-subtle)] border border-white/5 rounded-lg p-2.5">
                <div className="text-xs font-bold uppercase text-slate-400 mb-1">Tài khoản HĐH &amp; Máy trạm</div>
                <div className="font-mono text-slate-300">
                  {(auditRow.OS_USERNAME || '—') + ' @ ' + (auditRow.USERHOST || '—')} •{' '}
                  <span className="text-sky-400">{auditRow.CLIENT_PROGRAM_NAME || '—'}</span>
                </div>
              </div>
            </div>
          ) : null}

          {/* Direct 1-Click IPS Containment & Recovery Box inside Modal */}
          {matchedUser && onUserAction && (
            <div className="bg-[var(--surface-subtle)] border border-sky-500/25 rounded-lg p-3 flex items-center justify-between flex-wrap gap-2.5">
              <div className="text-xs">
                <span className="text-slate-400 font-semibold mr-1.5">Phản ứng IPS 1-Click cho</span>
                <strong className="font-mono text-sky-300">{displayedUser}</strong>
                <span className="font-mono text-slate-400 ml-2">
                  ({isLocked ? 'ĐANG KHÓA L3' : isReadOnly ? 'CHỈ ĐỌC L2' : 'OPEN · FULL DML'})
                </span>
              </div>
              <div className="flex items-center gap-2">
                {isReadOnly ? (
                  <button
                    onClick={() => onUserAction(matchedUser.USERNAME, 'grant_dml')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-sky-500/15 border border-sky-500/35 text-sky-300 hover:bg-sky-500/25 text-xs font-semibold cursor-pointer"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Khôi phục DML</span>
                  </button>
                ) : (
                  <button
                    onClick={() => onUserAction(matchedUser.USERNAME, 'revoke_dml')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-500/15 border border-amber-500/35 text-amber-300 hover:bg-amber-500/25 text-xs font-semibold cursor-pointer"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Hạ quyền Read-Only</span>
                  </button>
                )}
                {isLocked ? (
                  <button
                    onClick={() => onUserAction(matchedUser.USERNAME, 'unlock')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 text-xs font-bold cursor-pointer"
                  >
                    <Unlock className="w-3.5 h-3.5" />
                    <span>Mở khóa User (Unlock)</span>
                  </button>
                ) : (
                  <button
                    onClick={() => onUserAction(matchedUser.USERNAME, 'lock')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-500/15 border border-red-500/35 text-red-300 hover:bg-red-500/25 text-xs font-semibold cursor-pointer"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    <span>Khóa L3 (Lock)</span>
                  </button>
                )}
              </div>
            </div>
          )}

          {/* SQL Code Box */}
          <div>
            <div className="text-xs font-bold uppercase text-slate-400 mb-1.5 flex items-center justify-between">
              <span>{isAlert ? 'Chi tiết phát hiện / Câu lệnh vi phạm' : 'Câu lệnh SQL (SQL_TEXT)'}</span>
              <span className="text-xs text-sky-400 font-normal">Định dạng chuẩn Oracle</span>
            </div>
            <div className="bg-[var(--surface-subtle)] border border-sky-500/20 rounded-lg p-3.5 font-mono text-[12px] text-sky-300 break-words whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed selection:bg-sky-500/30">
              {sqlContent || '(Không có thêm chi tiết SQL)'}
            </div>
          </div>
        </div>

        {/* Footer with Review & Reset actions */}
        <div className="px-5 py-3 border-t border-white/10 bg-[var(--surface)] flex items-center justify-between flex-wrap gap-2.5">
          <div className="flex items-center gap-2 flex-wrap">
            {isAlert && alertItem && onToggleReviewAlert && (
              <button
                onClick={() => onToggleReviewAlert(alertItem.key)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-[12px] font-semibold transition-all cursor-pointer ${
                  alertItem.reviewed
                    ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30'
                    : 'bg-[var(--surface-subtle)] border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/15'
                }`}
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{alertItem.reviewed ? 'Đã kiểm duyệt (Bỏ dấu)' : 'Đánh dấu đã kiểm duyệt'}</span>
              </button>
            )}

            {isAlert && alertItem && onResolveAndResetAlert && (
              <button
                type="button"
                onClick={() => {
                  onResolveAndResetAlert(alertItem.key);
                  onClose();
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--line)] text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Reset cảnh báo</span>
              </button>
            )}

            {!isAlert && auditRow && onResetAuditRow && (
              <button
                type="button"
                onClick={() => {
                  onResetAuditRow(auditRow);
                  onClose();
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--line)] text-[var(--text-3)] hover:text-[var(--danger)] hover:bg-[var(--danger-soft)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Reset bản ghi</span>
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopySql}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--surface-subtle)] border border-sky-500/25 text-slate-200 hover:bg-[var(--surface-hover)] text-[12px] font-semibold transition-all cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Đã sao chép!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-400" />
                  <span>Sao chép SQL</span>
                </>
              )}
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-[12px] font-semibold transition-all cursor-pointer"
            >
              Đóng
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
