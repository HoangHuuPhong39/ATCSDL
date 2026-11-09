import React, { useState, useEffect, useMemo } from 'react';
import {
  X,
  FileDown,
  ShieldCheck,
  EyeOff,
  Eye,
  FileText,
  ShieldAlert,
  Layers,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
} from 'lucide-react';
import {
  AlertItem,
  AuditLogRow,
  DbUser,
  FgaEvent,
  Metrics,
  TriggerAlert,
} from '../types/ids';
import {
  buildPdfReportModel,
  PdfExportScope,
  PdfReviewFilter,
  renderPdfReportPages,
  triggerPdfDownload,
} from '../utils/pdfExporter';

interface PdfExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialScope?: PdfExportScope;
  metrics: Metrics;
  users: DbUser[];
  alerts: AlertItem[];
  auditLogs: AuditLogRow[];
  fgaEvents: FgaEvent[];
  triggers: TriggerAlert[];
  defaultPrivacyMode: boolean;
  onExportSuccess: (filename: string, pageCount: number, scope: PdfExportScope) => void;
}

export const PdfExportModal: React.FC<PdfExportModalProps> = ({
  isOpen,
  onClose,
  initialScope = 'full',
  metrics,
  users,
  alerts,
  auditLogs,
  fgaEvents,
  triggers,
  defaultPrivacyMode,
  onExportSuccess,
}) => {
  const [scope, setScope] = useState<PdfExportScope>(initialScope);
  const [reviewFilter, setReviewFilter] = useState<PdfReviewFilter>('ALL');
  const [pdfPrivacyMode, setPdfPrivacyMode] = useState<boolean>(defaultPrivacyMode);
  const [auditorName, setAuditorName] = useState<string>('Quản trị viên An ninh CSDL (SOC / DBA)');
  const [reportCode, setReportCode] = useState<string>(
    `SOC-ORA23AI-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`
  );
  const [notes, setNotes] = useState<string>(
    'Hồ sơ lưu trữ cảnh báo xâm nhập và nhật ký kiểm toán phục vụ báo cáo an toàn CSDL Oracle 23ai.'
  );
  const [previewPageIndex, setPreviewPageIndex] = useState<number>(0);

  useEffect(() => {
    if (isOpen) {
      setScope(initialScope);
      setPdfPrivacyMode(defaultPrivacyMode);
      setPreviewPageIndex(0);
    }
  }, [isOpen, initialScope, defaultPrivacyMode]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const reportModel = useMemo(() => {
    return buildPdfReportModel(
      {
        metrics,
        users,
        alerts,
        auditLogs,
        fgaEvents,
        triggers,
      },
      {
        scope,
        reviewFilter,
        privacyMode: pdfPrivacyMode,
        auditorName,
        reportCode,
        notes,
      }
    );
  }, [
    metrics,
    users,
    alerts,
    auditLogs,
    fgaEvents,
    triggers,
    scope,
    reviewFilter,
    pdfPrivacyMode,
    auditorName,
    reportCode,
    notes,
  ]);

  const renderedPdf = useMemo(() => {
    if (!isOpen || typeof document === 'undefined') {
      return { pageDataUrls: [], pdfBytes: new Uint8Array() };
    }
    return renderPdfReportPages(reportModel);
  }, [isOpen, reportModel]);

  if (!isOpen) return null;

  const totalPages = Math.max(1, renderedPdf.pageDataUrls.length);
  const safePageIdx = Math.min(previewPageIndex, totalPages - 1);

  const handleDownloadPdf = () => {
    const scopeSlug =
      scope === 'alerts'
        ? 'Canh_Bao_IDS'
        : scope === 'audit'
        ? 'Nhat_Ky_Audit_Log'
        : 'Ho_So_Tong_Hop_SOC';
    const filename = `${reportCode}_${scopeSlug}.pdf`;
    triggerPdfDownload(renderedPdf.pdfBytes, filename);
    onExportSuccess(filename, totalPages, scope);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="pdf-export-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/70 backdrop-blur-xs"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-[var(--surface)] border border-[var(--line)] rounded-xl w-full max-w-5xl shadow-2xl shadow-black/80 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-[var(--line)] bg-[var(--surface)] flex items-center justify-between gap-2">
          <div id="pdf-export-modal-title" className="flex items-center gap-2.5 text-sm font-semibold text-[var(--text-1)]">
            <FileDown className="w-4 h-4 text-[var(--accent)] shrink-0" />
            <span>Xuất hồ sơ báo cáo PDF</span>
          </div>
          <button
            onClick={onClose}
            aria-label="Đóng cửa sổ xuất PDF"
            className="w-7 h-7 rounded-md flex items-center justify-center text-[var(--text-3)] hover:text-[var(--text-1)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer focus-visible:ring"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body: Left Configuration + Right Live A4 Preview */}
        <div className="p-5 overflow-y-auto grid grid-cols-1 lg:grid-cols-12 gap-5 text-xs">
          {/* Left 6 cols: Export Configuration */}
          <div className="lg:col-span-6 space-y-4">
            {/* 1. Scope selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block">
                Loại hồ sơ báo cáo
              </label>
              <div className="grid grid-cols-1 gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setScope('full');
                    setPreviewPageIndex(0);
                  }}
                  className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex items-start justify-between gap-3 focus-visible:ring ${
                    scope === 'full'
                      ? 'bg-[var(--accent)]/10 border-[var(--accent)] text-[var(--text-1)]'
                      : 'bg-[var(--surface-subtle)] border-[var(--line)] text-[var(--text-2)] hover:border-[var(--line-hover)] hover:bg-[var(--surface-hover)]'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <Layers className={`w-4 h-4 shrink-0 mt-0.5 ${scope === 'full' ? 'text-[var(--accent)]' : 'text-[var(--text-3)]'}`} />
                    <div>
                      <div className="font-semibold text-xs text-[var(--text-1)]">
                        Hồ sơ bảo mật tổng hợp (Full SOC Report)
                      </div>
                      <div className="text-xs text-[var(--text-3)] mt-0.5">
                        Tóm tắt KPI, 4 User, Cảnh báo ({reportModel.summary.totalAlerts}) &amp; Kiểm toán ({reportModel.summary.totalAuditLogs})
                      </div>
                    </div>
                  </div>
                  {scope === 'full' && <CheckCircle2 className="w-4 h-4 text-[var(--accent)] shrink-0" />}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setScope('alerts');
                    setPreviewPageIndex(0);
                  }}
                  className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex items-start justify-between gap-3 focus-visible:ring ${
                    scope === 'alerts'
                      ? 'bg-[var(--accent)]/10 border-[var(--accent)] text-[var(--text-1)]'
                      : 'bg-[var(--surface-subtle)] border-[var(--line)] text-[var(--text-2)] hover:border-[var(--line-hover)] hover:bg-[var(--surface-hover)]'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <ShieldAlert className={`w-4 h-4 shrink-0 mt-0.5 ${scope === 'alerts' ? 'text-[var(--accent)]' : 'text-[var(--text-3)]'}`} />
                    <div>
                      <div className="font-semibold text-xs text-[var(--text-1)]">
                        Cảnh báo xâm nhập CSDL (IDS Alerts Only)
                      </div>
                      <div className="text-xs text-[var(--text-3)] mt-0.5">
                        Trích xuất chuyên sâu danh sách {reportModel.summary.totalAlerts} cảnh báo DBMS &amp; SDB
                      </div>
                    </div>
                  </div>
                  {scope === 'alerts' && <CheckCircle2 className="w-4 h-4 text-[var(--accent)] shrink-0" />}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setScope('audit');
                    setPreviewPageIndex(0);
                  }}
                  className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex items-start justify-between gap-3 focus-visible:ring ${
                    scope === 'audit'
                      ? 'bg-[var(--accent)]/10 border-[var(--accent)] text-[var(--text-1)]'
                      : 'bg-[var(--surface-subtle)] border-[var(--line)] text-[var(--text-2)] hover:border-[var(--line-hover)] hover:bg-[var(--surface-hover)]'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <FileText className={`w-4 h-4 shrink-0 mt-0.5 ${scope === 'audit' ? 'text-[var(--accent)]' : 'text-[var(--text-3)]'}`} />
                    <div>
                      <div className="font-semibold text-xs text-[var(--text-1)]">
                        Nhật ký kiểm toán hợp nhất (UNIFIED_AUDIT_TRAIL Only)
                      </div>
                      <div className="text-xs text-[var(--text-3)] mt-0.5">
                        Trích xuất {reportModel.summary.totalAuditLogs} bản ghi kiểm toán SQL, Policy và Ngữ cảnh
                      </div>
                    </div>
                  </div>
                  {scope === 'audit' && <CheckCircle2 className="w-4 h-4 text-[var(--accent)] shrink-0" />}
                </button>
              </div>
            </div>

            {/* 2. Review status filter & Privacy Mode */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                  Trạng thái duyệt
                </label>
                <select
                  value={reviewFilter}
                  onChange={(e) => {
                    setReviewFilter(e.target.value as PdfReviewFilter);
                    setPreviewPageIndex(0);
                  }}
                  className="w-full bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg text-[var(--text-1)] px-3 py-2 text-xs outline-none focus:border-[var(--accent)] cursor-pointer"
                >
                  <option value="ALL">Tất cả bản ghi</option>
                  <option value="PENDING">Chỉ bản ghi chờ duyệt</option>
                  <option value="REVIEWED">Chỉ bản ghi đã duyệt</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                  Bảo mật định danh
                </label>
                <button
                  type="button"
                  onClick={() => setPdfPrivacyMode((prev) => !prev)}
                  className={`w-full px-3 py-2 rounded-lg border text-xs font-medium flex items-center justify-between transition-colors cursor-pointer focus-visible:ring ${
                    pdfPrivacyMode
                      ? 'bg-[var(--accent)]/10 border-[var(--accent)]/40 text-[var(--accent)]'
                      : 'bg-[var(--surface-hover)] border-[var(--line)] text-[var(--text-3)] hover:text-[var(--text-1)]'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    {pdfPrivacyMode ? (
                      <EyeOff className="w-3.5 h-3.5 text-[var(--accent)]" />
                    ) : (
                      <Eye className="w-3.5 h-3.5 text-[var(--text-3)]" />
                    )}
                    <span>{pdfPrivacyMode ? 'Ẩn User & Host' : 'Hiện đầy đủ'}</span>
                  </span>
                  <span className="font-mono text-xs uppercase">
                    {pdfPrivacyMode ? 'MASKED' : 'RAW'}
                  </span>
                </button>
              </div>
            </div>

            {/* 3. Report Metadata fields */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                  Mã hồ sơ lưu trữ
                </label>
                <input
                  type="text"
                  value={reportCode}
                  onChange={(e) => setReportCode(e.target.value)}
                  className="w-full bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg text-[var(--text-1)] px-3 py-1.5 text-xs font-mono outline-none focus:border-[var(--accent)]"
                />
              </div>
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                  Người lập / Kiểm toán viên
                </label>
                <input
                  type="text"
                  value={auditorName}
                  onChange={(e) => setAuditorName(e.target.value)}
                  className="w-full bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg text-[var(--text-1)] px-3 py-1.5 text-xs outline-none focus:border-[var(--accent)]"
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold uppercase tracking-wider text-[var(--text-3)] block mb-1">
                Ghi chú &amp; nhận định đính kèm
              </label>
              <input
                type="text"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                className="w-full bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg text-[var(--text-1)] px-3 py-1.5 text-xs outline-none focus:border-[var(--accent)]"
              />
            </div>

            <div className="bg-[var(--surface-subtle)] border border-[var(--line)] rounded-lg p-3 text-xs text-[var(--text-2)] flex items-start gap-2.5">
              <ShieldCheck className="w-4 h-4 text-[var(--ok)] shrink-0 mt-0.5" />
              <div>
                File PDF được kết xuất chuẩn trang <strong>A4 (150 DPI)</strong> hỗ trợ đầy đủ <strong>Tiếng Việt có dấu</strong>, tự động che thông tin nhạy cảm và đính kèm dấu xác nhận an ninh.
              </div>
            </div>
          </div>

          {/* Right 6 cols: Live A4 Page Preview */}
          <div className="lg:col-span-6 bg-[var(--surface-subtle)] border border-[var(--line)] rounded-xl p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-xs font-semibold text-[var(--text-2)] flex items-center gap-2">
                <span>Bản xem trước A4</span>
                <span className="px-2 py-0.5 rounded bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] font-mono text-xs">
                  {totalPages} trang
                </span>
              </span>

              {totalPages > 1 && (
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setPreviewPageIndex((p) => Math.max(0, p - 1))}
                    disabled={safePageIdx === 0}
                    className="w-6 h-6 rounded flex items-center justify-center bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)] disabled:opacity-40 cursor-pointer focus-visible:ring"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                  </button>
                  <span className="font-mono text-xs text-[var(--text-3)]">
                    Trang {safePageIdx + 1} / {totalPages}
                  </span>
                  <button
                    type="button"
                    onClick={() => setPreviewPageIndex((p) => Math.min(totalPages - 1, p + 1))}
                    disabled={safePageIdx >= totalPages - 1}
                    className="w-6 h-6 rounded flex items-center justify-center bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)] disabled:opacity-40 cursor-pointer focus-visible:ring"
                  >
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>

            <div className="flex-1 flex items-center justify-center bg-[var(--bg)] rounded-lg p-2 border border-[var(--line)] overflow-hidden">
              {renderedPdf.pageDataUrls[safePageIdx] ? (
                <img
                  src={renderedPdf.pageDataUrls[safePageIdx]}
                  alt={`Xem trước báo cáo PDF trang ${safePageIdx + 1}`}
                  className="max-h-[410px] w-auto object-contain rounded shadow-md border border-[var(--line)]"
                />
              ) : (
                <div className="text-[var(--text-3)] text-xs py-16">
                  Đang tạo bản xem trước PDF...
                </div>
              )}
            </div>

            <div className="mt-2.5 flex items-center justify-between text-xs text-[var(--text-3)] font-mono">
              <span>Định dạng: PDF 1.4 A4</span>
              <span>
                Dung lượng: ~{Math.max(12, Math.round(renderedPdf.pdfBytes.length / 1024))} KB
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 border-t border-[var(--line)] bg-[var(--surface)] flex items-center justify-between flex-wrap gap-2">
          <div className="text-xs text-[var(--text-3)]">
            Sẵn sàng xuất: <strong className="text-[var(--text-1)] font-mono">{reportModel.alertRows.length}</strong> cảnh báo &amp;{' '}
            <strong className="text-[var(--text-1)] font-mono">{reportModel.auditRows.length}</strong> bản ghi kiểm toán
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleDownloadPdf}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--accent)] hover:opacity-90 text-white text-xs font-semibold transition-all shadow-xs cursor-pointer focus-visible:ring"
            >
              <FileDown className="w-4 h-4" />
              <span>Tải xuống File PDF (.pdf)</span>
            </button>
            <button
              type="button"
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
