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
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/80 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-[#0f192b] border border-sky-500/35 rounded-xl w-full max-w-5xl shadow-2xl shadow-black/90 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-white/10 bg-[#0c1424] flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5 text-[14px] font-bold text-slate-100">
            <FileDown className="w-4 h-4 text-sky-400 shrink-0" />
            <span>Trích xuất Hồ sơ Báo cáo &amp; Lưu trữ Bảo mật định dạng PDF (Chuẩn A4)</span>
          </div>
          <button
            onClick={onClose}
            aria-label="Đóng cửa sổ xuất PDF"
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body: Left Configuration + Right Live A4 Preview */}
        <div className="p-5 overflow-y-auto grid grid-cols-1 lg:grid-cols-12 gap-5 text-[12.5px]">
          {/* Left 6 cols: Export Configuration */}
          <div className="lg:col-span-6 space-y-4">
            {/* 1. Scope selector */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-bold uppercase text-slate-400 block">
                1. Chọn Loại Hồ sơ Báo cáo PDF cần xuất:
              </label>
              <div className="grid grid-cols-1 gap-2">
                <button
                  onClick={() => {
                    setScope('full');
                    setPreviewPageIndex(0);
                  }}
                  className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex items-start justify-between gap-3 ${
                    scope === 'full'
                      ? 'bg-sky-500/15 border-sky-400 text-white'
                      : 'bg-[#0b1322] border-white/10 text-slate-300 hover:border-sky-500/35'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <Layers className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-bold text-[12.5px]">
                        Hồ sơ Bảo mật Tổng hợp (Full SOC Audit Report)
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Bao gồm Tóm tắt KPI, Trạng thái 4 User, Cảnh báo Xâm nhập ({reportModel.summary.totalAlerts}) &amp; Nhật ký Kiểm toán ({reportModel.summary.totalAuditLogs})
                      </div>
                    </div>
                  </div>
                  {scope === 'full' && <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />}
                </button>

                <button
                  onClick={() => {
                    setScope('alerts');
                    setPreviewPageIndex(0);
                  }}
                  className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex items-start justify-between gap-3 ${
                    scope === 'alerts'
                      ? 'bg-red-500/15 border-red-400 text-white'
                      : 'bg-[#0b1322] border-white/10 text-slate-300 hover:border-red-500/35'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-bold text-[12.5px]">
                        Báo cáo Cảnh báo Xâm nhập CSDL (IDS Alerts Only)
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Trích xuất chuyên sâu danh sách {reportModel.summary.totalAlerts} cảnh báo kỹ thuật DBMS &amp; suy diễn thống kê SDB
                      </div>
                    </div>
                  </div>
                  {scope === 'alerts' && <CheckCircle2 className="w-4 h-4 text-red-400 shrink-0" />}
                </button>

                <button
                  onClick={() => {
                    setScope('audit');
                    setPreviewPageIndex(0);
                  }}
                  className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex items-start justify-between gap-3 ${
                    scope === 'audit'
                      ? 'bg-emerald-500/15 border-emerald-400 text-white'
                      : 'bg-[#0b1322] border-white/10 text-slate-300 hover:border-emerald-500/35'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <FileText className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-bold text-[12.5px]">
                        Hồ sơ Nhật ký Kiểm toán Hợp nhất (UNIFIED_AUDIT_TRAIL Only)
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Trích xuất {reportModel.summary.totalAuditLogs} bản ghi kiểm toán SQL_TEXT, Policy, Return Code và Ngữ cảnh
                      </div>
                    </div>
                  </div>
                  {scope === 'audit' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
                </button>
              </div>
            </div>

            {/* 2. Review status filter & Privacy Mode */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                  2. Lọc theo Trạng thái Kiểm duyệt:
                </label>
                <select
                  value={reviewFilter}
                  onChange={(e) => {
                    setReviewFilter(e.target.value as PdfReviewFilter);
                    setPreviewPageIndex(0);
                  }}
                  className="w-full bg-[#0b1322] border border-sky-500/25 rounded-lg text-slate-100 px-3 py-2 text-[12px] outline-none focus:border-sky-400"
                >
                  <option value="ALL">Tất cả bản ghi (Mọi trạng thái)</option>
                  <option value="PENDING">Chỉ bản ghi Chờ duyệt</option>
                  <option value="REVIEWED">Chỉ bản ghi Đã kiểm duyệt</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                  3. Bảo mật Định danh trong PDF:
                </label>
                <button
                  type="button"
                  onClick={() => setPdfPrivacyMode((prev) => !prev)}
                  className={`w-full px-3 py-2 rounded-lg border text-[12px] font-semibold flex items-center justify-between transition-all cursor-pointer ${
                    pdfPrivacyMode
                      ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                      : 'bg-[#0b1322] border-amber-500/35 text-amber-300'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    {pdfPrivacyMode ? (
                      <EyeOff className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Eye className="w-3.5 h-3.5 text-amber-400" />
                    )}
                    <span>{pdfPrivacyMode ? 'Đang ẩn User & Host' : 'Hiện đầy đủ User'}</span>
                  </span>
                  <span className="font-mono text-[10.5px] uppercase">
                    {pdfPrivacyMode ? 'MASKED' : 'RAW'}
                  </span>
                </button>
              </div>
            </div>

            {/* 3. Report Metadata fields */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                  Mã Hồ sơ Lưu trữ:
                </label>
                <input
                  type="text"
                  value={reportCode}
                  onChange={(e) => setReportCode(e.target.value)}
                  className="w-full bg-[#0b1322] border border-sky-500/25 rounded-lg text-slate-100 px-3 py-1.5 text-[12px] font-mono outline-none focus:border-sky-400"
                />
              </div>
              <div>
                <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                  Người lập / Kiểm toán viên:
                </label>
                <input
                  type="text"
                  value={auditorName}
                  onChange={(e) => setAuditorName(e.target.value)}
                  className="w-full bg-[#0b1322] border border-sky-500/25 rounded-lg text-slate-100 px-3 py-1.5 text-[12px] outline-none focus:border-sky-400"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] font-bold uppercase text-slate-400 block mb-1">
                Ghi chú &amp; Nhận định Kiểm toán đính kèm trong PDF:
              </label>
              <input
                type="text"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                className="w-full bg-[#0b1322] border border-sky-500/25 rounded-lg text-slate-100 px-3 py-1.5 text-[12px] outline-none focus:border-sky-400"
              />
            </div>

            <div className="bg-[#0b1322] border border-emerald-500/25 rounded-lg p-3 text-[11.5px] text-slate-300 flex items-start gap-2.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                File PDF được kết xuất chuẩn trang <strong>A4 (150 DPI)</strong> hỗ trợ đầy đủ <strong>Tiếng Việt có dấu</strong>, tự động ẩn mật khẩu <code className="text-sky-300 font-mono">•••••••• (SHA-512)</code> và đính kèm dấu xác nhận kiểm duyệt an ninh.
              </div>
            </div>
          </div>

          {/* Right 6 cols: Live A4 Page Preview */}
          <div className="lg:col-span-6 bg-[#080d17] border border-white/10 rounded-xl p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-[11.5px] font-bold text-slate-200 flex items-center gap-2">
                <span>Bản xem trước Trang A4 Thời gian thực</span>
                <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 font-mono text-[10.5px]">
                  {totalPages} trang
                </span>
              </span>

              {totalPages > 1 && (
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setPreviewPageIndex((p) => Math.max(0, p - 1))}
                    disabled={safePageIdx === 0}
                    className="p-1 rounded bg-[#131e33] border border-white/10 text-slate-300 hover:text-white disabled:opacity-40 cursor-pointer"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                  </button>
                  <span className="font-mono text-[11px] text-slate-300">
                    Trang {safePageIdx + 1} / {totalPages}
                  </span>
                  <button
                    onClick={() => setPreviewPageIndex((p) => Math.min(totalPages - 1, p + 1))}
                    disabled={safePageIdx >= totalPages - 1}
                    className="p-1 rounded bg-[#131e33] border border-white/10 text-slate-300 hover:text-white disabled:opacity-40 cursor-pointer"
                  >
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>

            <div className="flex-1 flex items-center justify-center bg-[#05080f] rounded-lg p-2 border border-white/5 overflow-hidden">
              {renderedPdf.pageDataUrls[safePageIdx] ? (
                <img
                  src={renderedPdf.pageDataUrls[safePageIdx]}
                  alt={`Xem trước báo cáo PDF trang ${safePageIdx + 1}`}
                  className="max-h-[410px] w-auto object-contain rounded shadow-lg border border-white/15"
                />
              ) : (
                <div className="text-slate-500 text-[12px] py-16">
                  Đang tạo bản xem trước PDF...
                </div>
              )}
            </div>

            <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span>Định dạng: PDF 1.4 Chuẩn A4</span>
              <span>
                Dung lượng: ~{Math.max(12, Math.round(renderedPdf.pdfBytes.length / 1024))} KB
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 border-t border-white/10 bg-[#0c1424] flex items-center justify-between flex-wrap gap-2">
          <div className="text-[11.5px] text-slate-400">
            Sẵn sàng xuất: <strong className="text-sky-300 font-mono">{reportModel.alertRows.length}</strong> cảnh báo IDS &amp;{' '}
            <strong className="text-emerald-300 font-mono">{reportModel.auditRows.length}</strong> bản ghi Audit Log
          </div>
          <div className="flex items-center gap-2.5">
            <button
              onClick={handleDownloadPdf}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 border border-sky-400 text-white text-[12.5px] font-bold transition-all shadow-md shadow-sky-950/60 cursor-pointer"
            >
              <FileDown className="w-4 h-4" />
              <span>Tải xuống File PDF (.pdf)</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-[12px] font-semibold transition-all cursor-pointer"
            >
              Đóng
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
