import { AlertItem, AuditLogRow, DbUser, FgaEvent, Metrics, TriggerAlert } from '../types/ids';
import {
  maskUsername,
  maskOsUser,
  maskHost,
  maskContextString,
  sanitizeSqlCredentials,
} from './privacy';
import { classifyAlertGroup, computeAttackBreakdown } from './analytics';

export type PdfExportScope = 'full' | 'alerts' | 'audit';
export type PdfReviewFilter = 'ALL' | 'REVIEWED' | 'PENDING';

export interface PdfExportOptions {
  scope: PdfExportScope;
  reviewFilter?: PdfReviewFilter;
  privacyMode: boolean;
  auditorName?: string;
  reportCode?: string;
  organization?: string;
  notes?: string;
  generatedAt?: string;
}

export interface PdfAlertRowModel {
  index: number;
  time: string;
  user: string;
  severity: string;
  group: string;
  riskScore: string;
  status: string;
  attackType: string;
  sqlDetails: string;
  context: string;
}

export interface PdfAuditRowModel {
  index: number;
  timestamp: string;
  dbUser: string;
  policyOrType: string;
  action: string;
  objectName: string;
  returnCode: string;
  status: string;
  context: string;
  sqlText: string;
}

export interface PdfReportModel {
  title: string;
  subtitle: string;
  reportCode: string;
  auditorName: string;
  organization: string;
  generatedAt: string;
  privacyMode: boolean;
  scope: PdfExportScope;
  reviewFilter: PdfReviewFilter;
  notes: string;
  summary: {
    totalAlerts: number;
    criticalAlerts: number;
    highAlerts: number;
    dbmsAlerts: number;
    sdbAlerts: number;
    reviewedAlerts: number;
    totalAuditLogs: number;
    reviewedAuditLogs: number;
    fgaCount: number;
    triggerCount: number;
    maxRisk: number;
    lockedUsers: number;
    readOnlyUsers: number;
  };
  users: {
    username: string;
    riskScore: number;
    responseLabel: string;
    dmlStatus: string;
    accountStatus: string;
  }[];
  alertRows: PdfAlertRowModel[];
  auditRows: PdfAuditRowModel[];
}

/**
 * Pure function that prepares and sanitizes all data for the PDF Security Report.
 * Ensures all passwords and sensitive identifiers are masked according to privacyMode.
 */
export function buildPdfReportModel(
  data: {
    metrics: Metrics;
    users: DbUser[];
    alerts: AlertItem[];
    auditLogs: AuditLogRow[];
    fgaEvents?: FgaEvent[];
    triggers?: TriggerAlert[];
  },
  options: PdfExportOptions
): PdfReportModel {
  const {
    scope,
    reviewFilter = 'ALL',
    privacyMode,
    auditorName = 'Quản trị viên An ninh CSDL (SOC Lead / DBA)',
    reportCode = `SOC-ORA23AI-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`,
    organization = 'Trung tâm Giám sát An toàn CSDL Oracle 23ai (FREEPDB1)',
    notes = 'Hồ sơ trích xuất từ hệ thống phát hiện và ngăn chặn xâm nhập CSDL đa tầng (Defense-in-Depth & Active IPS).',
    generatedAt = new Date().toISOString().replace('T', ' ').substring(0, 19),
  } = options;

  const filteredAlerts = data.alerts.filter((a) => {
    if (reviewFilter === 'REVIEWED') return !!a.reviewed;
    if (reviewFilter === 'PENDING') return !a.reviewed;
    return true;
  });

  const filteredAudit = data.auditLogs.filter((r) => {
    if (reviewFilter === 'REVIEWED') return !!r.reviewed;
    if (reviewFilter === 'PENDING') return !r.reviewed;
    return true;
  });

  const breakdown = computeAttackBreakdown(filteredAlerts);

  const alertRows: PdfAlertRowModel[] =
    scope === 'audit'
      ? []
      : filteredAlerts.map((a, idx) => {
          const group = classifyAlertGroup(a);
          return {
            index: idx + 1,
            time: a.time,
            user: maskUsername(a.user, privacyMode),
            severity: a.severity,
            group: group === 'SDB' ? 'SDB Inference' : 'DBMS Tech',
            riskScore: `${a.risk_score}/100`,
            status: a.reviewed ? 'ĐÃ DUYỆT' : 'CHỜ DUYỆT',
            attackType: a.attack_type,
            sqlDetails: sanitizeSqlCredentials(a.details),
            context: maskContextString(a.context, privacyMode),
          };
        });

  const auditRows: PdfAuditRowModel[] =
    scope === 'alerts'
      ? []
      : filteredAudit.map((r, idx) => {
          const code = Number(r.RETURN_CODE || 0);
          const objFull =
            r.OBJECT_SCHEMA && r.OBJECT_NAME
              ? `${r.OBJECT_SCHEMA}.${r.OBJECT_NAME}`
              : r.OBJECT_NAME || '—';
          const rawHost = maskHost(r.USERHOST, privacyMode);
          const rawOs = maskOsUser(r.OS_USERNAME, privacyMode);
          return {
            index: idx + 1,
            timestamp: r.EVENT_TIMESTAMP,
            dbUser: maskUsername(r.DBUSERNAME, privacyMode),
            policyOrType: r.FGA_POLICY_NAME || r.UNIFIED_AUDIT_POLICIES || r.AUDIT_TYPE || 'Standard',
            action: r.ACTION_NAME,
            objectName: objFull,
            returnCode: code === 0 ? '0 (OK)' : `ORA-${code}`,
            status: r.reviewed ? 'ĐÃ DUYỆT' : 'CHỜ DUYỆT',
            context: `${r.CLIENT_PROGRAM_NAME || 'Client'} (${rawOs}@${rawHost})`,
            sqlText: sanitizeSqlCredentials(r.SQL_TEXT || '—'),
          };
        });

  const title =
    scope === 'alerts'
      ? 'BÁO CÁO CẢNH BÁO XÂM NHẬP CƠ SỞ DỮ LIỆU (IDS ALERTS REPORT)'
      : scope === 'audit'
      ? 'HỒ SƠ NHẬT KÝ KIỂM TOÁN HỢP NHẤT (UNIFIED AUDIT TRAIL REPORT)'
      : 'HỒ SƠ BÁO CÁO AN NINH CƠ SỞ DỮ LIỆU & KIỂM TOÁN TỔNG HỢP (SOC REPORT)';

  const subtitle =
    'Hệ thống Phát hiện & Ngăn chặn Xâm nhập CSDL Đa tầng trên Oracle 23ai (Defense-in-Depth & Active IPS)';

  return {
    title,
    subtitle,
    reportCode,
    auditorName,
    organization,
    generatedAt,
    privacyMode,
    scope,
    reviewFilter,
    notes,
    summary: {
      totalAlerts: filteredAlerts.length,
      criticalAlerts: breakdown.criticalCount,
      highAlerts: breakdown.highCount,
      dbmsAlerts: breakdown.dbmsCount,
      sdbAlerts: breakdown.sdbCount,
      reviewedAlerts: filteredAlerts.filter((a) => a.reviewed).length,
      totalAuditLogs: filteredAudit.length,
      reviewedAuditLogs: filteredAudit.filter((r) => r.reviewed).length,
      fgaCount: data.fgaEvents ? data.fgaEvents.length : data.metrics.fga_count,
      triggerCount: data.triggers ? data.triggers.length : data.metrics.trigger_count,
      maxRisk: data.metrics.max_risk,
      lockedUsers: data.metrics.locked_count,
      readOnlyUsers: data.metrics.readonly_count,
    },
    users: data.users.map((u) => ({
      username: maskUsername(u.USERNAME, privacyMode),
      riskScore: u.RISK_SCORE,
      responseLabel: u.RESPONSE_LABEL,
      dmlStatus: u.DML_STATUS,
      accountStatus: u.ACCOUNT_STATUS,
    })),
    alertRows,
    auditRows,
  };
}

/**
 * Pure helper to wrap long text (such as SQL statements or attack descriptions) into lines of maxChars.
 */
export function wrapTextByChars(text: string, maxChars: number): string[] {
  const clean = (text || '').replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim();
  if (!clean) return ['—'];
  if (clean.length <= maxChars) return [clean];

  const words = clean.split(' ');
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (!current) {
      if (word.length > maxChars) {
        lines.push(word.slice(0, maxChars));
        current = word.slice(maxChars);
      } else {
        current = word;
      }
    } else if (current.length + 1 + word.length <= maxChars) {
      current += ' ' + word;
    } else {
      lines.push(current);
      if (word.length > maxChars) {
        lines.push(word.slice(0, maxChars));
        current = word.slice(maxChars);
      } else {
        current = word;
      }
    }
  }
  if (current) lines.push(current);
  return lines;
}

/**
 * Pure function that packs one or more JPEG byte arrays (representing A4 pages)
 * into a standards-compliant multi-page PDF 1.4 binary (Uint8Array).
 * Zero external dependencies, 100% immune to font encoding bugs for Vietnamese characters.
 */
export function buildPdfBinaryFromJpegPages(
  pages: { jpegBytes: Uint8Array; widthPx: number; heightPx: number }[]
): Uint8Array {
  if (pages.length === 0) {
    throw new Error('At least one page is required to build a PDF document.');
  }

  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let offset = 0;
  const xrefOffsets: number[] = [0]; // index 0 is free object

  const pushBytes = (bytes: Uint8Array) => {
    chunks.push(bytes);
    offset += bytes.length;
  };

  const pushStr = (str: string) => {
    pushBytes(encoder.encode(str));
  };

  // A4 dimensions in PDF points (72 pt/inch): 595.28 x 841.89
  const pageWidthPt = 595.28;
  const pageHeightPt = 841.89;

  // Object 1: Catalog
  // Object 2: Pages
  // For each page i (0..N-1):
  //   pageObjId = 3 + i * 3
  //   contentObjId = 4 + i * 3
  //   imageObjId = 5 + i * 3
  const pageObjIds = pages.map((_, i) => 3 + i * 3);

  // PDF Header (with binary comment)
  pushStr('%PDF-1.4\n%\xFF\xFF\xFF\xFF\n');

  // Obj 1: Catalog
  xrefOffsets[1] = offset;
  pushStr('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');

  // Obj 2: Pages
  xrefOffsets[2] = offset;
  const kidsRef = pageObjIds.map((id) => `${id} 0 R`).join(' ');
  pushStr(`2 0 obj\n<< /Type /Pages /Kids [ ${kidsRef} ] /Count ${pages.length} >>\nendobj\n`);

  // Each Page
  pages.forEach((p, idx) => {
    const pageObjId = 3 + idx * 3;
    const contentObjId = 4 + idx * 3;
    const imageObjId = 5 + idx * 3;
    const imgName = `/Im${idx + 1}`;

    // Content stream draws image stretched to full A4 page
    const contentStream = `q\n${pageWidthPt.toFixed(2)} 0 0 ${pageHeightPt.toFixed(2)} 0 0 cm\n${imgName} Do\nQ\n`;
    const contentBytes = encoder.encode(contentStream);

    // Page Object
    xrefOffsets[pageObjId] = offset;
    pushStr(
      `${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 ${pageWidthPt.toFixed(
        2
      )} ${pageHeightPt.toFixed(
        2
      )} ] /Resources << /XObject << ${imgName} ${imageObjId} 0 R >> >> /Contents ${contentObjId} 0 R >>\nendobj\n`
    );

    // Content Object
    xrefOffsets[contentObjId] = offset;
    pushStr(`${contentObjId} 0 obj\n<< /Length ${contentBytes.length} >>\nstream\n`);
    pushBytes(contentBytes);
    pushStr('\nendstream\nendobj\n');

    // Image XObject (DCTDecode = JPEG)
    xrefOffsets[imageObjId] = offset;
    pushStr(
      `${imageObjId} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${p.widthPx} /Height ${p.heightPx} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${p.jpegBytes.length} >>\nstream\n`
    );
    pushBytes(p.jpegBytes);
    pushStr('\nendstream\nendobj\n');
  });

  // XRef table
  const totalObjects = 2 + pages.length * 3 + 1;
  const startXref = offset;
  pushStr(`xref\n0 ${totalObjects}\n`);
  pushStr('0000000000 65535 f \n');
  for (let objId = 1; objId < totalObjects; objId++) {
    const pos = String(xrefOffsets[objId] || 0).padStart(10, '0');
    pushStr(`${pos} 00000 n \n`);
  }

  // Trailer
  pushStr(
    `trailer\n<< /Size ${totalObjects} /Root 1 0 R >>\nstartxref\n${startXref}\n%%EOF\n`
  );

  // Merge chunks
  const result = new Uint8Array(offset);
  let cursor = 0;
  for (const chunk of chunks) {
    result.set(chunk, cursor);
    cursor += chunk.length;
  }
  return result;
}

/**
 * Helper to convert a data:image/jpeg;base64,... URL to Uint8Array.
 */
function dataUrlToUint8Array(dataUrl: string): Uint8Array {
  const base64 = dataUrl.split(',')[1] || '';
  const binaryStr = atob(base64);
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }
  return bytes;
}

/**
 * Renders the PdfReportModel onto high-DPI A4 HTML5 canvases with full Vietnamese Unicode typography,
 * converts each page to JPEG, and returns both preview Data URLs and the final PDF binary.
 */
export function renderPdfReportPages(model: PdfReportModel): {
  pageDataUrls: string[];
  pdfBytes: Uint8Array;
} {
  const WIDTH = 1240; // A4 @ 150 DPI width
  const HEIGHT = 1754; // A4 @ 150 DPI height
  const MARGIN_X = 64;
  const CONTENT_W = WIDTH - MARGIN_X * 2;

  type DrawCommand = (ctx: CanvasRenderingContext2D) => void;
  const pagesCommands: DrawCommand[][] = [];
  let currentCommands: DrawCommand[] = [];
  let cursorY = 0;

  const startNewPage = (isFirstPage: boolean) => {
    if (currentCommands.length > 0) {
      pagesCommands.push(currentCommands);
    }
    currentCommands = [];

    // Page background & top banner
    currentCommands.push((ctx) => {
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, WIDTH, HEIGHT);

      // Top dark navy header bar
      ctx.fillStyle = '#0c1629';
      ctx.fillRect(0, 0, WIDTH, isFirstPage ? 150 : 92);

      // Accent sky stripe
      ctx.fillStyle = '#0284c7';
      ctx.fillRect(0, isFirstPage ? 150 : 92, WIDTH, 4);

      // Header text
      ctx.fillStyle = '#38bdf8';
      ctx.font = 'bold 16px Inter, system-ui, sans-serif';
      ctx.fillText(
        'ORACLE DB-IDS 23ai · HỆ THỐNG GIÁM SÁT & PHÁT HIỆN XÂM NHẬP CƠ SỞ DỮ LIỆU',
        MARGIN_X,
        38
      );

      // Confidentiality Stamp badge on right
      const stampText = model.privacyMode
        ? 'BẢO MẬT ĐỊNH DANH: BẬT (MASKED)'
        : 'HỒ SƠ KIỂM TOÁN NỘI BỘ';
      ctx.fillStyle = model.privacyMode ? '#065f46' : '#1e293b';
      ctx.fillRect(WIDTH - MARGIN_X - 290, 18, 290, 28);
      ctx.strokeStyle = model.privacyMode ? '#10b981' : '#38bdf8';
      ctx.lineWidth = 1.5;
      ctx.strokeRect(WIDTH - MARGIN_X - 290, 18, 290, 28);
      ctx.fillStyle = '#ecfdf5';
      ctx.font = 'bold 13px "JetBrains Mono", monospace';
      ctx.fillText(stampText, WIDTH - MARGIN_X - 276, 37);

      if (isFirstPage) {
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 24px Inter, system-ui, sans-serif';
        ctx.fillText(model.title, MARGIN_X, 78);

        ctx.fillStyle = '#cbd5e1';
        ctx.font = '15px Inter, system-ui, sans-serif';
        ctx.fillText(model.subtitle, MARGIN_X, 106);

        ctx.fillStyle = '#94a3b8';
        ctx.font = '13px "JetBrains Mono", monospace';
        ctx.fillText(
          `Mã hồ sơ: ${model.reportCode}   |   Thời gian xuất: ${model.generatedAt}   |   Người lập: ${model.auditorName}`,
          MARGIN_X,
          134
        );
      } else {
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 18px Inter, system-ui, sans-serif';
        ctx.fillText(`${model.title} (Tiếp theo)`, MARGIN_X, 68);
        ctx.fillStyle = '#94a3b8';
        ctx.font = '13px "JetBrains Mono", monospace';
        ctx.fillText(`Mã hồ sơ: ${model.reportCode}`, WIDTH - MARGIN_X - 290, 68);
      }
    });

    cursorY = isFirstPage ? 182 : 124;
  };

  const ensureSpace = (neededHeight: number) => {
    if (cursorY + neededHeight > HEIGHT - 110) {
      startNewPage(false);
    }
  };

  // Start Page 1
  startNewPage(true);

  // 1. Metadata & Executive KPI Summary Box on Page 1
  const metaY = cursorY;
  currentCommands.push((ctx) => {
    ctx.fillStyle = '#f8fafc';
    ctx.fillRect(MARGIN_X, metaY, CONTENT_W, 132);
    ctx.strokeStyle = '#cbd5e1';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(MARGIN_X, metaY, CONTENT_W, 132);

    ctx.fillStyle = '#0f172a';
    ctx.font = 'bold 16px Inter, system-ui, sans-serif';
    ctx.fillText('I. TÓM TẮT CHỈ SỐ AN NINH & TRẠNG THÁI KIỂM DUYỆT (EXECUTIVE SUMMARY)', MARGIN_X + 20, metaY + 28);

    // 4 KPI blocks inside the summary box
    const boxW = (CONTENT_W - 60) / 4;
    const kpis = [
      {
        label: 'Tổng Cảnh báo IDS',
        val: `${model.summary.totalAlerts} cảnh báo`,
        sub: `CRITICAL: ${model.summary.criticalAlerts} | HIGH: ${model.summary.highAlerts}`,
        color: '#dc2626',
      },
      {
        label: 'Phân nhóm Kỹ thuật',
        val: `DBMS: ${model.summary.dbmsAlerts} | SDB: ${model.summary.sdbAlerts}`,
        sub: `Bẫy FGA: ${model.summary.fgaCount} | Trigger: ${model.summary.triggerCount}`,
        color: '#d97706',
      },
      {
        label: 'Nhật ký Kiểm toán',
        val: `${model.summary.totalAuditLogs} bản ghi`,
        sub: `Đã duyệt: ${model.summary.reviewedAuditLogs}/${model.summary.totalAuditLogs}`,
        color: '#0284c7',
      },
      {
        label: 'Định mức Rủi ro & IPS',
        val: `Max Risk: ${model.summary.maxRisk}/100`,
        sub: `Khóa L3: ${model.summary.lockedUsers} | Read-Only L2: ${model.summary.readOnlyUsers}`,
        color: '#7c3aed',
      },
    ];

    kpis.forEach((k, idx) => {
      const bx = MARGIN_X + 20 + idx * (boxW + 6);
      const by = metaY + 42;
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(bx, by, boxW, 74);
      ctx.strokeStyle = '#e2e8f0';
      ctx.strokeRect(bx, by, boxW, 74);

      ctx.fillStyle = k.color;
      ctx.fillRect(bx, by, 5, 74);

      ctx.fillStyle = '#475569';
      ctx.font = 'bold 12px Inter, system-ui, sans-serif';
      ctx.fillText(k.label, bx + 14, by + 20);

      ctx.fillStyle = '#0f172a';
      ctx.font = 'bold 17px "JetBrains Mono", monospace';
      ctx.fillText(k.val, bx + 14, by + 44);

      ctx.fillStyle = '#64748b';
      ctx.font = '12px Inter, system-ui, sans-serif';
      ctx.fillText(k.sub, bx + 14, by + 64);
    });
  });
  cursorY += 150;

  // Notes bar
  if (model.notes) {
    const noteY = cursorY;
    currentCommands.push((ctx) => {
      ctx.fillStyle = '#f1f5f9';
      ctx.fillRect(MARGIN_X, noteY, CONTENT_W, 38);
      ctx.fillStyle = '#334155';
      ctx.font = 'italic 13px Inter, system-ui, sans-serif';
      ctx.fillText(`Ghi chú hồ sơ: ${model.notes.slice(0, 125)}`, MARGIN_X + 14, noteY + 24);
    });
    cursorY += 52;
  }

  // 2. User Posture Table (if scope === 'full')
  if (model.scope === 'full' && model.users.length > 0) {
    ensureSpace(190);
    const secY = cursorY;
    currentCommands.push((ctx) => {
      ctx.fillStyle = '#0f172a';
      ctx.font = 'bold 17px Inter, system-ui, sans-serif';
      ctx.fillText(
        'II. TRẠNG THÁI RỦI RO & CÁCH LY TÀI KHOẢN CSDL (DATABASE USER POSTURE)',
        MARGIN_X,
        secY + 20
      );

      // Table Header
      const thY = secY + 32;
      ctx.fillStyle = '#1e293b';
      ctx.fillRect(MARGIN_X, thY, CONTENT_W, 32);
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 13px Inter, system-ui, sans-serif';
      ctx.fillText('Tài khoản CSDL', MARGIN_X + 16, thY + 21);
      ctx.fillText('Mật khẩu (SYS.USER$)', MARGIN_X + 180, thY + 21);
      ctx.fillText('Điểm Rủi ro', MARGIN_X + 380, thY + 21);
      ctx.fillText('Cấp độ Phản ứng IPS', MARGIN_X + 520, thY + 21);
      ctx.fillText('Chế độ Quyền DML', MARGIN_X + 830, thY + 21);
      ctx.fillText('Trạng thái', MARGIN_X + 995, thY + 21);
    });
    cursorY += 64;

    model.users.forEach((u, idx) => {
      const rowY = cursorY;
      currentCommands.push((ctx) => {
        ctx.fillStyle = idx % 2 === 0 ? '#ffffff' : '#f8fafc';
        ctx.fillRect(MARGIN_X, rowY, CONTENT_W, 32);
        ctx.strokeStyle = '#e2e8f0';
        ctx.strokeRect(MARGIN_X, rowY, CONTENT_W, 32);

        ctx.fillStyle = '#0284c7';
        ctx.font = 'bold 13px "JetBrains Mono", monospace';
        ctx.fillText(u.username, MARGIN_X + 16, rowY + 21);

        ctx.fillStyle = '#64748b';
        ctx.font = '12px "JetBrains Mono", monospace';
        ctx.fillText('•••••••• (SHA-512)', MARGIN_X + 180, rowY + 21);

        ctx.fillStyle = u.riskScore >= 80 ? '#dc2626' : u.riskScore >= 50 ? '#d97706' : '#059669';
        ctx.font = 'bold 13px "JetBrains Mono", monospace';
        ctx.fillText(`${u.riskScore} / 100`, MARGIN_X + 380, rowY + 21);

        ctx.fillStyle = '#1e293b';
        ctx.font = '13px Inter, system-ui, sans-serif';
        ctx.fillText(u.responseLabel, MARGIN_X + 520, rowY + 21);

        ctx.fillStyle = u.dmlStatus === 'READ-ONLY' ? '#d97706' : '#059669';
        ctx.font = 'bold 12px "JetBrains Mono", monospace';
        ctx.fillText(u.dmlStatus, MARGIN_X + 830, rowY + 21);

        ctx.fillStyle = u.accountStatus.includes('LOCK') ? '#dc2626' : '#059669';
        ctx.font = 'bold 12px "JetBrains Mono", monospace';
        ctx.fillText(u.accountStatus, MARGIN_X + 995, rowY + 21);
      });
      cursorY += 32;
    });
    cursorY += 24;
  }

  // 3. Alerts Section (if scope === 'full' or 'alerts')
  if (model.scope === 'full' || model.scope === 'alerts') {
    ensureSpace(120);
    const secTitleY = cursorY;
    const sectionPrefix = model.scope === 'full' ? 'III.' : 'II.';
    currentCommands.push((ctx) => {
      ctx.fillStyle = '#0f172a';
      ctx.font = 'bold 17px Inter, system-ui, sans-serif';
      ctx.fillText(
        `${sectionPrefix} DANH SÁCH CẢNH BÁO XÂM NHẬP ĐA CHIỀU (${model.alertRows.length} BẢN GHI)`,
        MARGIN_X,
        secTitleY + 20
      );

      const thY = secTitleY + 32;
      ctx.fillStyle = '#7f1d1d';
      ctx.fillRect(MARGIN_X, thY, CONTENT_W, 34);
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 12.5px Inter, system-ui, sans-serif';
      ctx.fillText('#', MARGIN_X + 12, thY + 22);
      ctx.fillText('Thời gian / User', MARGIN_X + 46, thY + 22);
      ctx.fillText('Mức độ / Nhóm', MARGIN_X + 220, thY + 22);
      ctx.fillText('Loại Tấn công & Câu lệnh SQL Vi phạm', MARGIN_X + 385, thY + 22);
      ctx.fillText('Trạng thái', MARGIN_X + 995, thY + 22);
    });
    cursorY += 66;

    if (model.alertRows.length === 0) {
      const emptyY = cursorY;
      currentCommands.push((ctx) => {
        ctx.fillStyle = '#f8fafc';
        ctx.fillRect(MARGIN_X, emptyY, CONTENT_W, 44);
        ctx.strokeStyle = '#cbd5e1';
        ctx.strokeRect(MARGIN_X, emptyY, CONTENT_W, 44);
        ctx.fillStyle = '#475569';
        ctx.font = '14px Inter, system-ui, sans-serif';
        ctx.fillText('Không có cảnh báo xâm nhập nào trong phạm vi bộ lọc hiện tại.', MARGIN_X + 20, emptyY + 27);
      });
      cursorY += 56;
    } else {
      model.alertRows.forEach((row, idx) => {
        const sqlLines = wrapTextByChars(row.sqlDetails, 74).slice(0, 2);
        const rowH = Math.max(58, 38 + sqlLines.length * 18);
        ensureSpace(rowH + 10);
        const rY = cursorY;

        currentCommands.push((ctx) => {
          ctx.fillStyle = idx % 2 === 0 ? '#ffffff' : '#f8fafc';
          ctx.fillRect(MARGIN_X, rY, CONTENT_W, rowH);
          ctx.strokeStyle = '#cbd5e1';
          ctx.lineWidth = 1;
          ctx.strokeRect(MARGIN_X, rY, CONTENT_W, rowH);

          // Index
          ctx.fillStyle = '#475569';
          ctx.font = 'bold 12px "JetBrains Mono", monospace';
          ctx.fillText(String(row.index), MARGIN_X + 12, rY + 24);

          // Time & User
          ctx.fillStyle = '#0f172a';
          ctx.font = 'bold 13px "JetBrains Mono", monospace';
          ctx.fillText(`User: ${row.user}`, MARGIN_X + 46, rY + 22);
          ctx.fillStyle = '#475569';
          ctx.font = '11.5px "JetBrains Mono", monospace';
          ctx.fillText(row.time, MARGIN_X + 46, rY + 42);

          // Severity & Group
          ctx.fillStyle =
            row.severity === 'CRITICAL'
              ? '#dc2626'
              : row.severity === 'HIGH'
              ? '#d97706'
              : '#0284c7';
          ctx.font = 'bold 12.5px "JetBrains Mono", monospace';
          ctx.fillText(`${row.severity} (${row.riskScore})`, MARGIN_X + 220, rY + 22);
          ctx.fillStyle = '#334155';
          ctx.font = '12px Inter, system-ui, sans-serif';
          ctx.fillText(row.group, MARGIN_X + 220, rY + 42);

          // Attack Type & Wrapped SQL
          ctx.fillStyle = '#0f172a';
          ctx.font = 'bold 13px Inter, system-ui, sans-serif';
          ctx.fillText(row.attackType.slice(0, 76), MARGIN_X + 385, rY + 22);

          ctx.fillStyle = '#0369a1';
          ctx.font = '12px "JetBrains Mono", monospace';
          sqlLines.forEach((line, lIdx) => {
            ctx.fillText(line, MARGIN_X + 385, rY + 41 + lIdx * 17);
          });

          // Review status
          ctx.fillStyle = row.status === 'ĐÃ DUYỆT' ? '#059669' : '#d97706';
          ctx.font = 'bold 12px "JetBrains Mono", monospace';
          ctx.fillText(row.status, MARGIN_X + 995, rY + 28);
        });

        cursorY += rowH;
      });
      cursorY += 24;
    }
  }

  // 4. Audit Logs Section (if scope === 'full' or 'audit')
  if (model.scope === 'full' || model.scope === 'audit') {
    ensureSpace(120);
    const secTitleY = cursorY;
    const sectionPrefix = model.scope === 'full' ? 'IV.' : 'II.';
    currentCommands.push((ctx) => {
      ctx.fillStyle = '#0f172a';
      ctx.font = 'bold 17px Inter, system-ui, sans-serif';
      ctx.fillText(
        `${sectionPrefix} NHẬT KÝ KIỂM TOÁN HỢP NHẤT - UNIFIED_AUDIT_TRAIL (${model.auditRows.length} BẢN GHI)`,
        MARGIN_X,
        secTitleY + 20
      );

      const thY = secTitleY + 32;
      ctx.fillStyle = '#0c4a6e';
      ctx.fillRect(MARGIN_X, thY, CONTENT_W, 34);
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 12.5px Inter, system-ui, sans-serif';
      ctx.fillText('#', MARGIN_X + 12, thY + 22);
      ctx.fillText('Thời gian / DB User', MARGIN_X + 46, thY + 22);
      ctx.fillText('Policy / Action / Mã ORA', MARGIN_X + 225, thY + 22);
      ctx.fillText('Ngữ cảnh & Câu lệnh SQL (SQL_TEXT)', MARGIN_X + 445, thY + 22);
      ctx.fillText('Trạng thái', MARGIN_X + 995, thY + 22);
    });
    cursorY += 66;

    if (model.auditRows.length === 0) {
      const emptyY = cursorY;
      currentCommands.push((ctx) => {
        ctx.fillStyle = '#f8fafc';
        ctx.fillRect(MARGIN_X, emptyY, CONTENT_W, 44);
        ctx.strokeStyle = '#cbd5e1';
        ctx.strokeRect(MARGIN_X, emptyY, CONTENT_W, 44);
        ctx.fillStyle = '#475569';
        ctx.font = '14px Inter, system-ui, sans-serif';
        ctx.fillText('Không có bản ghi kiểm toán nào trong phạm vi bộ lọc hiện tại.', MARGIN_X + 20, emptyY + 27);
      });
      cursorY += 56;
    } else {
      model.auditRows.forEach((row, idx) => {
        const sqlLines = wrapTextByChars(row.sqlText, 66).slice(0, 2);
        const rowH = Math.max(58, 38 + sqlLines.length * 18);
        ensureSpace(rowH + 10);
        const rY = cursorY;

        currentCommands.push((ctx) => {
          ctx.fillStyle = idx % 2 === 0 ? '#ffffff' : '#f8fafc';
          ctx.fillRect(MARGIN_X, rY, CONTENT_W, rowH);
          ctx.strokeStyle = '#cbd5e1';
          ctx.lineWidth = 1;
          ctx.strokeRect(MARGIN_X, rY, CONTENT_W, rowH);

          // Index
          ctx.fillStyle = '#475569';
          ctx.font = 'bold 12px "JetBrains Mono", monospace';
          ctx.fillText(String(row.index), MARGIN_X + 12, rY + 24);

          // Timestamp & User
          ctx.fillStyle = '#0f172a';
          ctx.font = 'bold 13px "JetBrains Mono", monospace';
          ctx.fillText(`User: ${row.dbUser}`, MARGIN_X + 46, rY + 22);
          ctx.fillStyle = '#475569';
          ctx.font = '11.5px "JetBrains Mono", monospace';
          ctx.fillText(row.timestamp, MARGIN_X + 46, rY + 42);

          // Policy / Action / Return code
          ctx.fillStyle = '#1e293b';
          ctx.font = 'bold 12px "JetBrains Mono", monospace';
          ctx.fillText(`${row.action} (${row.objectName})`, MARGIN_X + 225, rY + 22);
          ctx.fillStyle = row.returnCode.startsWith('0') ? '#059669' : '#dc2626';
          ctx.font = 'bold 11.5px "JetBrains Mono", monospace';
          ctx.fillText(`${row.policyOrType.slice(0, 18)} · ${row.returnCode}`, MARGIN_X + 225, rY + 42);

          // Context & SQL_TEXT
          ctx.fillStyle = '#475569';
          ctx.font = '12px Inter, system-ui, sans-serif';
          ctx.fillText(`Ngữ cảnh: ${row.context}`, MARGIN_X + 445, rY + 22);

          ctx.fillStyle = '#0369a1';
          ctx.font = '12px "JetBrains Mono", monospace';
          sqlLines.forEach((line, lIdx) => {
            ctx.fillText(line, MARGIN_X + 445, rY + 41 + lIdx * 17);
          });

          // Review status
          ctx.fillStyle = row.status === 'ĐÃ DUYỆT' ? '#059669' : '#64748b';
          ctx.font = 'bold 12px "JetBrains Mono", monospace';
          ctx.fillText(row.status, MARGIN_X + 995, rY + 28);
        });

        cursorY += rowH;
      });
      cursorY += 24;
    }
  }

  // 5. Signature & Archival Certification Block at the end of the report
  ensureSpace(150);
  const sigY = cursorY + 10;
  currentCommands.push((ctx) => {
    ctx.fillStyle = '#f8fafc';
    ctx.fillRect(MARGIN_X, sigY, CONTENT_W, 118);
    ctx.strokeStyle = '#94a3b8';
    ctx.setLineDash([5, 4]);
    ctx.strokeRect(MARGIN_X, sigY, CONTENT_W, 118);
    ctx.setLineDash([]);

    ctx.fillStyle = '#0f172a';
    ctx.font = 'bold 14px Inter, system-ui, sans-serif';
    ctx.fillText('XÁC NHẬN KIỂM DUYỆT & LƯU TRỮ HỒ SƠ AN TOÀN CƠ SỞ DỮ LIỆU', MARGIN_X + 24, sigY + 28);

    ctx.fillStyle = '#475569';
    ctx.font = '13px Inter, system-ui, sans-serif';
    ctx.fillText(
      `• Đơn vị quản lý: ${model.organization}`,
      MARGIN_X + 24,
      sigY + 54
    );
    ctx.fillText(
      `• Chế độ bảo mật thông tin nhạy cảm: ${
        model.privacyMode
          ? 'ĐÃ BẬT (Đã che định danh User, Máy trạm, CMND & Mật khẩu)'
          : 'Tiêu chuẩn (Mật khẩu luôn được ẩn SHA-512)'
      }`,
      MARGIN_X + 24,
      sigY + 78
    );
    ctx.fillText(
      `• Cam kết toàn vẹn: Trích xuất tự động từ UNIFIED_AUDIT_TRAIL, DBMS_FGA và SYS.IDS_TRIGGER_ALERTS.`,
      MARGIN_X + 24,
      sigY + 102
    );

    // Right side signature stamp
    ctx.fillStyle = '#0284c7';
    ctx.font = 'bold 13px "JetBrains Mono", monospace';
    ctx.fillText('CHỮ KÝ KIỂM TOÁN VIÊN SOC', WIDTH - MARGIN_X - 260, sigY + 32);
    ctx.fillStyle = '#0f172a';
    ctx.font = 'bold 14px Inter, system-ui, sans-serif';
    ctx.fillText(model.auditorName, WIDTH - MARGIN_X - 260, sigY + 66);
    ctx.fillStyle = '#059669';
    ctx.font = 'bold 12px "JetBrains Mono", monospace';
    ctx.fillText(`[VERIFIED · ${model.generatedAt}]`, WIDTH - MARGIN_X - 260, sigY + 94);
  });

  if (currentCommands.length > 0) {
    pagesCommands.push(currentCommands);
  }

  // Render each page onto an offscreen canvas and collect JPEG bytes
  const totalPages = pagesCommands.length;
  const pageDataUrls: string[] = [];
  const jpegPages: { jpegBytes: Uint8Array; widthPx: number; heightPx: number }[] = [];

  pagesCommands.forEach((cmds, pageIdx) => {
    const canvas = document.createElement('canvas');
    canvas.width = WIDTH;
    canvas.height = HEIGHT;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    cmds.forEach((fn) => fn(ctx));

    // Draw Page Footer
    ctx.fillStyle = '#0c1629';
    ctx.fillRect(0, HEIGHT - 54, WIDTH, 54);
    ctx.fillStyle = '#94a3b8';
    ctx.font = '12px "JetBrains Mono", monospace';
    ctx.fillText(
      `Hồ sơ Bảo mật CSDL Oracle 23ai · Mã lưu trữ: ${model.reportCode} · Mật khẩu & khóa TDE được bảo vệ nghiêm ngặt`,
      MARGIN_X,
      HEIGHT - 22
    );
    ctx.fillStyle = '#38bdf8';
    ctx.font = 'bold 13px "JetBrains Mono", monospace';
    ctx.fillText(
      `Trang ${pageIdx + 1} / ${totalPages}`,
      WIDTH - MARGIN_X - 110,
      HEIGHT - 22
    );

    const dataUrl = canvas.toDataURL('image/jpeg', 0.92);
    pageDataUrls.push(dataUrl);
    jpegPages.push({
      jpegBytes: dataUrlToUint8Array(dataUrl),
      widthPx: WIDTH,
      heightPx: HEIGHT,
    });
  });

  const pdfBytes = buildPdfBinaryFromJpegPages(jpegPages);
  return { pageDataUrls, pdfBytes };
}

/**
 * Triggers a direct browser download of the generated PDF file without opening popups.
 */
export function triggerPdfDownload(pdfBytes: Uint8Array, filename: string): void {
  const blob = new Blob([pdfBytes as unknown as BlobPart], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename.endsWith('.pdf') ? filename : `${filename}.pdf`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}
