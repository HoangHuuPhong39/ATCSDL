import React, { useState, useRef, useEffect } from 'react';
import {
  Activity,
  RefreshCw,
  Database,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  SlidersHorizontal,
  Maximize2,
  Minimize2,
  LayoutGrid,
  EyeOff,
  Eye,
  FileDown,
} from 'lucide-react';
import { ActiveTab } from '../types/ids';

export type LayoutWidthMode = 'fluid' | 'boxed' | 'compact';
export type UiDensityMode = 'comfortable' | 'compact';

interface HeaderProps {
  activeTab: ActiveTab;
  onRefresh: () => void;
  isRefreshing: boolean;
  onOpenOracleBridge: () => void;
  onOpenPdfExport: () => void;
  isBridgeConnected: boolean;
  privacyMode: boolean;
  onTogglePrivacyMode: () => void;
  isSidebarCollapsed: boolean;
  onToggleSidebarCollapse: () => void;
  onOpenMobileMenu: () => void;
  layoutWidth: LayoutWidthMode;
  onChangeLayoutWidth: (mode: LayoutWidthMode) => void;
  uiDensity: UiDensityMode;
  onChangeUiDensity: (density: UiDensityMode) => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onRefresh,
  isRefreshing,
  onOpenOracleBridge,
  onOpenPdfExport,
  isBridgeConnected,
  privacyMode,
  onTogglePrivacyMode,
  isSidebarCollapsed,
  onToggleSidebarCollapse,
  onOpenMobileMenu,
  layoutWidth,
  onChangeLayoutWidth,
  uiDensity,
  onChangeUiDensity,
}) => {
  const [customizerOpen, setCustomizerOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setCustomizerOpen(false);
      }
    };
    if (customizerOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [customizerOpen]);

  const getTitles = (): { title: string; subtitle: string } => {
    switch (activeTab) {
      case 'home':
        return {
          title: 'Trung tâm Điều hành An ninh CSDL (Oracle DB-IDS SOC)',
          subtitle: 'Giám sát trực tiếp từ Oracle 23ai (FREEPDB1) · Biểu đồ Nhiệt & Phân tích Đa chiều',
        };
      case 'alerts':
        return {
          title: 'Danh sách Cảnh báo Xâm nhập & Chấm điểm Rủi ro (IDS Alerts)',
          subtitle: 'Phân loại 6 kỹ thuật tấn công DBMS & 4 kiểu suy diễn thống kê SDB theo mức độ',
        };
      case 'fga':
        return {
          title: 'Kiểm toán Mịn (DBMS_FGA) & Bẫy Dữ liệu Honeytoken',
          subtitle: 'Policies: FGA_HONEYTOKEN_TRAP (manv="NV_TRAP") & FGA_HIGH_SALARY_ACCESS (lương >= 1000)',
        };
      case 'triggers':
        return {
          title: 'Hành vi bị chặn tức thời bởi Database Trigger (Autonomous Transaction)',
          subtitle: 'SYS.TRG_PROTECT_NV · Ngăn chặn xóa nhân viên (ORA-20001) & Chặn tăng lương > 50% (ORA-20002)',
        };
      case 'audit':
        return {
          title: 'Nhật ký Kiểm toán Hợp nhất Thời gian thực (UNIFIED_AUDIT_TRAIL)',
          subtitle: 'Truy vết toàn diện câu lệnh SQL, Return Code, OS User, Host và Client Application',
        };
      case 'users':
        return {
          title: 'Hồ sơ Tài khoản CSDL & Dữ liệu Bảng Nhạy cảm (SYS.NV)',
          subtitle: 'Quản lý dữ liệu gốc SYS.NV, bản ghi bẫy Honeytoken (NV_TRAP) và hồ sơ phiên chuẩn',
        };
      case 'ips':
        return {
          title: 'Phản ứng Đa cấp Tự động & Điều khiển Cách ly (Active IPS)',
          subtitle: 'Cấu hình Auto-Response, Ma trận Phòng thủ L0–L3 và Bảng Điều khiển Khóa / Hạ quyền Read-Only',
        };
      case 'docs':
        return {
          title: 'Báo cáo Đề tài & Tài liệu Kiến trúc Chuyên sâu',
          subtitle: 'Hệ thống phân loại tấn công, Mô hình toán học SDB Inference, Kiến trúc 5 tầng & Mã nguồn PL/SQL',
        };
      default:
        return {
          title: 'Hệ thống Phát hiện Xâm nhập CSDL Oracle',
          subtitle: 'Defense-in-Depth & Active IPS',
        };
    }
  };

  const { title, subtitle } = getTitles();

  return (
    <header className="h-16 bg-[#0e1626]/95 border-b border-[#38bdf8]/15 px-3 sm:px-5 flex items-center justify-between gap-2.5 sticky top-0 z-30 backdrop-blur-md">
      {/* Left Zone: Sidebar toggles + Contextual Page Title */}
      <div className="flex items-center gap-2.5 min-w-0">
        {/* Mobile Hamburger Button */}
        <button
          onClick={onOpenMobileMenu}
          aria-label="Mở menu điều hướng"
          className="lg:hidden p-2 rounded-lg bg-[#131e33] border border-sky-500/20 text-slate-200 hover:text-white hover:border-sky-400 transition-colors cursor-pointer shrink-0"
        >
          <Menu className="w-4 h-4" />
        </button>

        {/* Desktop Sidebar Collapse/Expand Toggle */}
        <button
          onClick={onToggleSidebarCollapse}
          aria-label={isSidebarCollapsed ? 'Mở rộng thanh bên' : 'Thu gọn thanh bên'}
          title={isSidebarCollapsed ? 'Mở rộng thanh bên (Sidebar)' : 'Thu gọn thanh bên (Sidebar)'}
          className="hidden lg:flex p-2 rounded-lg bg-[#131e33] border border-sky-500/20 text-slate-300 hover:text-white hover:border-sky-400 transition-colors cursor-pointer shrink-0"
        >
          {isSidebarCollapsed ? (
            <PanelLeftOpen className="w-4 h-4 text-sky-400" />
          ) : (
            <PanelLeftClose className="w-4 h-4 text-sky-400" />
          )}
        </button>

        <div className="hidden sm:flex w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-400/20 items-center justify-center text-sky-400 shrink-0">
          <Activity className="w-4 h-4" />
        </div>

        <div className="min-w-0">
          <h1 className="text-[13px] sm:text-[14px] font-bold text-slate-100 tracking-tight truncate">
            {title}
          </h1>
          <p className="text-[11px] text-slate-400 truncate mt-0.5 hidden md:block">{subtitle}</p>
        </div>
      </div>

      {/* Right Zone: Confidentiality Mask Toggle + Oracle Live Bridge + Customizer + Flush Audit */}
      <div className="flex items-center gap-2 shrink-0">
        {/* Privacy / Credential Mask Toggle */}
        <button
          onClick={onTogglePrivacyMode}
          aria-label={privacyMode ? 'Đang ẩn thông tin nhạy cảm' : 'Đang hiện tên tài khoản'}
          title={
            privacyMode
              ? 'Đang BẬT chế độ bảo mật: Ẩn Username, Host, CMND & Mật khẩu (Nhấn để hiện định danh)'
              : 'Đang hiển thị Username & Host phục vụ kiểm tra (Mật khẩu luôn được mã hóa ẩn)'
          }
          className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap shrink-0 ${
            privacyMode
              ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/25'
              : 'bg-[#131e33] border-amber-500/35 text-amber-300 hover:bg-amber-500/15'
          }`}
        >
          {privacyMode ? (
            <>
              <EyeOff className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Bảo mật định danh: ON</span>
            </>
          ) : (
            <>
              <Eye className="w-3.5 h-3.5 text-amber-400" />
              <span className="hidden sm:inline">Bảo mật định danh: OFF</span>
            </>
          )}
        </button>

        {/* Live Oracle SQL Developer Sync Button */}
        <button
          onClick={onOpenOracleBridge}
          title="Kết nối & nhận cảnh báo trực tiếp khi thực thi câu lệnh trên Oracle SQL Developer"
          className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-[#131e33] border border-sky-500/35 text-sky-300 hover:bg-sky-500/20 hover:text-white text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap shrink-0"
        >
          <span
            className={`w-2 h-2 rounded-full ${
              isBridgeConnected ? 'bg-emerald-400 animate-pulse' : 'bg-sky-400'
            }`}
          />
          <Database className="w-3.5 h-3.5 text-sky-400 hidden sm:inline" />
          <span>Oracle Live Sync</span>
        </button>

        {/* Export PDF Security Report Button */}
        <button
          onClick={onOpenPdfExport}
          title="Xuất dữ liệu Cảnh báo IDS và Nhật ký Kiểm toán (Audit Logs) sang định dạng PDF"
          className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg bg-purple-500/15 border border-purple-500/40 text-purple-200 hover:bg-purple-500/25 hover:text-white text-[11.5px] font-semibold transition-all cursor-pointer whitespace-nowrap shrink-0"
        >
          <FileDown className="w-3.5 h-3.5 text-purple-300" />
          <span>Xuất PDF</span>
        </button>

        {/* Screen & Layout Customizer Popover */}
        <div className="relative" ref={popoverRef}>
          <button
            onClick={() => setCustomizerOpen((prev) => !prev)}
            aria-label="Tùy chỉnh giao diện"
            title="Tùy chỉnh kích thước khung nhìn & mật độ hiển thị"
            className={`inline-flex items-center gap-1.5 p-2 sm:px-2.5 sm:py-1.5 rounded-lg border text-[12px] font-semibold transition-all cursor-pointer whitespace-nowrap shrink-0 ${
              customizerOpen
                ? 'bg-sky-500/20 border-sky-400 text-sky-300'
                : 'bg-[#131e33] border-sky-500/20 text-slate-300 hover:text-white hover:border-sky-400/50'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-sky-400" />
            <span className="hidden xl:inline">Giao diện</span>
          </button>

          {customizerOpen && (
            <div className="absolute right-0 mt-2 w-72 bg-[#0e1626] border border-sky-500/30 rounded-xl shadow-2xl shadow-black/80 p-4 z-50 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-2.5">
                <div className="flex items-center gap-2 text-[12.5px] font-bold text-slate-100">
                  <LayoutGrid className="w-4 h-4 text-sky-400" />
                  <span>Tùy chỉnh Khung nhìn &amp; Bố cục</span>
                </div>
              </div>

              {/* Option 1: Sidebar state */}
              <div className="space-y-1.5 hidden lg:block">
                <label className="text-[11px] font-semibold text-slate-400 block">
                  Thanh điều hướng bên (Sidebar)
                </label>
                <div className="grid grid-cols-2 gap-1.5 p-1 bg-[#090e17] rounded-lg border border-white/5">
                  <button
                    onClick={() => isSidebarCollapsed && onToggleSidebarCollapse()}
                    className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-colors cursor-pointer ${
                      !isSidebarCollapsed
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Mở rộng (256px)
                  </button>
                  <button
                    onClick={() => !isSidebarCollapsed && onToggleSidebarCollapse()}
                    className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-colors cursor-pointer ${
                      isSidebarCollapsed
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Thu gọn (74px)
                  </button>
                </div>
              </div>

              {/* Option 2: Viewport Container Width */}
              <div className="space-y-1.5">
                <label className="text-[11px] font-semibold text-slate-400 block">
                  Độ rộng Khung nội dung theo màn hình
                </label>
                <div className="grid grid-cols-3 gap-1 p-1 bg-[#090e17] rounded-lg border border-white/5">
                  <button
                    onClick={() => onChangeLayoutWidth('fluid')}
                    className={`px-2 py-1.5 rounded-md text-[11px] font-semibold transition-colors cursor-pointer flex items-center justify-center gap-1 ${
                      layoutWidth === 'fluid'
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Maximize2 className="w-3 h-3" />
                    <span>Toàn bộ</span>
                  </button>
                  <button
                    onClick={() => onChangeLayoutWidth('boxed')}
                    className={`px-2 py-1.5 rounded-md text-[11px] font-semibold transition-colors cursor-pointer ${
                      layoutWidth === 'boxed'
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Chuẩn 1600
                  </button>
                  <button
                    onClick={() => onChangeLayoutWidth('compact')}
                    className={`px-2 py-1.5 rounded-md text-[11px] font-semibold transition-colors cursor-pointer flex items-center justify-center gap-1 ${
                      layoutWidth === 'compact'
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Minimize2 className="w-3 h-3" />
                    <span>Gọn 1280</span>
                  </button>
                </div>
              </div>

              {/* Option 3: UI Density */}
              <div className="space-y-1.5">
                <label className="text-[11px] font-semibold text-slate-400 block">
                  Mật độ Bảng dữ liệu (Table Density)
                </label>
                <div className="grid grid-cols-2 gap-1.5 p-1 bg-[#090e17] rounded-lg border border-white/5">
                  <button
                    onClick={() => onChangeUiDensity('comfortable')}
                    className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-colors cursor-pointer ${
                      uiDensity === 'comfortable'
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Thoáng (Chuẩn)
                  </button>
                  <button
                    onClick={() => onChangeUiDensity('compact')}
                    className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-colors cursor-pointer ${
                      uiDensity === 'compact'
                        ? 'bg-sky-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Thu gọn (Dense)
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Flush Audit button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="inline-flex items-center gap-1.5 px-2.5 sm:px-3.5 py-1.5 rounded-lg bg-sky-600 border border-sky-400 hover:bg-sky-500 text-white text-[12px] font-semibold transition-all shadow-sm shadow-sky-900/50 cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'spin-active' : ''}`} />
          <span className="hidden sm:inline">Đồng bộ Oracle</span>
        </button>
      </div>
    </header>
  );
};
