import React, { useState, useRef, useEffect } from 'react';
import {
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  SlidersHorizontal,
  Maximize2,
  Minimize2,
  EyeOff,
  Eye,
  FileDown,
  Sun,
  Moon,
  MoreHorizontal,
  Database,
  RefreshCw,
} from 'lucide-react';
import { ActiveTab } from '../types/ids';
import { StatusDot } from './ui/StatusDot';

export type LayoutWidthMode = 'fluid' | 'boxed' | 'compact';
export type UiDensityMode = 'comfortable' | 'compact';
export type ThemeMode = 'dark' | 'light';

interface HeaderProps {
  activeTab: ActiveTab;
  onRefresh: () => void;
  isRefreshing: boolean;
  onOpenOracleBridge: () => void;
  onOpenPdfExport: () => void;
  isBridgeConnected: boolean;
  lastSyncTime?: string | null;
  privacyMode: boolean;
  onTogglePrivacyMode: () => void;
  isSidebarCollapsed: boolean;
  onToggleSidebarCollapse: () => void;
  onOpenMobileMenu: () => void;
  layoutWidth: LayoutWidthMode;
  onChangeLayoutWidth: (mode: LayoutWidthMode) => void;
  uiDensity: UiDensityMode;
  onChangeUiDensity: (density: UiDensityMode) => void;
  themeMode?: ThemeMode;
  onToggleThemeMode?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onRefresh,
  isRefreshing,
  onOpenOracleBridge,
  onOpenPdfExport,
  isBridgeConnected,
  lastSyncTime,
  privacyMode,
  onTogglePrivacyMode,
  isSidebarCollapsed,
  onToggleSidebarCollapse,
  onOpenMobileMenu,
  layoutWidth,
  onChangeLayoutWidth,
  uiDensity,
  onChangeUiDensity,
  themeMode = 'dark',
  onToggleThemeMode,
}) => {
  const [uiMenuOpen, setUiMenuOpen] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);

  const uiMenuRef = useRef<HTMLDivElement>(null);
  const moreMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (uiMenuRef.current && !uiMenuRef.current.contains(e.target as Node)) {
        setUiMenuOpen(false);
      }
      if (moreMenuRef.current && !moreMenuRef.current.contains(e.target as Node)) {
        setMoreMenuOpen(false);
      }
    };
    if (uiMenuOpen || moreMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [uiMenuOpen, moreMenuOpen]);

  const getTitles = (): { title: string; subtitle: string } => {
    switch (activeTab) {
      case 'home':
        return {
          title: 'Tổng quan SOC',
          subtitle: 'Giám sát an ninh CSDL Oracle 23ai (FREEPDB1)',
        };
      case 'alerts':
        return {
          title: 'Cảnh báo IDS',
          subtitle: 'Phát hiện tấn công DBMS & suy diễn thống kê SDB',
        };
      case 'fga':
        return {
          title: 'Bẫy FGA',
          subtitle: 'Kiểm toán hạt mịn & bẫy Honeytoken (SYS.NV)',
        };
      case 'triggers':
        return {
          title: 'Trigger chặn',
          subtitle: 'Ngăn chặn tức thời qua Autonomous Transaction',
        };
      case 'audit':
        return {
          title: 'Nhật ký kiểm toán',
          subtitle: 'UNIFIED_AUDIT_TRAIL thời gian thực',
        };
      case 'ips':
        return {
          title: 'Phản ứng IPS',
          subtitle: 'Điều khiển cách ly L0–L3 và khóa tài khoản',
        };
      case 'users':
        return {
          title: 'Hồ sơ tài khoản',
          subtitle: 'Quản trị quyền và dữ liệu bảng SYS.NV',
        };
      case 'docs':
        return {
          title: 'Báo cáo đề tài',
          subtitle: 'Kiến trúc hệ thống và tài liệu kỹ thuật',
        };
      default:
        return {
          title: 'Oracle DB-IDS',
          subtitle: 'Defense-in-Depth & Active IPS',
        };
    }
  };

  const { title, subtitle } = getTitles();
  const shortSyncTime = lastSyncTime ? lastSyncTime.substring(11, 19) : null;

  return (
    <header className="h-16 bg-[var(--surface)] border-b border-[var(--line)] px-4 sm:px-6 flex items-center justify-between gap-3 sticky top-0 z-30">
      {/* Left Zone: Sidebar toggles + Concise Title (1 title + 1 line subtitle) */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Mobile Hamburger Button */}
        <button
          onClick={onOpenMobileMenu}
          aria-label="Mở menu điều hướng"
          className="lg:hidden w-8 h-8 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)] flex items-center justify-center transition-colors cursor-pointer shrink-0 focus-visible:ring"
        >
          <Menu className="w-4 h-4" />
        </button>

        {/* Desktop Sidebar Collapse/Expand Toggle */}
        <button
          onClick={onToggleSidebarCollapse}
          aria-label={isSidebarCollapsed ? 'Mở rộng thanh bên' : 'Thu gọn thanh bên'}
          title={isSidebarCollapsed ? 'Mở rộng thanh bên' : 'Thu gọn thanh bên'}
          className="hidden lg:flex w-8 h-8 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)] items-center justify-center transition-colors cursor-pointer shrink-0 focus-visible:ring"
        >
          {isSidebarCollapsed ? (
            <PanelLeftOpen className="w-4 h-4 text-[var(--accent)]" />
          ) : (
            <PanelLeftClose className="w-4 h-4 text-[var(--text-2)]" />
          )}
        </button>

        <div className="min-w-0">
          <h1 className="text-sm font-semibold text-[var(--text-1)] tracking-tight truncate leading-tight">
            {title}
          </h1>
          <p className="text-xs text-[var(--text-3)] truncate mt-0.5 hidden sm:block leading-tight">
            {subtitle}
          </p>
        </div>
      </div>

      {/* Right Zone: Exactly 4 minimalist elements */}
      <div className="flex items-center gap-2 shrink-0">
        {/* 1. Connection status dot + sync time */}
        <div
          role="status"
          aria-live="polite"
          title={
            isBridgeConnected
              ? `Đang kết nối Oracle 23ai (FREEPDB1)${shortSyncTime ? ` · Đồng bộ lúc ${shortSyncTime}` : ''}`
              : `Oracle Bridge sẵn sàng${shortSyncTime ? ` · Đồng bộ lúc ${shortSyncTime}` : ''}`
          }
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)] text-xs font-mono text-[var(--text-2)] tabular-nums"
        >
          <StatusDot status={isBridgeConnected ? 'ok' : 'warn'} pulse={isRefreshing} size="sm" />
          <span className="hidden sm:inline font-sans text-xs text-[var(--text-3)]">Đồng bộ:</span>
          <span>{shortSyncTime || 'Tự động'}</span>
          {isRefreshing && (
            <RefreshCw className="w-3 h-3 text-[var(--accent)] spin-active ml-0.5" />
          )}
        </div>

        {/* 2. Privacy Mode Toggle (Icon + Tooltip, min 32px) */}
        <button
          onClick={onTogglePrivacyMode}
          aria-label={privacyMode ? 'Đang ẩn thông tin nhạy cảm (Bảo mật định danh)' : 'Đang hiện thông tin định danh'}
          title={
            privacyMode
              ? 'Bảo mật định danh: BẬT (Đang che Username, Host, OS User, CMND). Nhấn để hiện.'
              : 'Bảo mật định danh: TẮT (Đang hiện Username, Host). Nhấn để che.'
          }
          className={`w-8 h-8 rounded-lg border flex items-center justify-center transition-colors cursor-pointer shrink-0 focus-visible:ring ${
            privacyMode
              ? 'bg-[var(--ok-soft)] border-[var(--ok)]/30 text-[var(--ok)]'
              : 'bg-[var(--surface-hover)] border-[var(--line)] text-[var(--text-3)] hover:text-[var(--text-1)]'
          }`}
        >
          {privacyMode ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        </button>

        {/* 3. Combined UI Customizer Dropdown ("Giao diện": theme / width / density) */}
        <div className="relative" ref={uiMenuRef}>
          <button
            onClick={() => {
              setUiMenuOpen((prev) => !prev);
              setMoreMenuOpen(false);
            }}
            aria-label="Tùy chỉnh giao diện"
            aria-expanded={uiMenuOpen}
            aria-haspopup="true"
            title="Tùy chỉnh giao diện (Chủ đề, Khung nhìn, Mật độ bảng)"
            className={`h-8 px-2.5 rounded-lg border flex items-center gap-1.5 text-xs font-medium transition-colors cursor-pointer shrink-0 focus-visible:ring ${
              uiMenuOpen
                ? 'bg-[var(--surface-hover)] border-[var(--accent)] text-[var(--text-1)]'
                : 'bg-[var(--surface-hover)] border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)]'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-[var(--accent)]" />
            <span className="hidden md:inline">Giao diện</span>
          </button>

          {uiMenuOpen && (
            <div className="absolute right-0 mt-2 w-72 bg-[var(--surface)] border border-[var(--line)] rounded-xl shadow-xl p-3.5 z-50 space-y-3.5">
              <div className="text-xs font-semibold text-[var(--text-1)] border-b border-[var(--line)] pb-2">
                Tùy chỉnh giao diện
              </div>

              {/* Theme Mode */}
              {onToggleThemeMode && (
                <div className="space-y-1.5">
                  <div className="text-xs text-[var(--text-3)]">Chủ đề màu sắc</div>
                  <div className="grid grid-cols-2 gap-1.5 p-1 bg-[var(--surface-hover)] rounded-lg border border-[var(--line)]">
                    <button
                      onClick={() => themeMode !== 'dark' && onToggleThemeMode()}
                      className={`px-2 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center justify-center gap-1.5 ${
                        themeMode === 'dark'
                          ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                          : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                      }`}
                    >
                      <Moon className="w-3.5 h-3.5" />
                      <span>Tối (SOC)</span>
                    </button>
                    <button
                      onClick={() => themeMode !== 'light' && onToggleThemeMode()}
                      className={`px-2 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center justify-center gap-1.5 ${
                        themeMode === 'light'
                          ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                          : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                      }`}
                    >
                      <Sun className="w-3.5 h-3.5" />
                      <span>Sáng (Chiếu)</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Viewport Width */}
              <div className="space-y-1.5">
                <div className="text-xs text-[var(--text-3)]">Độ rộng khung nhìn</div>
                <div className="grid grid-cols-3 gap-1 p-1 bg-[var(--surface-hover)] rounded-lg border border-[var(--line)]">
                  <button
                    onClick={() => onChangeLayoutWidth('fluid')}
                    className={`px-1.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center justify-center gap-1 ${
                      layoutWidth === 'fluid'
                        ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                        : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                    }`}
                  >
                    <Maximize2 className="w-3 h-3" />
                    <span>Toàn bộ</span>
                  </button>
                  <button
                    onClick={() => onChangeLayoutWidth('boxed')}
                    className={`px-1.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                      layoutWidth === 'boxed'
                        ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                        : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                    }`}
                  >
                    1600px
                  </button>
                  <button
                    onClick={() => onChangeLayoutWidth('compact')}
                    className={`px-1.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center justify-center gap-1 ${
                      layoutWidth === 'compact'
                        ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                        : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                    }`}
                  >
                    <Minimize2 className="w-3 h-3" />
                    <span>1280px</span>
                  </button>
                </div>
              </div>

              {/* Table Density */}
              <div className="space-y-1.5">
                <div className="text-xs text-[var(--text-3)]">Mật độ bảng dữ liệu</div>
                <div className="grid grid-cols-2 gap-1.5 p-1 bg-[var(--surface-hover)] rounded-lg border border-[var(--line)]">
                  <button
                    onClick={() => onChangeUiDensity('comfortable')}
                    className={`px-2 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                      uiDensity === 'comfortable'
                        ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                        : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                    }`}
                  >
                    Thoáng
                  </button>
                  <button
                    onClick={() => onChangeUiDensity('compact')}
                    className={`px-2 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                      uiDensity === 'compact'
                        ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                        : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
                    }`}
                  >
                    Thu gọn
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* 4. More Actions Menu "⋯" (PDF export, Oracle connection, manual sync) */}
        <div className="relative" ref={moreMenuRef}>
          <button
            onClick={() => {
              setMoreMenuOpen((prev) => !prev);
              setUiMenuOpen(false);
            }}
            aria-label="Thao tác khác"
            aria-expanded={moreMenuOpen}
            aria-haspopup="true"
            title="Thao tác khác (Xuất PDF, Kết nối Oracle, Đồng bộ)"
            className={`w-8 h-8 rounded-lg border flex items-center justify-center transition-colors cursor-pointer shrink-0 focus-visible:ring ${
              moreMenuOpen
                ? 'bg-[var(--surface-hover)] border-[var(--accent)] text-[var(--text-1)]'
                : 'bg-[var(--surface-hover)] border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)]'
            }`}
          >
            <MoreHorizontal className="w-4 h-4" />
          </button>

          {moreMenuOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-[var(--surface)] border border-[var(--line)] rounded-xl shadow-xl p-1.5 z-50 space-y-0.5">
              <button
                onClick={() => {
                  onOpenPdfExport();
                  setMoreMenuOpen(false);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-[var(--text-2)] hover:text-[var(--text-1)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer text-left focus-visible:ring"
              >
                <FileDown className="w-4 h-4 text-[var(--accent)]" />
                <span>Xuất báo cáo PDF</span>
              </button>

              <button
                onClick={() => {
                  onOpenOracleBridge();
                  setMoreMenuOpen(false);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-[var(--text-2)] hover:text-[var(--text-1)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer text-left focus-visible:ring"
              >
                <Database className="w-4 h-4 text-[var(--ok)]" />
                <span>Kết nối Oracle Bridge</span>
              </button>

              <button
                onClick={() => {
                  onRefresh();
                  setMoreMenuOpen(false);
                }}
                disabled={isRefreshing}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-[var(--text-2)] hover:text-[var(--text-1)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer text-left disabled:opacity-50 focus-visible:ring"
              >
                <RefreshCw className={`w-4 h-4 text-[var(--text-3)] ${isRefreshing ? 'spin-active' : ''}`} />
                <span>Đồng bộ thủ công</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
