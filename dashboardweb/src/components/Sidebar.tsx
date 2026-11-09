import React from 'react';
import { motion, useReducedMotion } from 'motion/react';
import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  Target,
  Zap,
  FileText,
  Users,
  ShieldAlert,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  X,
  Menu,
} from 'lucide-react';
import { ActiveTab, Metrics } from '../types/ids';
import { StatusDot } from './ui/StatusDot';

interface SidebarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  metrics: Metrics;
  autoResponse: boolean;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
  onOpenMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  metrics,
  autoResponse,
  isCollapsed,
  onToggleCollapse,
  isMobileOpen,
  onCloseMobile,
  onOpenMobile,
}) => {
  const shouldReduceMotion = useReducedMotion();

  // Navigation items: each label <= 2 words, no group titles
  const navItems: Array<{
    id: ActiveTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number | null;
  }> = [
    {
      id: 'home',
      label: 'Tổng quan',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'alerts',
      label: 'Cảnh báo',
      icon: AlertTriangle,
      badge: metrics.alert_count > 0 ? metrics.alert_count : null,
    },
    {
      id: 'fga',
      label: 'Bẫy FGA',
      icon: Target,
      badge: metrics.fga_count > 0 ? metrics.fga_count : null,
    },
    {
      id: 'triggers',
      label: 'Trigger',
      icon: Zap,
      badge: metrics.trigger_count > 0 ? metrics.trigger_count : null,
    },
    {
      id: 'audit',
      label: 'Kiểm toán',
      icon: FileText,
      badge: metrics.audit_count > 0 ? metrics.audit_count : null,
    },
    {
      id: 'ips',
      label: 'IPS',
      icon: ShieldAlert,
      badge: null,
    },
    {
      id: 'users',
      label: 'Hồ sơ User',
      icon: Users,
      badge:
        metrics.locked_count + metrics.readonly_count > 0
          ? metrics.locked_count + metrics.readonly_count
          : null,
    },
    {
      id: 'docs',
      label: 'Báo cáo',
      icon: BookOpen,
      badge: null,
    },
  ];

  const mobileQuickItems = navItems.slice(0, 5);

  const handleSelectTab = (id: ActiveTab) => {
    onTabChange(id);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile / Tablet Backdrop Overlay */}
      {isMobileOpen && (
        <div
          onClick={onCloseMobile}
          aria-hidden="true"
          className="fixed inset-0 bg-black/60 backdrop-blur-xs z-40 lg:hidden transition-opacity duration-200"
        />
      )}

      <aside
        aria-label="Điều hướng hệ thống"
        className={`bg-[var(--surface)] border-r border-[var(--line)] flex flex-col fixed top-0 bottom-0 left-0 z-50 transition-all duration-200 ease-out select-none ${
          isCollapsed ? 'lg:w-[74px] w-64' : 'w-64'
        } ${
          isMobileOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div
          className={`h-16 px-4 border-b border-[var(--line)] flex items-center ${
            isCollapsed ? 'lg:justify-center justify-between' : 'justify-between'
          } gap-2 shrink-0`}
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <button
              type="button"
              onClick={onToggleCollapse}
              aria-label={isCollapsed ? 'Mở rộng thanh bên' : 'Thu gọn thanh bên'}
              title={isCollapsed ? 'Mở rộng thanh bên' : 'Oracle DB-IDS'}
              className="w-8 h-8 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)] flex items-center justify-center text-[var(--accent)] shrink-0 cursor-pointer hover:border-[var(--accent)] transition-colors focus-visible:ring"
            >
              <Shield className="w-4 h-4" />
            </button>
            <div className={`min-w-0 ${isCollapsed ? 'lg:hidden block' : 'block'}`}>
              <div className="font-semibold text-sm text-[var(--text-1)] tracking-tight flex items-center gap-1.5 whitespace-nowrap">
                <span>Oracle DB-IDS</span>
                <span className="text-xs font-mono px-1.5 py-0.2 rounded bg-[var(--surface-hover)] text-[var(--text-3)] border border-[var(--line)]">
                  23ai
                </span>
              </div>
            </div>
          </div>

          {/* Close button on mobile */}
          <button
            onClick={onCloseMobile}
            aria-label="Đóng menu điều hướng"
            className="lg:hidden p-1.5 rounded-lg text-[var(--text-3)] hover:text-[var(--text-1)] hover:bg-[var(--surface-hover)] transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Flat Navigation List (no group titles) */}
        <nav className="p-3 flex-1 overflow-y-auto overflow-x-hidden space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleSelectTab(item.id)}
                aria-label={item.label}
                aria-current={isActive ? 'page' : undefined}
                title={isCollapsed ? `${item.label}${item.badge !== null && item.badge !== undefined ? ` (${item.badge})` : ''}` : undefined}
                className={`w-full relative group flex items-center ${
                  isCollapsed ? 'lg:justify-center justify-between lg:px-0 px-3' : 'justify-between px-3'
                } py-2 rounded-lg text-left text-xs font-medium transition-colors cursor-pointer focus-visible:ring ${
                  isActive
                    ? 'text-[var(--text-1)] font-semibold'
                    : 'text-[var(--text-2)] hover:text-[var(--text-1)]'
                }`}
              >
                {/* Active animated pill background */}
                {isActive && (
                  <motion.div
                    layoutId={shouldReduceMotion ? undefined : 'sidebar-active-pill'}
                    className="absolute inset-0 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)] shadow-xs"
                    transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                  />
                )}
                {/* Active indicator bar on left */}
                {isActive && (
                  <motion.div
                    layoutId={shouldReduceMotion ? undefined : 'sidebar-active-bar'}
                    className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r bg-[var(--accent)]"
                    transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                  />
                )}

                <div className="relative z-10 flex items-center gap-2.5 min-w-0">
                  <Icon
                    className={`w-4 h-4 shrink-0 transition-colors ${
                      isActive ? 'text-[var(--accent)]' : 'text-[var(--text-3)] group-hover:text-[var(--text-2)]'
                    }`}
                  />
                  <span className={`truncate whitespace-nowrap ${isCollapsed ? 'lg:hidden block' : 'block'}`}>
                    {item.label}
                  </span>
                </div>

                {/* Badge: pure number, no wrap */}
                {item.badge !== null && item.badge !== undefined && (
                  <span
                    className={`relative z-10 text-xs font-mono tabular-nums px-1.5 py-0.2 rounded leading-none shrink-0 border ${
                      isCollapsed ? 'lg:hidden inline-flex' : 'inline-flex'
                    } ${
                      isActive
                        ? 'bg-[var(--surface)] text-[var(--text-1)] border-[var(--line)]'
                        : 'bg-[var(--surface-hover)] text-[var(--text-2)] border-[var(--line)]'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}

                {/* Collapsed dot */}
                {isCollapsed && item.badge !== null && item.badge !== undefined && (
                  <span className="hidden lg:inline-block absolute top-1.5 right-2 z-10">
                    <StatusDot status="accent" size="sm" />
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* System Telemetry Status (Replaces IPS Engine Box) */}
        <div className="p-3 border-t border-[var(--line)] bg-[var(--surface)] space-y-2 shrink-0">
          <div
            className={`space-y-1.5 text-xs ${
              isCollapsed ? 'lg:hidden block' : 'block'
            }`}
          >
            <div className="text-xs uppercase tracking-wider font-semibold text-[var(--text-3)] px-1 mb-1">
              Trạng thái hệ thống
            </div>

            {/* Oracle FREEPDB1 Status */}
            <div className="flex items-center justify-between px-1 py-0.5 rounded text-[var(--text-2)] font-mono">
              <span className="flex items-center gap-2">
                <StatusDot status="ok" size="sm" />
                <span className="font-sans text-xs">Oracle FREEPDB1</span>
              </span>
              <span className="text-xs text-[var(--ok)]">Online</span>
            </div>

            {/* Audit Status */}
            <div className="flex items-center justify-between px-1 py-0.5 rounded text-[var(--text-2)] font-mono">
              <span className="flex items-center gap-2">
                <StatusDot status="ok" size="sm" />
                <span className="font-sans text-xs">Audit Trail</span>
              </span>
              <span className="text-xs text-[var(--ok)]">Active</span>
            </div>

            {/* IPS Engine Status */}
            <div className="flex items-center justify-between px-1 py-0.5 rounded text-[var(--text-2)] font-mono">
              <span className="flex items-center gap-2">
                <StatusDot status={autoResponse ? 'ok' : 'warn'} size="sm" />
                <span className="font-sans text-xs">IPS Engine</span>
              </span>
              <span
                className={`text-xs ${
                  autoResponse ? 'text-[var(--ok)]' : 'text-[var(--warn)]'
                }`}
              >
                {autoResponse ? 'L0–L3' : 'Monitor'}
              </span>
            </div>
          </div>

          {/* Collapsed icon status indicators */}
          {isCollapsed && (
            <div className="hidden lg:flex flex-col items-center gap-2 py-1">
              <span title="Oracle FREEPDB1: Online">
                <StatusDot status="ok" size="sm" />
              </span>
              <span title="Audit Trail: Active">
                <StatusDot status="ok" size="sm" />
              </span>
              <span title={`IPS Engine: ${autoResponse ? 'L0-L3 Auto' : 'Monitor'}`}>
                <StatusDot status={autoResponse ? 'ok' : 'warn'} size="sm" />
              </span>
            </div>
          )}

          {/* Collapse/Expand Toggle Button */}
          <button
            onClick={onToggleCollapse}
            aria-label={isCollapsed ? 'Mở rộng thanh bên' : 'Thu gọn thanh bên'}
            title={isCollapsed ? 'Mở rộng thanh bên' : 'Thu gọn thanh bên'}
            className="hidden lg:inline-flex w-full items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)] text-[var(--text-2)] hover:text-[var(--text-1)] text-xs font-medium transition-colors cursor-pointer focus-visible:ring"
          >
            {isCollapsed ? (
              <ChevronRight className="w-3.5 h-3.5" />
            ) : (
              <>
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Thu gọn</span>
              </>
            )}
          </button>
        </div>
      </aside>

      {/* Mobile Thumb-Zone Bottom Navigation Bar (< 768px) */}
      <nav
        aria-label="Điều hướng nhanh trên thiết bị di động"
        className="soc-mobile-bottom-nav md:hidden fixed bottom-0 left-0 right-0 z-30 bg-[var(--surface)]/95 border-t border-[var(--line)] backdrop-blur-xl px-2 pt-1.5 safe-bottom-nav grid grid-cols-6 gap-1"
      >
        {mobileQuickItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => handleSelectTab(item.id)}
              aria-current={isActive ? 'page' : undefined}
              className={`relative flex flex-col items-center justify-center py-1.5 px-1 rounded-lg text-xs font-medium transition-colors cursor-pointer min-h-11 ${
                isActive
                  ? 'text-[var(--text-1)] font-semibold'
                  : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
              }`}
            >
              {isActive && (
                <motion.div
                  layoutId={shouldReduceMotion ? undefined : 'mobile-active-pill'}
                  className="absolute inset-1 rounded-lg bg-[var(--surface-hover)] border border-[var(--line)]"
                  transition={{ type: 'spring', stiffness: 380, damping: 30 }}
                />
              )}
              <Icon className={`relative z-10 w-4 h-4 ${isActive ? 'text-[var(--accent)]' : 'text-[var(--text-3)]'}`} />
              <span className="relative z-10 truncate max-w-full mt-0.5 text-xs">{item.label}</span>
              {typeof item.badge === 'number' && item.badge > 0 && (
                <span className="absolute top-1 right-2 z-10">
                  <StatusDot status="accent" size="sm" />
                </span>
              )}
            </button>
          );
        })}

        <button
          onClick={() => (onOpenMobile ? onOpenMobile() : onCloseMobile())}
          aria-label="Mở toàn bộ menu"
          className="flex flex-col items-center justify-center py-1.5 px-1 rounded-lg text-xs font-medium text-[var(--text-3)] hover:text-[var(--text-1)] cursor-pointer min-h-11"
        >
          <Menu className="w-4 h-4" />
          <span className="truncate max-w-full mt-0.5 text-xs">Menu</span>
        </button>
      </nav>
    </>
  );
};
