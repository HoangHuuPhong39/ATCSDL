import React from 'react';
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
} from 'lucide-react';
import { ActiveTab, Metrics } from '../types/ids';

interface SidebarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  metrics: Metrics;
  autoResponse: boolean;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
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
}) => {
  const navGroups = [
    {
      groupTitle: 'Giám sát & Phát hiện (IDS)',
      items: [
        {
          id: 'home' as ActiveTab,
          label: 'Tổng quan SOC',
          icon: LayoutDashboard,
          badge: null,
        },
        {
          id: 'alerts' as ActiveTab,
          label: 'Cảnh báo & Risk Score',
          icon: AlertTriangle,
          badge: metrics.alert_count,
          badgeColor: 'bg-red-500/15 text-red-300 border-red-500/30',
          dotColor: 'bg-red-500',
        },
        {
          id: 'fga' as ActiveTab,
          label: 'Bẫy FGA & Honeytoken',
          icon: Target,
          badge: metrics.fga_count,
          badgeColor: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
          dotColor: 'bg-purple-500',
        },
        {
          id: 'triggers' as ActiveTab,
          label: 'Trigger chặn tức thời',
          icon: Zap,
          badge: metrics.trigger_count,
          badgeColor: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          dotColor: 'bg-amber-500',
        },
        {
          id: 'audit' as ActiveTab,
          label: 'Nhật ký kiểm toán',
          icon: FileText,
          badge: metrics.audit_count,
          badgeColor: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
          dotColor: 'bg-sky-500',
        },
      ],
    },
    {
      groupTitle: 'Phản ứng & Quản trị (IPS)',
      items: [
        {
          id: 'ips' as ActiveTab,
          label: 'Phản ứng Đa cấp (IPS)',
          icon: ShieldAlert,
          badge: autoResponse ? 'ON' : 'OFF',
          badgeColor: autoResponse
            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
            : 'bg-slate-500/15 text-slate-300 border-slate-500/30',
          dotColor: autoResponse ? 'bg-emerald-500' : 'bg-slate-500',
        },
        {
          id: 'users' as ActiveTab,
          label: 'Hồ sơ User & Bảng NV',
          icon: Users,
          badge: null,
        },
        {
          id: 'docs' as ActiveTab,
          label: 'Báo cáo & Kiến trúc',
          icon: BookOpen,
          badge: null,
        },
      ],
    },
  ];

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
          className="fixed inset-0 bg-black/65 backdrop-blur-xs z-40 lg:hidden transition-opacity duration-200"
        />
      )}

      <aside
        aria-label="Điều hướng hệ thống"
        className={`bg-[#0e1626] border-r border-[#38bdf8]/15 flex flex-col fixed top-0 bottom-0 left-0 z-50 transition-all duration-200 ease-out select-none ${
          isCollapsed ? 'lg:w-[74px] w-64' : 'w-64'
        } ${
          isMobileOpen ? 'translate-x-0 shadow-2xl shadow-black/80' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div
          className={`h-16 px-3.5 border-b border-white/5 flex items-center ${
            isCollapsed ? 'lg:justify-center justify-between' : 'justify-between'
          } gap-2 shrink-0`}
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <div
              onClick={onToggleCollapse}
              title={isCollapsed ? 'Mở rộng thanh bên' : 'Oracle DB-IDS 23ai'}
              className="w-9 h-9 rounded-lg bg-gradient-to-br from-sky-500/20 to-sky-600/40 border border-sky-400/35 flex items-center justify-center text-sky-400 shrink-0 cursor-pointer hover:border-sky-300 transition-colors"
            >
              <Shield className="w-5 h-5" />
            </div>
            <div className={`min-w-0 transition-opacity duration-150 ${isCollapsed ? 'lg:hidden block' : 'block'}`}>
              <div className="font-bold text-[14px] text-slate-100 tracking-tight flex items-center gap-1.5 whitespace-nowrap">
                <span>Oracle DB-IDS</span>
                <span className="text-[10px] font-mono text-sky-300">· 23ai</span>
              </div>
              <div className="text-[11px] text-slate-400 truncate">Defense-in-Depth &amp; IPS</div>
            </div>
          </div>

          {/* Close button on mobile */}
          <button
            onClick={onCloseMobile}
            aria-label="Đóng menu điều hướng"
            className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Groups */}
        <nav className="p-2.5 flex-1 overflow-y-auto overflow-x-hidden space-y-4">
          {navGroups.map((group) => (
            <div key={group.groupTitle} className="space-y-1">
              <div
                className={`px-2.5 py-1 text-[10px] uppercase font-bold tracking-wider text-slate-400 truncate ${
                  isCollapsed ? 'lg:hidden block' : 'block'
                }`}
              >
                {group.groupTitle}
              </div>

              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => handleSelectTab(item.id)}
                    aria-label={item.label}
                    title={isCollapsed ? `${item.label}${item.badge !== null ? ` (${item.badge})` : ''}` : undefined}
                    className={`w-full relative group flex items-center ${
                      isCollapsed ? 'lg:justify-center justify-between lg:px-0 px-3' : 'justify-between px-3'
                    } py-2.5 rounded-lg text-left text-[12.5px] font-semibold transition-all duration-150 border cursor-pointer ${
                      isActive
                        ? 'bg-sky-600 text-white border-sky-400 shadow-sm shadow-sky-900/40'
                        : 'text-slate-300 border-transparent hover:bg-[#131e33] hover:text-white'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-slate-400 group-hover:text-sky-300'}`} />
                      <span className={`truncate whitespace-nowrap ${isCollapsed ? 'lg:hidden block' : 'block'}`}>
                        {item.label}
                      </span>
                    </div>

                    {/* Expanded Badge */}
                    {item.badge !== null && (
                      <span
                        className={`text-[10px] font-bold font-mono tabular-nums px-1.5 py-0.5 rounded border ${
                          isCollapsed ? 'lg:hidden inline-flex' : 'inline-flex'
                        } ${
                          isActive
                            ? 'bg-white/20 text-white border-white/30'
                            : item.badgeColor || 'bg-slate-700/50 text-slate-300 border-slate-600'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}

                    {/* Collapsed Mini Badge Dot */}
                    {isCollapsed && item.badge !== null && (
                      <span
                        className={`hidden lg:inline-block absolute top-1.5 right-2 w-2 h-2 rounded-full ${
                          item.dotColor || 'bg-sky-400'
                        } ring-2 ring-[#0e1626]`}
                      />
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Footer Toggle / System Status */}
        <div className="p-3 border-t border-white/5 bg-[#0b1322]/70 flex items-center justify-between gap-2 shrink-0">
          <div className={`flex items-center gap-2.5 min-w-0 ${isCollapsed ? 'lg:hidden flex' : 'flex'}`}>
            <div className="min-w-0">
              <div className="text-[11.5px] font-bold text-slate-200 truncate">Oracle Security Engine</div>
              <div className="text-[10.5px] text-emerald-400 font-semibold font-mono truncate">
                IPS: {autoResponse ? 'Active Mode' : 'Monitor Only'}
              </div>
            </div>
          </div>

          <button
            onClick={onToggleCollapse}
            aria-label={isCollapsed ? 'Mở rộng thanh điều hướng' : 'Thu gọn thanh điều hướng'}
            title={isCollapsed ? 'Mở rộng thanh điều hướng' : 'Thu gọn thanh điều hướng'}
            className={`hidden lg:inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#131e33] border border-sky-500/20 text-slate-300 hover:text-white hover:border-sky-400 text-[11px] font-semibold transition-colors cursor-pointer ${
              isCollapsed ? 'w-full' : 'shrink-0'
            }`}
          >
            {isCollapsed ? (
              <ChevronRight className="w-4 h-4 text-sky-400" />
            ) : (
              <>
                <ChevronLeft className="w-3.5 h-3.5 text-sky-400" />
                <span>Thu gọn</span>
              </>
            )}
          </button>
        </div>
      </aside>
    </>
  );
};
