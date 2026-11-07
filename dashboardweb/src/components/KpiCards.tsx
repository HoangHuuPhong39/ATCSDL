import React from 'react';
import { Database, AlertTriangle, Zap, ShieldCheck } from 'lucide-react';
import { Metrics } from '../types/ids';

interface KpiCardsProps {
  metrics: Metrics;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ metrics }) => {
  return (
    <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Card 1: Tổng sự kiện Audit & FGA */}
      <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-4 flex flex-col justify-between shadow-lg shadow-black/30 relative overflow-hidden group hover:border-sky-500/40 transition-all">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-400/30 flex items-center justify-center text-sky-400 shrink-0">
            <Database className="w-4 h-4" />
          </div>
          <div className="text-[12px] font-semibold text-slate-300">Tổng sự kiện Audit &amp; FGA</div>
        </div>
        <div className="flex items-end justify-between mt-3.5">
          <div>
            <div className="text-2xl font-extrabold text-slate-100 font-mono tracking-tight">
              {metrics.audit_count}
            </div>
            <div className="text-[11px] font-semibold text-emerald-400 mt-1 flex items-center gap-1">
              <span>↑ +12%</span>
              <span className="text-slate-400 font-normal">so với phiên trước</span>
            </div>
          </div>
          {/* Mini Bar chart SVG */}
          <div className="w-16 h-8 flex items-end justify-end shrink-0">
            <svg width="60" height="28" viewBox="0 0 60 28" fill="none">
              <rect x="2" y="14" width="6" height="14" rx="2" fill="#0284c7" opacity="0.6"/>
              <rect x="12" y="10" width="6" height="18" rx="2" fill="#0284c7" opacity="0.75"/>
              <rect x="22" y="16" width="6" height="12" rx="2" fill="#0284c7" opacity="0.6"/>
              <rect x="32" y="6" width="6" height="22" rx="2" fill="#0284c7" opacity="0.85"/>
              <rect x="42" y="2" width="6" height="26" rx="2" fill="#38bdf8"/>
              <rect x="52" y="8" width="6" height="20" rx="2" fill="#0284c7"/>
            </svg>
          </div>
        </div>
      </div>

      {/* Card 2: Cảnh báo IDS đa chiều */}
      <div className="bg-[#101b2e] border border-red-500/25 rounded-xl p-4 flex flex-col justify-between shadow-lg shadow-black/30 relative overflow-hidden group hover:border-red-500/40 transition-all">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-red-500/15 border border-red-500/35 flex items-center justify-center text-red-400 shrink-0">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="text-[12px] font-semibold text-slate-300">Cảnh báo IDS đa chiều</div>
        </div>
        <div className="flex items-end justify-between mt-3.5">
          <div>
            <div className="text-2xl font-extrabold text-slate-100 font-mono tracking-tight">
              {metrics.alert_count}
            </div>
            <div className="text-[11px] font-semibold text-red-400 mt-1 flex items-center gap-1">
              <span>↑ Cần xử lý</span>
              <span className="text-slate-400 font-normal font-mono">({metrics.alert_count} cảnh báo)</span>
            </div>
          </div>
          {/* Mini Red Sparkline SVG */}
          <div className="w-16 h-8 flex items-end justify-end shrink-0">
            <svg width="65" height="28" viewBox="0 0 65 28" fill="none">
              <path d="M2 22 Q 15 24, 25 14 T 45 16 T 63 4" stroke="#ef4444" strokeWidth="2.5" fill="none" strokeLinecap="round"/>
              <path d="M2 22 Q 15 24, 25 14 T 45 16 T 63 4 L 63 28 L 2 28 Z" fill="url(#red-spark-grad)" opacity="0.25"/>
              <defs>
                <linearGradient id="red-spark-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444"/>
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0"/>
                </linearGradient>
              </defs>
            </svg>
          </div>
        </div>
      </div>

      {/* Card 3: Vi phạm bị Trigger chặn */}
      <div className="bg-[#101b2e] border border-amber-500/25 rounded-xl p-4 flex flex-col justify-between shadow-lg shadow-black/30 relative overflow-hidden group hover:border-amber-500/40 transition-all">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-amber-500/15 border border-amber-500/35 flex items-center justify-center text-amber-400 shrink-0">
            <Zap className="w-4 h-4" />
          </div>
          <div className="text-[12px] font-semibold text-slate-300">Vi phạm bị Trigger chặn</div>
        </div>
        <div className="flex items-end justify-between mt-3.5">
          <div>
            <div className="text-2xl font-extrabold text-slate-100 font-mono tracking-tight">
              {metrics.trigger_count}
            </div>
            <div className="text-[11px] font-semibold text-emerald-400 mt-1 flex items-center gap-1">
              <span>↓ Đã chặn đứng</span>
              <span className="text-slate-400 font-normal">Autonomous</span>
            </div>
          </div>
          {/* Mini Yellow Sparkline SVG */}
          <div className="w-16 h-8 flex items-end justify-end shrink-0">
            <svg width="65" height="28" viewBox="0 0 65 28" fill="none">
              <path d="M2 20 Q 18 8, 32 18 T 63 6" stroke="#f97316" strokeWidth="2.5" fill="none" strokeLinecap="round"/>
              <path d="M2 20 Q 18 8, 32 18 T 63 6 L 63 28 L 2 28 Z" fill="url(#yellow-spark-grad)" opacity="0.25"/>
              <defs>
                <linearGradient id="yellow-spark-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f97316"/>
                  <stop offset="100%" stopColor="#f97316" stopOpacity="0"/>
                </linearGradient>
              </defs>
            </svg>
          </div>
        </div>
      </div>

      {/* Card 4: Định mức rủi ro & Phản ứng IPS */}
      <div className="bg-[#101b2e] border border-purple-500/25 rounded-xl p-4 flex flex-col justify-between shadow-lg shadow-black/30 relative overflow-hidden group hover:border-purple-500/40 transition-all">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-500/15 border border-purple-500/35 flex items-center justify-center text-purple-400 shrink-0">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="text-[12px] font-semibold text-slate-300">Định mức rủi ro &amp; Phản ứng IPS</div>
        </div>
        <div className="flex items-end justify-between mt-3.5">
          <div>
            <div className="text-2xl font-extrabold text-slate-100 font-mono tracking-tight">
              {metrics.max_risk} / 100
            </div>
            <div className="text-[11px] font-medium text-slate-300 mt-1">
              Khóa (L3): <span className="font-bold text-red-400 font-mono">{metrics.locked_count}</span> | Read-Only (L2): <span className="font-bold text-amber-400 font-mono">{metrics.readonly_count}</span>
            </div>
          </div>
          {/* Mini Donut SVG */}
          <div className="w-10 h-10 flex items-center justify-center shrink-0">
            <svg width="36" height="36" viewBox="0 0 36 36">
              <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(139,92,246,0.2)" strokeWidth="4"/>
              <circle 
                cx="18" cy="18" r="14" 
                fill="none" 
                stroke="#a855f7" 
                strokeWidth="4" 
                strokeDasharray="88" 
                strokeDashoffset={Math.max(0, 88 - (88 * metrics.max_risk) / 100)} 
                strokeLinecap="round"
                transform="rotate(-90 18 18)"
              />
            </svg>
          </div>
        </div>
      </div>
    </section>
  );
};
