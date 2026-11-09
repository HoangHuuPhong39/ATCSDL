import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  Tooltip,
  Cell,
  CartesianGrid,
} from 'recharts';
import { Flame, Eye, Database, Info } from 'lucide-react';
import { AlertItem, DbUser } from '../types/ids';
import {
  AttackGroup,
  buildAttackHeatmapMatrix,
  HeatmapCellPoint,
} from '../utils/analytics';
import { maskUsername } from '../utils/privacy';

interface AttackHeatmapProps {
  alerts: AlertItem[];
  users: DbUser[];
  privacyMode?: boolean;
  onOpenAlertModal: (alert: AlertItem) => void;
  onOpenOracleBridge: () => void;
}

interface CustomHeatmapCellProps {
  cx?: number;
  cy?: number;
  payload?: HeatmapCellPoint;
  totalCols: number;
  onSelectCell: (cell: HeatmapCellPoint) => void;
}

const CustomHeatmapCell: React.FC<CustomHeatmapCellProps> = ({
  cx = 0,
  cy = 0,
  payload,
  totalCols,
  onSelectCell,
}) => {
  if (!payload) return null;

  const cellWidth = Math.max(66, Math.min(118, Math.floor(680 / Math.max(1, totalCols))));
  const cellHeight = 42;
  const x = cx - cellWidth / 2;
  const y = cy - cellHeight / 2;
  const isActive = payload.intensity > 0;

  return (
    <g
      onClick={() => onSelectCell(payload)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelectCell(payload);
        }
      }}
      tabIndex={isActive ? 0 : -1}
      role={isActive ? 'button' : undefined}
      aria-label={
        isActive
          ? `User ${payload.user} lúc ${payload.timeSlot}: cường độ ${payload.intensity}/100, ${payload.eventCount} sự kiện`
          : undefined
      }
      style={{ cursor: isActive ? 'pointer' : 'default' }}
      className="transition-opacity hover:opacity-90 focus:outline-none"
    >
      <rect
        x={x}
        y={y}
        width={cellWidth}
        height={cellHeight}
        rx={7}
        ry={7}
        fill={payload.fill}
        stroke={payload.stroke}
        strokeWidth={isActive ? 1.5 : 1}
      />
      {isActive ? (
        <>
          <text
            x={cx}
            y={cy - 3}
            textAnchor="middle"
            dominantBaseline="central"
            fill="var(--text-1)"
            fontSize={12}
            fontWeight={700}
            fontFamily="IBM Plex Mono, monospace"
          >
            {payload.intensity} pts
          </text>
          <text
            x={cx}
            y={cy + 11}
            textAnchor="middle"
            dominantBaseline="central"
            fill="var(--text-2)"
            fontSize={11}
            fontWeight={600}
            fontFamily="IBM Plex Mono, monospace"
          >
            {payload.eventCount} sự kiện
          </text>
        </>
      ) : (
        <text
          x={cx}
          y={cy}
          textAnchor="middle"
          dominantBaseline="central"
          fill="var(--text-3)"
          fontSize={11}
          fontFamily="IBM Plex Mono, monospace"
        >
          0
        </text>
      )}
    </g>
  );
};

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: HeatmapCellPoint }>;
}

const CustomHeatmapTooltip: React.FC<CustomTooltipProps> = ({ active, payload }) => {
  if (!active || !payload || !payload.length) return null;
  const cell = payload[0].payload;

  return (
    <div className="bg-[var(--surface-subtle)]/95 border border-sky-400/40 rounded-xl p-3.5 shadow-2xl shadow-black/90 text-xs max-w-xs space-y-2 backdrop-blur-md">
      <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-2">
        <span className="font-mono font-bold text-sky-300 text-xs">
          User: {cell.user}
        </span>
        <span className="font-mono text-slate-300 tabular-nums">
          Khung giờ: {cell.timeSlot}
        </span>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Cường độ tấn công:</span>
          <span className="font-mono font-bold text-white tabular-nums">
            {cell.intensity} / 100
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Số sự kiện ghi nhận:</span>
          <span className="font-mono font-bold text-slate-200 tabular-nums">
            {cell.eventCount} (DBMS: {cell.dbmsCount} · SDB: {cell.sdbCount})
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Phản ứng IPS:</span>
          <span className="font-mono font-semibold text-amber-300">
            {cell.levelLabel}
          </span>
        </div>
      </div>

      <div className="pt-1.5 border-t border-white/10 text-xs text-slate-300">
        <span className="text-slate-400 block mb-0.5">Kỹ thuật nổi bật:</span>
        <span className="font-semibold text-sky-200 line-clamp-2">{cell.topAttack}</span>
      </div>
    </div>
  );
};

export const AttackHeatmap: React.FC<AttackHeatmapProps> = ({
  alerts,
  users,
  privacyMode = false,
  onOpenAlertModal,
  onOpenOracleBridge,
}) => {
  const [groupFilter, setGroupFilter] = useState<'ALL' | AttackGroup>('ALL');
  const [selectedCell, setSelectedCell] = useState<HeatmapCellPoint | null>(null);

  const matrix = useMemo(() => {
    const mappedUsers = privacyMode
      ? users.map((u) => ({ ...u, USERNAME: maskUsername(u.USERNAME, true) }))
      : users;
    return buildAttackHeatmapMatrix(alerts, mappedUsers, groupFilter);
  }, [alerts, users, privacyMode, groupFilter]);

  const activeInspectionCell =
    selectedCell &&
    matrix.points.find(
      (p) => p.user === selectedCell.user && p.timeSlot === selectedCell.timeSlot
    )
      ? matrix.points.find(
          (p) => p.user === selectedCell.user && p.timeSlot === selectedCell.timeSlot
        )!
      : matrix.peakCell;

  const handleCellClick = (cell: HeatmapCellPoint) => {
    setSelectedCell(cell);
    if (cell.sampleAlert) {
      onOpenAlertModal(cell.sampleAlert);
    }
  };

  return (
    <section
      data-testid="recharts-attack-heatmap"
      className="bg-[var(--surface)] border border-[var(--line)] rounded-xl p-3.5 sm:p-4 transition-colors"
    >
      {/* Header & Group Filter */}
      <div className="flex items-center justify-between gap-3 pb-3 border-b border-[var(--line)]">
        <div className="flex items-center gap-2 min-w-0">
          <Flame className="w-4 h-4 text-[var(--warn)] shrink-0" />
          <h2 className="text-xs sm:text-sm font-semibold text-[var(--text-1)] truncate">
            Biểu đồ nhiệt
          </h2>
          <span
            title="Trục ngang: Khung thời gian (5 phút) · Trục dọc: Tài khoản CSDL · Nhấn vào ô để xem chi tiết"
            className="text-[var(--text-3)] cursor-help shrink-0"
          >
            <Info className="w-3.5 h-3.5" />
          </span>
        </div>

        <div className="flex items-center bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg p-0.5 gap-0.5 shrink-0">
          <button
            type="button"
            onClick={() => setGroupFilter('ALL')}
            className={`px-2 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap focus-visible:ring ${
              groupFilter === 'ALL'
                ? 'bg-[var(--surface)] text-[var(--text-1)] shadow-sm'
                : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
            }`}
          >
            Tất cả
          </button>
          <button
            type="button"
            onClick={() => setGroupFilter('DBMS')}
            className={`px-2 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap focus-visible:ring ${
              groupFilter === 'DBMS'
                ? 'bg-[var(--surface)] text-[var(--danger)] shadow-sm'
                : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
            }`}
          >
            DBMS
          </button>
          <button
            type="button"
            onClick={() => setGroupFilter('SDB')}
            className={`px-2 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap focus-visible:ring ${
              groupFilter === 'SDB'
                ? 'bg-[var(--surface)] text-[var(--warn)] shadow-sm'
                : 'text-[var(--text-3)] hover:text-[var(--text-1)]'
            }`}
          >
            SDB
          </button>
        </div>
      </div>

      {/* Recharts 2D Scatter Matrix Heatmap */}
      <div className="mt-4 w-full bg-[var(--surface-subtle)]/70 border border-white/5 rounded-xl p-2 sm:p-3 overflow-x-auto">
        <div className="min-w-[520px] h-[270px]">
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart
              margin={{ top: 18, right: 28, bottom: 16, left: 10 }}
            >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgba(148, 163, 184, 0.08)"
              vertical={true}
              horizontal={true}
            />
            <XAxis
              type="number"
              dataKey="xIndex"
              name="Khung giờ"
              domain={[-0.5, Math.max(0.5, matrix.timeSlots.length - 0.5)]}
              ticks={matrix.timeSlots.map((_, idx) => idx)}
              tickFormatter={(idx: number) => matrix.timeSlots[idx] || ''}
              tick={{ fill: 'var(--text-3)', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }}
              axisLine={{ stroke: 'rgba(56, 189, 248, 0.2)' }}
              tickLine={false}
              interval={0}
            />
            <YAxis
              type="number"
              dataKey="yIndex"
              name="Tài khoản"
              domain={[-0.6, Math.max(0.6, matrix.users.length - 0.4)]}
              ticks={matrix.users.map((_, idx) => idx)}
              tickFormatter={(idx: number) => matrix.users[idx] || ''}
              tick={{ fill: 'var(--accent)', fontSize: 12, fontWeight: 700, fontFamily: 'IBM Plex Mono, monospace' }}
              axisLine={{ stroke: 'rgba(56, 189, 248, 0.2)' }}
              tickLine={false}
              width={56}
              reversed={true}
            />
            <ZAxis type="number" dataKey="intensity" range={[100, 500]} name="Cường độ" />
            <Tooltip
              cursor={{ strokeDasharray: '3 3', stroke: 'rgba(56, 189, 248, 0.35)' }}
              content={<CustomHeatmapTooltip />}
            />
            <Scatter
              name="Attack Intensity Matrix"
              data={matrix.points}
              isAnimationActive={false}
              shape={(props: unknown) => {
                const typedProps = props as {
                  cx?: number;
                  cy?: number;
                  payload?: HeatmapCellPoint;
                };
                return (
                  <CustomHeatmapCell
                    cx={typedProps.cx}
                    cy={typedProps.cy}
                    payload={typedProps.payload}
                    totalCols={matrix.timeSlots.length}
                    onSelectCell={handleCellClick}
                  />
                );
              }}
            >
              {matrix.points.map((entry) => (
                <Cell
                  key={`cell-${entry.user}-${entry.timeSlot}`}
                  fill={entry.fill}
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
        </div>
      </div>

      {/* Bottom Legend & Peak Cell Inspector */}
      <div className="mt-3 pt-3 border-t border-[var(--line)] flex flex-col xl:flex-row xl:items-center justify-between gap-3 text-xs">
        {/* Intensity Scale Legend */}
        <div className="flex items-center gap-3.5 flex-wrap text-[var(--text-3)] font-mono">
          <span className="font-sans font-medium text-[var(--text-2)]">Thang nhiệt:</span>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[var(--surface-hover)] border border-[var(--line)] inline-block" />
            <span className="text-xs">0 (An toàn)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[var(--accent)]/40 inline-block" />
            <span className="text-xs">1–49 (L1)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[var(--warn)]/70 inline-block" />
            <span className="text-xs">50–79 (L2)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[var(--danger)]/80 inline-block" />
            <span className="text-xs">80–100 (L3)</span>
          </div>
        </div>

        {/* Selected / Peak Cell Quick Action */}
        {activeInspectionCell && activeInspectionCell.intensity > 0 ? (
          <div className="flex items-center justify-between sm:justify-end gap-2.5 bg-[var(--surface-hover)] border border-[var(--line)] px-2.5 py-1 rounded-lg">
            <div className="text-xs font-mono text-[var(--text-2)] truncate max-w-md">
              Điểm nóng: <strong className="text-[var(--text-1)]">{activeInspectionCell.user}</strong> lúc{' '}
              <span className="tabular-nums">{activeInspectionCell.timeSlot}</span> ·{' '}
              <strong className="text-[var(--danger)] tabular-nums">{activeInspectionCell.intensity}/100</strong>
            </div>
            {activeInspectionCell.sampleAlert && (
              <button
                type="button"
                onClick={() => onOpenAlertModal(activeInspectionCell.sampleAlert!)}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[var(--surface)] border border-[var(--line)] text-[var(--accent)] hover:text-[var(--text-1)] text-xs font-medium transition-colors cursor-pointer shrink-0 focus-visible:ring"
              >
                <Eye className="w-3 h-3" />
                <span>Chi tiết</span>
              </button>
            )}
          </div>
        ) : (
          <button
            type="button"
            onClick={onOpenOracleBridge}
            className="inline-flex items-center gap-1.5 text-[var(--text-3)] hover:text-[var(--text-1)] text-xs transition-colors cursor-pointer self-start xl:self-auto focus-visible:ring"
          >
            <Database className="w-3.5 h-3.5 text-[var(--ok)]" />
            <span>Oracle Bridge kết nối trực tiếp FREEPDB1</span>
          </button>
        )}
      </div>
    </section>
  );
};
