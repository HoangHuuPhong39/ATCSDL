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
import { Flame, Eye, Database } from 'lucide-react';
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
      style={{ cursor: isActive ? 'pointer' : 'default' }}
      className="transition-opacity hover:opacity-90"
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
            fill="#ffffff"
            fontSize={12}
            fontWeight={700}
            fontFamily="JetBrains Mono, monospace"
          >
            {payload.intensity} pts
          </text>
          <text
            x={cx}
            y={cy + 11}
            textAnchor="middle"
            dominantBaseline="central"
            fill="#e2e8f0"
            fontSize={9.5}
            fontWeight={600}
            fontFamily="JetBrains Mono, monospace"
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
          fill="#475569"
          fontSize={10.5}
          fontFamily="JetBrains Mono, monospace"
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
    <div className="bg-[#090e17]/95 border border-sky-400/40 rounded-xl p-3.5 shadow-2xl shadow-black/90 text-[11.5px] max-w-xs space-y-2 backdrop-blur-md">
      <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-2">
        <span className="font-mono font-bold text-sky-300 text-[12.5px]">
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

      <div className="pt-1.5 border-t border-white/10 text-[11px] text-slate-300">
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
      className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-4 sm:p-5 shadow-lg shadow-black/30"
    >
      {/* Header & Group Filter */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-4 border-b border-white/5">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-orange-500/15 border border-orange-500/30 flex items-center justify-center text-orange-400 shrink-0">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-[13.5px] sm:text-[14px] font-bold text-slate-100">
              Biểu đồ Nhiệt Cường độ Tấn công theo Thời gian &amp; Tài khoản (Recharts Attack Intensity Heatmap)
            </h2>
            <p className="text-[11px] text-slate-400">
              Trục ngang: Khung thời gian (5 phút) · Trục dọc: Tài khoản CSDL · Nhấn vào ô nhiệt để thanh tra trực tiếp câu lệnh SQL
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <div className="flex items-center bg-[#0b1322] border border-sky-500/20 rounded-lg p-1 gap-1">
            <button
              onClick={() => setGroupFilter('ALL')}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded cursor-pointer transition-colors whitespace-nowrap ${
                groupFilter === 'ALL'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Tất cả Vectơ
            </button>
            <button
              onClick={() => setGroupFilter('DBMS')}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded cursor-pointer transition-colors whitespace-nowrap ${
                groupFilter === 'DBMS'
                  ? 'bg-red-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Kỹ thuật DBMS
            </button>
            <button
              onClick={() => setGroupFilter('SDB')}
              className={`px-2.5 py-1 text-[11px] font-semibold rounded cursor-pointer transition-colors whitespace-nowrap ${
                groupFilter === 'SDB'
                  ? 'bg-amber-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Suy diễn SDB
            </button>
          </div>
        </div>
      </div>

      {/* Recharts 2D Scatter Matrix Heatmap */}
      <div className="mt-4 w-full h-[270px] bg-[#0b1322]/70 border border-white/5 rounded-xl p-2 sm:p-3">
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
              tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
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
              tick={{ fill: '#38bdf8', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}
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

      {/* Bottom Legend & Peak Cell Inspector */}
      <div className="mt-3.5 pt-3 border-t border-white/5 flex flex-col xl:flex-row xl:items-center justify-between gap-3 text-[11.5px]">
        {/* Intensity Scale Legend */}
        <div className="flex items-center gap-4 flex-wrap text-slate-300">
          <span className="text-slate-400 font-semibold">Thang nhiệt độ rủi ro:</span>
          <div className="flex items-center gap-1.5">
            <span className="w-3.5 h-3.5 rounded bg-[#0b1322] border border-sky-500/25 inline-block" />
            <span className="font-mono text-[11px]">0 (An toàn)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3.5 h-3.5 rounded bg-sky-500/70 border border-sky-400 inline-block" />
            <span className="font-mono text-[11px]">1–49 (L1 Warning)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3.5 h-3.5 rounded bg-orange-500/80 border border-orange-400 inline-block" />
            <span className="font-mono text-[11px]">50–79 (L2 Read-Only)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3.5 h-3.5 rounded bg-red-500/85 border border-red-400 inline-block" />
            <span className="font-mono text-[11px]">80–100 (L3 Lock &amp; Kill)</span>
          </div>
        </div>

        {/* Selected / Peak Cell Quick Action */}
        {activeInspectionCell && activeInspectionCell.intensity > 0 ? (
          <div className="flex items-center justify-between sm:justify-end gap-3 bg-[#0b1322] border border-white/5 px-3 py-1.5 rounded-lg">
            <div className="text-[11px] font-mono text-slate-300 truncate max-w-md">
              Điểm nóng: <strong className="text-sky-300">{activeInspectionCell.user}</strong> lúc{' '}
              <span className="text-slate-200 tabular-nums">{activeInspectionCell.timeSlot}</span> ·{' '}
              <strong className="text-red-400 tabular-nums">{activeInspectionCell.intensity}/100 pts</strong> ({activeInspectionCell.topAttack})
            </div>
            {activeInspectionCell.sampleAlert && (
              <button
                onClick={() => onOpenAlertModal(activeInspectionCell.sampleAlert!)}
                className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[#131e33] border border-sky-500/25 text-sky-300 hover:text-white text-[11px] font-semibold transition-colors cursor-pointer shrink-0"
              >
                <Eye className="w-3 h-3" />
                <span>Xem SQL</span>
              </button>
            )}
          </div>
        ) : (
          <button
            onClick={onOpenOracleBridge}
            className="inline-flex items-center gap-1.5 text-sky-300 hover:text-white font-semibold text-[11.5px] cursor-pointer self-start xl:self-auto"
          >
            <Database className="w-3.5 h-3.5" />
            <span>Đang lắng nghe sự kiện mới từ Oracle SQL Developer</span>
          </button>
        )}
      </div>
    </section>
  );
};
