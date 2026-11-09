import React from 'react';

export type StatusDotVariant = 'ok' | 'warn' | 'danger' | 'accent' | 'neutral';

export interface StatusDotProps {
  status: StatusDotVariant;
  size?: 'sm' | 'md' | 'lg';
  pulse?: boolean;
  className?: string;
  'aria-label'?: string;
}

const colorMap: Record<StatusDotVariant, { dot: string; ping: string }> = {
  ok: {
    dot: 'bg-[var(--ok)]',
    ping: 'bg-[var(--ok)]',
  },
  warn: {
    dot: 'bg-[var(--warn)]',
    ping: 'bg-[var(--warn)]',
  },
  danger: {
    dot: 'bg-[var(--danger)]',
    ping: 'bg-[var(--danger)]',
  },
  accent: {
    dot: 'bg-[var(--accent)]',
    ping: 'bg-[var(--accent)]',
  },
  neutral: {
    dot: 'bg-[var(--text-3)]',
    ping: 'bg-[var(--text-3)]',
  },
};

const sizeMap = {
  sm: 'w-1.5 h-1.5',
  md: 'w-2 h-2',
  lg: 'w-2.5 h-2.5',
};

export const StatusDot: React.FC<StatusDotProps> = ({
  status,
  size = 'md',
  pulse = false,
  className = '',
  'aria-label': ariaLabel,
}) => {
  const colors = colorMap[status] || colorMap.neutral;
  const sizeClass = sizeMap[size];

  return (
    <span
      className={`relative inline-flex items-center justify-center shrink-0 ${sizeClass} ${className}`}
      aria-label={ariaLabel}
      role={ariaLabel ? 'status' : undefined}
    >
      {pulse && (
        <span
          className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${colors.ping}`}
        />
      )}
      <span className={`relative inline-flex rounded-full ${sizeClass} ${colors.dot}`} />
    </span>
  );
};
