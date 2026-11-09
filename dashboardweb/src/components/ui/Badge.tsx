import React from 'react';

export type BadgeVariant = 'default' | 'ok' | 'warn' | 'danger' | 'accent';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
  children: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
}

const badgeStyles: Record<BadgeVariant, string> = {
  default:
    'bg-[var(--surface-hover)] text-[var(--text-2)] border border-[var(--line)]',
  ok:
    'bg-[var(--ok-soft)] text-[var(--ok)] border border-[var(--ok)]/30',
  warn:
    'bg-[var(--warn-soft)] text-[var(--warn)] border border-[var(--warn)]/30',
  danger:
    'bg-[var(--danger-soft)] text-[var(--danger)] border border-[var(--danger)]/30',
  accent:
    'bg-[var(--accent-soft)] text-[var(--accent)] border border-[var(--accent)]/30',
};

export const Badge: React.FC<BadgeProps> = ({
  variant = 'default',
  children,
  icon,
  className = '',
  ...props
}) => {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium whitespace-nowrap leading-none transition-colors ${badgeStyles[variant]} ${className}`}
      {...props}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </span>
  );
};
