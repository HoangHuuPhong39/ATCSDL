import React from 'react';

export interface CardProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: React.ReactNode;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  headerClassName?: string;
  bodyClassName?: string;
  noPadding?: boolean;
}

export const Card: React.FC<CardProps> = ({
  title,
  right,
  children,
  className = '',
  headerClassName = '',
  bodyClassName = '',
  noPadding = false,
  ...props
}) => {
  return (
    <section
      className={`bg-[var(--surface)] border border-[var(--line)] rounded-xl transition-colors ${className}`}
      {...props}
    >
      {(title || right) && (
        <div
          className={`px-4 py-3 border-b border-[var(--line)] flex items-center justify-between gap-3 ${headerClassName}`}
        >
          {title && (
            <h2 className="text-sm font-semibold text-[var(--text-1)] tracking-tight truncate">
              {title}
            </h2>
          )}
          {right && (
            <div className="flex items-center gap-2 shrink-0">
              {right}
            </div>
          )}
        </div>
      )}
      <div className={noPadding ? bodyClassName : `p-4 sm:p-5 ${bodyClassName}`}>
        {children}
      </div>
    </section>
  );
};
