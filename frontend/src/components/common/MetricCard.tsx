import type { FC, ReactNode } from 'react';

export interface MetricCardProps {
  label: string;
  value: string | number | ReactNode;
  description?: string;
  icon?: ReactNode;
  statusContext?: 'healthy' | 'warning' | 'error' | 'info' | 'neutral';
  className?: string;
}

export const MetricCard: FC<MetricCardProps> = ({
  label,
  value,
  description,
  icon,
  statusContext = 'neutral',
  className = '',
}) => {
  const getContextBorder = () => {
    switch (statusContext) {
      case 'healthy':
        return 'border-emerald-800/40 bg-emerald-950/10';
      case 'warning':
        return 'border-amber-800/40 bg-amber-950/10';
      case 'error':
        return 'border-rose-800/40 bg-rose-950/10';
      case 'info':
        return 'border-cyan-800/40 bg-cyan-950/10';
      case 'neutral':
      default:
        return 'border-[var(--panel-border)] bg-[var(--panel-bg)]';
    }
  };

  const getIconContainerColor = () => {
    switch (statusContext) {
      case 'healthy':
        return 'text-emerald-400 bg-emerald-950/60 border-emerald-800/50';
      case 'warning':
        return 'text-amber-400 bg-amber-950/60 border-amber-800/50';
      case 'error':
        return 'text-rose-400 bg-rose-950/60 border-rose-800/50';
      case 'info':
        return 'text-cyan-400 bg-cyan-950/60 border-cyan-800/50';
      case 'neutral':
      default:
        return 'text-slate-400 bg-slate-800/60 border-slate-700/50';
    }
  };

  return (
    <div
      className={`flex flex-col justify-between rounded-lg border p-4 shadow-xs transition-colors ${getContextBorder()} ${className}`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-sans truncate">
          {label}
        </span>
        {icon && (
          <div
            className={`flex h-7 w-7 shrink-0 items-center justify-center rounded border ${getIconContainerColor()}`}
            aria-hidden="true"
          >
            {icon}
          </div>
        )}
      </div>

      <div className="mt-2 flex items-baseline gap-2">
        {typeof value === 'number' || typeof value === 'string' ? (
          <span className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
            {value}
          </span>
        ) : (
          value
        )}
      </div>

      {description && (
        <p className="mt-1 text-xs text-slate-400 font-sans truncate">
          {description}
        </p>
      )}
    </div>
  );
};
