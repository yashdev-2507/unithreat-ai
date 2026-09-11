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
  const getContextStyle = () => {
    switch (statusContext) {
      case 'healthy':
        return 'border-emerald-200 bg-emerald-50/50 hover:border-emerald-300';
      case 'warning':
        return 'border-amber-200 bg-amber-50/50 hover:border-amber-300';
      case 'error':
        return 'border-rose-200 bg-rose-50/50 hover:border-rose-300';
      case 'info':
        return 'border-blue-200 bg-blue-50/50 hover:border-blue-300';
      case 'neutral':
      default:
        return 'border-[#E5E5E5] bg-[#FFFFFF] hover:border-slate-300';
    }
  };

  const getIconContainerColor = () => {
    switch (statusContext) {
      case 'healthy':
        return 'text-emerald-600 bg-emerald-100 border-emerald-200';
      case 'warning':
        return 'text-amber-600 bg-amber-100 border-amber-200';
      case 'error':
        return 'text-rose-600 bg-rose-100 border-rose-200';
      case 'info':
        return 'text-[#2563EB] bg-[#EFF6FF] border-blue-200';
      case 'neutral':
      default:
        return 'text-slate-600 bg-slate-100 border-slate-200';
    }
  };

  return (
    <div
      className={`flex flex-col justify-between rounded-xl border p-4 shadow-2xs transition-all duration-200 ${getContextStyle()} ${className}`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-[#525252] font-sans truncate">
          {label}
        </span>
        {icon && (
          <div
            className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${getIconContainerColor()}`}
            aria-hidden="true"
          >
            {icon}
          </div>
        )}
      </div>

      <div className="mt-2 flex items-baseline gap-2">
        {typeof value === 'number' || typeof value === 'string' ? (
          <span className="text-2xl sm:text-[32px] font-bold tracking-tight text-[#0A0A0A] font-sans leading-tight">
            {value}
          </span>
        ) : (
          value
        )}
      </div>

      {description && (
        <p className="mt-1 text-xs text-[#737373] font-sans truncate">
          {description}
        </p>
      )}
    </div>
  );
};
