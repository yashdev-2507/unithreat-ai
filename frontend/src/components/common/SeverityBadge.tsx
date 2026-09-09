import type { FC } from 'react';
import { AlertOctagon, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import type { SeverityLevel } from '../../types';

export interface SeverityBadgeProps {
  severity: SeverityLevel;
  size?: 'sm' | 'md';
  className?: string;
}

export const SeverityBadge: FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  className = '',
}) => {
  const normalizedSeverity = (severity || 'LOW').toUpperCase() as SeverityLevel;

  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-[11px] gap-1 font-mono'
      : 'px-2.5 py-1 text-xs gap-1.5 font-mono';

  const iconSizes = size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5';

  switch (normalizedSeverity) {
    case 'CRITICAL':
      return (
        <span
          className={`inline-flex items-center rounded border font-semibold tracking-wide border-rose-500/40 bg-rose-950/30 text-rose-400 select-none ${sizeClasses} ${className}`}
          title="Severity: CRITICAL"
        >
          <AlertOctagon className={`${iconSizes} text-rose-400 shrink-0`} aria-hidden="true" />
          <span>CRITICAL</span>
        </span>
      );
    case 'HIGH':
      return (
        <span
          className={`inline-flex items-center rounded border font-semibold tracking-wide border-orange-500/40 bg-orange-950/30 text-orange-400 select-none ${sizeClasses} ${className}`}
          title="Severity: HIGH"
        >
          <AlertTriangle className={`${iconSizes} text-orange-400 shrink-0`} aria-hidden="true" />
          <span>HIGH</span>
        </span>
      );
    case 'MEDIUM':
      return (
        <span
          className={`inline-flex items-center rounded border font-semibold tracking-wide border-amber-500/40 bg-amber-950/30 text-amber-400 select-none ${sizeClasses} ${className}`}
          title="Severity: MEDIUM"
        >
          <AlertCircle className={`${iconSizes} text-amber-400 shrink-0`} aria-hidden="true" />
          <span>MEDIUM</span>
        </span>
      );
    case 'LOW':
    default:
      return (
        <span
          className={`inline-flex items-center rounded border font-semibold tracking-wide border-slate-600/40 bg-slate-800/40 text-slate-400 select-none ${sizeClasses} ${className}`}
          title="Severity: LOW"
        >
          <Info className={`${iconSizes} text-slate-400 shrink-0`} aria-hidden="true" />
          <span>LOW</span>
        </span>
      );
  }
};
