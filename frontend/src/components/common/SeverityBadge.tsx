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
      ? 'px-2 py-0.5 text-[11px] gap-1 font-sans font-semibold tracking-wide'
      : 'px-2.5 py-1 text-xs gap-1.5 font-sans font-semibold tracking-wide';

  const iconSizes = size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5';

  switch (normalizedSeverity) {
    case 'CRITICAL':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-bold border-rose-200 bg-rose-50 text-rose-700 shadow-2xs select-none ${sizeClasses} ${className}`}
          title="Severity: CRITICAL"
        >
          <span className="h-1.5 w-1.5 rounded-full bg-rose-600 shrink-0" aria-hidden="true" />
          <AlertOctagon className={`${iconSizes} text-rose-600 shrink-0`} aria-hidden="true" />
          <span>CRITICAL</span>
        </span>
      );
    case 'HIGH':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-bold border-orange-200 bg-orange-50 text-orange-700 shadow-2xs select-none ${sizeClasses} ${className}`}
          title="Severity: HIGH"
        >
          <AlertTriangle className={`${iconSizes} text-orange-600 shrink-0`} aria-hidden="true" />
          <span>HIGH</span>
        </span>
      );
    case 'MEDIUM':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-amber-200 bg-amber-50 text-amber-700 select-none ${sizeClasses} ${className}`}
          title="Severity: MEDIUM"
        >
          <AlertCircle className={`${iconSizes} text-amber-600 shrink-0`} aria-hidden="true" />
          <span>MEDIUM</span>
        </span>
      );
    case 'LOW':
    default:
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-slate-200 bg-slate-100 text-slate-700 select-none ${sizeClasses} ${className}`}
          title="Severity: LOW"
        >
          <Info className={`${iconSizes} text-slate-500 shrink-0`} aria-hidden="true" />
          <span>LOW</span>
        </span>
      );
  }
};
