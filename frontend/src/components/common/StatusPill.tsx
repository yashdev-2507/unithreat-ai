import type { FC } from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Wifi,
  WifiOff,
  RefreshCw,
  Radio,
  PlayCircle,
  Activity,
} from 'lucide-react';

export type StatusType =
  | 'HEALTHY'
  | 'DEGRADED'
  | 'ERROR'
  | 'UNAVAILABLE'
  | 'CONNECTED'
  | 'DISCONNECTED'
  | 'RECONNECTING'
  | 'LIVE'
  | 'REPLAY'
  | 'CALIBRATED'
  | 'UNCALIBRATED'
  | 'UNCALIBRATED · RF VOTING';

export interface StatusPillProps {
  status: StatusType | string | null | undefined;
  size?: 'sm' | 'md';
  className?: string;
}

export const StatusPill: FC<StatusPillProps> = ({
  status,
  size = 'md',
  className = '',
}) => {
  const displayStatus = (status || '').toUpperCase() || 'N/A';

  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-[11px] gap-1 font-sans font-semibold tracking-wide'
      : 'px-2.5 py-1 text-xs gap-1.5 font-sans font-semibold tracking-wide';

  const iconSizes = size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5';

  switch (displayStatus) {
    case 'HEALTHY':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-emerald-200 bg-emerald-50 text-emerald-700 select-none ${sizeClasses} ${className}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-600 shrink-0" aria-hidden="true" />
          <CheckCircle2 className={`${iconSizes} text-emerald-600 shrink-0`} aria-hidden="true" />
          <span>HEALTHY</span>
        </span>
      );

    case 'DEGRADED':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-amber-200 bg-amber-50 text-amber-700 select-none ${sizeClasses} ${className}`}
        >
          <AlertTriangle className={`${iconSizes} text-amber-600 shrink-0`} aria-hidden="true" />
          <span>DEGRADED</span>
        </span>
      );

    case 'ERROR':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-rose-200 bg-rose-50 text-rose-700 select-none ${sizeClasses} ${className}`}
        >
          <XCircle className={`${iconSizes} text-rose-600 shrink-0`} aria-hidden="true" />
          <span>ERROR</span>
        </span>
      );

    case 'UNAVAILABLE':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-slate-200 bg-slate-100 text-slate-600 select-none ${sizeClasses} ${className}`}
        >
          <HelpCircle className={`${iconSizes} text-slate-500 shrink-0`} aria-hidden="true" />
          <span>UNAVAILABLE</span>
        </span>
      );

    case 'CONNECTED':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-emerald-200 bg-emerald-50 text-emerald-700 select-none ${sizeClasses} ${className}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-600 shrink-0" aria-hidden="true" />
          <Wifi className={`${iconSizes} text-emerald-600 shrink-0`} aria-hidden="true" />
          <span>CONNECTED</span>
        </span>
      );

    case 'DISCONNECTED':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-rose-200 bg-rose-50 text-rose-700 select-none ${sizeClasses} ${className}`}
        >
          <WifiOff className={`${iconSizes} text-rose-600 shrink-0`} aria-hidden="true" />
          <span>DISCONNECTED</span>
        </span>
      );

    case 'RECONNECTING':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-amber-200 bg-amber-50 text-amber-700 select-none ${sizeClasses} ${className}`}
        >
          <RefreshCw className={`${iconSizes} text-amber-600 animate-spin shrink-0`} aria-hidden="true" />
          <span>RECONNECTING</span>
        </span>
      );

    case 'LIVE':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-emerald-200 bg-emerald-50 text-emerald-700 shadow-2xs select-none ${sizeClasses} ${className}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-600 shrink-0" aria-hidden="true" />
          <Radio className={`${iconSizes} text-emerald-600 shrink-0`} aria-hidden="true" />
          <span>LIVE</span>
        </span>
      );

    case 'REPLAY':
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-blue-200 bg-blue-50 text-[#2563EB] select-none ${sizeClasses} ${className}`}
        >
          <PlayCircle className={`${iconSizes} text-[#2563EB] shrink-0`} aria-hidden="true" />
          <span>REPLAY</span>
        </span>
      );

    case 'CALIBRATED':
      return (
        <span
          className={`inline-flex items-center rounded border font-semibold border-emerald-500/40 bg-emerald-950/30 text-emerald-400 select-none ${sizeClasses} ${className}`}
        >
          <CheckCircle2 className={`${iconSizes} text-emerald-400 shrink-0`} aria-hidden="true" />
          <span>CALIBRATED</span>
        </span>
      );

    case 'UNCALIBRATED':
    case 'UNCALIBRATED · RF VOTING':
      return (
        <span
          className={`inline-flex items-center rounded border font-semibold border-amber-500/40 bg-amber-950/30 text-amber-400 select-none ${sizeClasses} ${className}`}
          title="Random Forest voting proportions; Platt scaling/isotonic calibration not applied"
        >
          <AlertTriangle className={`${iconSizes} text-amber-400 shrink-0`} aria-hidden="true" />
          <span>UNCALIBRATED · RF VOTING</span>
        </span>
      );

    default:
      return (
        <span
          className={`inline-flex items-center rounded-md border font-semibold border-slate-200 bg-slate-100 text-slate-700 select-none ${sizeClasses} ${className}`}
        >
          <Activity className={`${iconSizes} text-slate-500 shrink-0`} aria-hidden="true" />
          <span>{displayStatus}</span>
        </span>
      );
  }
};
