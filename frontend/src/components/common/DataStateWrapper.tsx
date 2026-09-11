import type { FC, ReactNode } from 'react';
import {
  Inbox,
  AlertTriangle,
  HelpCircle,
  WifiOff,
  RefreshCw,
  Loader2,
} from 'lucide-react';

export type DataState =
  | 'loading'
  | 'empty'
  | 'error'
  | 'unavailable'
  | 'disconnected'
  | 'ready';

export interface DataStateWrapperProps {
  state: DataState;
  children?: ReactNode;
  loadingMessage?: string;
  emptyTitle?: string;
  emptyMessage?: string;
  errorMessage?: string;
  onRetry?: () => void;
  className?: string;
}

export const DataStateWrapper: FC<DataStateWrapperProps> = ({
  state,
  children,
  loadingMessage = 'Loading backend data observations...',
  emptyTitle = 'No Data Available',
  emptyMessage = 'No matching network observations found for the selected criteria.',
  errorMessage = 'Unable to load data from backend service.',
  onRetry,
  className = '',
}) => {
  if (state === 'ready') {
    return <>{children}</>;
  }

  return (
    <div
      className={`flex flex-col items-center justify-center rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-8 text-center min-h-[200px] ${className}`}
      role={state === 'error' ? 'alert' : 'status'}
    >
      {state === 'loading' && (
        <div className="flex flex-col items-center gap-3">
          <div className="flex items-center justify-center p-2">
            <Loader2 className="h-7 w-7 animate-spin text-[#2563EB]" aria-hidden="true" />
          </div>
          <p className="text-xs font-semibold text-[#2563EB] font-mono tracking-wider uppercase">
            {loadingMessage}
          </p>
        </div>
      )}

      {state === 'empty' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-slate-100 p-3 text-slate-500 border border-slate-200">
            <Inbox className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-bold text-[#0A0A0A] mt-1 font-sans">{emptyTitle}</h3>
          <p className="text-xs text-[#525252] font-sans leading-relaxed">{emptyMessage}</p>
        </div>
      )}

      {state === 'error' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-rose-50 p-3 text-rose-600 border border-rose-200 shadow-2xs">
            <AlertTriangle className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-bold text-rose-700 mt-1 font-sans">Data Error</h3>
          <p className="text-xs text-[#525252] font-sans leading-relaxed">{errorMessage}</p>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1.5 text-xs font-mono font-semibold text-[#0A0A0A] hover:bg-[#F5F5F5] focus-ring transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Retry Request</span>
            </button>
          )}
        </div>
      )}

      {state === 'unavailable' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-slate-100 p-3 text-slate-500 border border-slate-200">
            <HelpCircle className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-bold text-[#0A0A0A] mt-1 font-sans">
            Telemetry Unavailable
          </h3>
          <p className="text-xs text-[#525252] font-sans leading-relaxed">
            The requested data telemetry is not currently defined or supplied by backend.
          </p>
        </div>
      )}

      {state === 'disconnected' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-amber-50 p-3 text-amber-600 border border-amber-200 shadow-2xs">
            <WifiOff className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-bold text-amber-700 mt-1 font-sans">
            Data Source Disconnected
          </h3>
          <p className="text-xs text-[#525252] font-sans leading-relaxed">
            Data transport connection between frontend and service is offline.
          </p>
        </div>
      )}
    </div>
  );
};
