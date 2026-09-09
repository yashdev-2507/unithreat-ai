import type { FC, ReactNode } from 'react';
import {
  Loader2,
  Inbox,
  AlertTriangle,
  HelpCircle,
  WifiOff,
  RefreshCw,
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
      className={`flex flex-col items-center justify-center rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-8 text-center min-h-[180px] ${className}`}
      role={state === 'error' ? 'alert' : 'status'}
    >
      {state === 'loading' && (
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-7 w-7 animate-spin text-cyan-400" aria-hidden="true" />
          <p className="text-xs font-medium text-slate-300 font-mono">
            {loadingMessage}
          </p>
        </div>
      )}

      {state === 'empty' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-slate-800/80 p-3 text-slate-400 border border-slate-700/50">
            <Inbox className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-semibold text-slate-200 mt-1">{emptyTitle}</h3>
          <p className="text-xs text-slate-400 font-sans">{emptyMessage}</p>
        </div>
      )}

      {state === 'error' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-rose-950/80 p-3 text-rose-400 border border-rose-800/50">
            <AlertTriangle className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-semibold text-rose-300 mt-1">Data Error</h3>
          <p className="text-xs text-slate-400 font-sans">{errorMessage}</p>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 focus-ring"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Retry Request</span>
            </button>
          )}
        </div>
      )}

      {state === 'unavailable' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-slate-800/80 p-3 text-slate-400 border border-slate-700/50">
            <HelpCircle className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-semibold text-slate-300 mt-1">
            Telemetry Unavailable
          </h3>
          <p className="text-xs text-slate-400 font-sans">
            The requested data telemetry is not currently defined or supplied by backend.
          </p>
        </div>
      )}

      {state === 'disconnected' && (
        <div className="flex flex-col items-center gap-2 max-w-sm">
          <div className="rounded-full bg-amber-950/80 p-3 text-amber-400 border border-amber-800/50">
            <WifiOff className="h-6 w-6" aria-hidden="true" />
          </div>
          <h3 className="text-sm font-semibold text-amber-300 mt-1">
            Data Source Disconnected
          </h3>
          <p className="text-xs text-slate-400 font-sans">
            Data transport connection between frontend and service is offline.
          </p>
        </div>
      )}
    </div>
  );
};
