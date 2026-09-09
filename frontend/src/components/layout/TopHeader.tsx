import { useState, useEffect, type FC } from 'react';
import { Menu, X, ShieldAlert, Clock, Activity } from 'lucide-react';

export interface TopHeaderProps {
  onToggleSidebar?: () => void;
  isSidebarOpen?: boolean;
}

export const TopHeader: FC<TopHeaderProps> = ({
  onToggleSidebar,
  isSidebarOpen = false,
}) => {
  const [timeString, setTimeString] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeString(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="sticky top-0 z-30 flex h-14 w-full items-center justify-between border-b border-[var(--panel-border)] bg-[var(--panel-bg)] px-4 text-slate-200 select-none">
      {/* Left section: Mobile Toggle & Brand */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onToggleSidebar}
          className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 focus-ring md:hidden"
          aria-label={isSidebarOpen ? 'Close navigation sidebar' : 'Open navigation sidebar'}
          aria-expanded={isSidebarOpen}
        >
          {isSidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>

        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div className="flex flex-col leading-none">
            <span className="font-bold tracking-wider text-slate-100 text-sm uppercase">
              UniThreat<span className="text-cyan-400 ml-0.5">AI</span>
            </span>
            <span className="text-[10px] text-slate-400 tracking-wider font-mono">
              SOC CONSOLE
            </span>
          </div>
        </div>
      </div>

      {/* Center section: Architectural Indicators */}
      <div className="hidden lg:flex items-center gap-2">
        {/* Passive Ingest Indicator */}
        <div className="inline-flex items-center gap-1.5 rounded border border-cyan-800/40 bg-cyan-950/30 px-2.5 py-1 text-xs font-medium text-cyan-300">
          <span className="h-2 w-2 rounded-full bg-cyan-500"></span>
          <span>PASSIVE UNIDIRECTIONAL INGEST — READ ONLY</span>
        </div>

        {/* Mock Environment Banner */}
        <div className="inline-flex items-center gap-1.5 rounded border border-amber-800/40 bg-amber-950/30 px-2.5 py-1 text-xs font-medium text-amber-300">
          <span>DEMO / REPLAY DATA — SIMULATED ENVIRONMENT</span>
        </div>
      </div>

      {/* Right section: Telemetry Placeholder & UTC Clock */}
      <div className="flex items-center gap-3">
        {/* Neutral Telemetry Status Placeholder */}
        <div className="hidden sm:inline-flex items-center gap-1.5 rounded border border-slate-700/50 bg-slate-800/30 px-2.5 py-1 text-xs text-slate-400 font-mono">
          <Activity className="h-3.5 w-3.5 text-slate-400" />
          <span>PIPELINE STATUS — UNAVAILABLE</span>
        </div>

        {/* Live Clock */}
        <div className="flex items-center gap-1.5 text-xs text-slate-300 font-mono bg-slate-900/60 border border-slate-800 px-2.5 py-1 rounded">
          <Clock className="h-3.5 w-3.5 text-slate-400" />
          <span>{timeString || 'UTC CLOCK'}</span>
        </div>
      </div>
    </header>
  );
};
