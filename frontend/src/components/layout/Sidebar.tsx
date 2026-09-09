import type { FC, ComponentType } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  AlertTriangle,
  Network,
  ShieldAlert,
  BarChart3,
  Cpu,
  Server,
  X,
} from 'lucide-react';

export interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

interface NavItem {
  label: string;
  path: string;
  icon: ComponentType<{ className?: string }>;
}

const PRIMARY_NAV_ITEMS: NavItem[] = [
  { label: 'Overview', path: '/overview', icon: LayoutDashboard },
  { label: 'Live Alerts', path: '/alerts', icon: AlertTriangle },
  { label: 'Flow Explorer', path: '/flows', icon: Network },
  { label: 'Threat Analysis', path: '/threat-analysis', icon: ShieldAlert },
  { label: 'Detection Analytics', path: '/analytics', icon: BarChart3 },
  { label: 'ML Intelligence', path: '/ml-intelligence', icon: Cpu },
  { label: 'System Monitoring', path: '/system-health', icon: Server },
];

export const Sidebar: FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const handleKeyDown = (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.key === 'Escape' && onClose) {
      e.preventDefault();
      onClose();
    }
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-xs md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-14 bottom-0 left-0 z-40 w-64 border-r border-[var(--panel-border)] bg-[var(--panel-bg)] flex flex-col transition-transform duration-200 ease-in-out md:static md:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Main Navigation"
        onKeyDown={handleKeyDown}
      >
        {/* Mobile Header inside Sidebar */}
        <div className="flex items-center justify-between p-3 border-b border-[var(--panel-border-subtle)] md:hidden">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Navigation Menu
          </span>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 focus-ring"
            aria-label="Close navigation sidebar"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Primary Navigation Links */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          <div className="px-3 pb-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider font-mono">
            Primary Views
          </div>

          {PRIMARY_NAV_ITEMS.map((item) => {
            const IconComponent = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={onClose}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors focus-ring ${
                    isActive
                      ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-800/50 shadow-xs'
                      : 'text-slate-300 hover:text-slate-100 hover:bg-slate-800/50'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <IconComponent
                      className={`h-4 w-4 shrink-0 ${
                        isActive ? 'text-cyan-400' : 'text-slate-400'
                      }`}
                    />
                    <span>{item.label}</span>
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Sidebar Footer — Architectural Badge */}
        <div className="p-3 border-t border-[var(--panel-border-subtle)] bg-slate-950/40">
          <div className="rounded border border-slate-800 bg-slate-900/60 p-2.5 text-xs text-slate-400 font-mono">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1 font-sans">
              System Mode
            </div>
            <div className="text-cyan-400 font-medium truncate">
              UNIDIRECTIONAL / READ ONLY
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};
