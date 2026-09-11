import { useState, useEffect, type FC, type ComponentType } from 'react';
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
  Lock,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

export interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

interface NavItem {
  label: string;
  path: string;
  icon: ComponentType<{ className?: string }>;
  badge?: string;
}

interface NavGroup {
  groupLabel: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    groupLabel: 'OPERATIONS',
    items: [
      { label: 'Overview', path: '/overview', icon: LayoutDashboard },
      { label: 'Live Alerts', path: '/alerts', icon: AlertTriangle, badge: '10' },
      { label: 'Flow Explorer', path: '/flows', icon: Network, badge: '12' },
    ],
  },
  {
    groupLabel: 'ANALYSIS',
    items: [
      { label: 'Threat Analysis', path: '/threat-analysis', icon: ShieldAlert },
      { label: 'Detection Analytics', path: '/analytics', icon: BarChart3 },
      { label: 'ML Intelligence', path: '/ml-intelligence', icon: Cpu },
    ],
  },
  {
    groupLabel: 'SYSTEM',
    items: [
      { label: 'System Monitoring', path: '/system-health', icon: Server },
    ],
  },
];

export const Sidebar: FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const [isCollapsed, setIsCollapsed] = useState<boolean>(false);
  const [isHovered, setIsHovered] = useState<boolean>(false);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState<boolean>(false);

  useEffect(() => {
    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
      setPrefersReducedMotion(mediaQuery.matches);

      const handleChange = () => setPrefersReducedMotion(mediaQuery.matches);
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    }
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.key === 'Escape' && onClose) {
      e.preventDefault();
      onClose();
    }
  };

  const isExpandedDesktop = !isCollapsed || isHovered;

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/40 backdrop-blur-xs md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        className={`fixed top-14 bottom-0 left-0 z-40 border-r border-[#E5E5E5] bg-[#FFFFFF] flex flex-col ${
          prefersReducedMotion ? '' : 'transition-all duration-200 ease-in-out'
        } md:static md:translate-x-0 ${
          isOpen ? 'translate-x-0 w-64' : '-translate-x-full md:translate-x-0'
        } ${isExpandedDesktop ? 'md:w-60' : 'md:w-16'}`}
        aria-label="Main Navigation"
        onKeyDown={handleKeyDown}
      >
        {/* Mobile Header inside Sidebar */}
        <div className="flex items-center justify-between p-3 border-b border-[#E5E5E5] md:hidden">
          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">
            SOC Navigation
          </span>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-md text-slate-500 hover:text-[#0A0A0A] hover:bg-[#F5F5F5] focus-ring"
            aria-label="Close navigation sidebar"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Desktop Header / Collapse Toggle */}
        <div className="hidden md:flex items-center justify-between p-3 border-b border-[#E5E5E5]">
          {isExpandedDesktop ? (
            <>
              <div className="flex items-center gap-2.5">
                <div className="flex h-7 w-7 items-center justify-center rounded-md bg-[#EFF6FF] text-[#2563EB] border border-blue-200 shadow-2xs">
                  <ShieldAlert className="h-4 w-4" />
                </div>
                <div className="flex flex-col leading-none">
                  <span className="font-extrabold tracking-wider text-[#0A0A0A] text-xs uppercase font-sans">
                    UniThreat<span className="text-[#2563EB] ml-0.5">AI</span>
                  </span>
                  <span className="text-[10px] text-[#737373] tracking-wider font-sans font-semibold">
                    SOC CONSOLE
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsCollapsed(!isCollapsed)}
                className="p-1 rounded-md text-slate-500 hover:text-[#0A0A0A] hover:bg-[#F5F5F5] focus-ring"
                title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              >
                <ChevronLeft className="h-4 w-4 text-[#2563EB]" />
              </button>
            </>
          ) : (
            <div className="w-full flex justify-center">
              <button
                type="button"
                onClick={() => setIsCollapsed(!isCollapsed)}
                className="flex h-8 w-8 items-center justify-center rounded-md bg-[#EFF6FF] text-[#2563EB] border border-blue-200 hover:bg-blue-100 focus-ring"
                title="Expand sidebar"
                aria-label="Expand sidebar"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {/* Primary Grouped Navigation Links */}
        <nav className="flex-1 overflow-y-auto px-2.5 py-4 space-y-5">
          {NAV_GROUPS.map((group) => (
            <div key={group.groupLabel} className="space-y-1">
              {isExpandedDesktop ? (
                <div className="px-2.5 pb-1 text-[11px] font-bold text-[#737373] uppercase tracking-wider font-sans">
                  {group.groupLabel}
                </div>
              ) : (
                <div className="h-2" />
              )}

              {group.items.map((item) => {
                const IconComponent = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    onClick={onClose}
                    className={({ isActive }) =>
                      `group relative flex items-center ${
                        isExpandedDesktop ? 'justify-between px-3' : 'justify-center px-0'
                      } py-2 rounded-lg text-sm font-medium font-sans ${
                        prefersReducedMotion ? '' : 'transition-all duration-150'
                      } focus-ring ${
                        isActive
                          ? 'bg-[#EFF6FF] text-[#2563EB] border border-blue-200 shadow-2xs font-semibold'
                          : 'text-[#525252] hover:text-[#0A0A0A] hover:bg-[#F5F5F5]'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <div className="flex items-center gap-2.5 min-w-0">
                          <IconComponent
                            className={`h-4 w-4 shrink-0 transition-colors ${
                              isActive ? 'text-[#2563EB]' : 'text-slate-400 group-hover:text-slate-700'
                            }`}
                          />
                          {isExpandedDesktop && <span className="truncate">{item.label}</span>}
                        </div>

                        {isExpandedDesktop && item.badge && (
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                              isActive
                                ? 'bg-blue-100 text-[#2563EB] border border-blue-300 font-bold'
                                : 'bg-[#F8FAFC] text-slate-500 border border-[#E5E5E5]'
                            }`}
                          >
                            {item.badge}
                          </span>
                        )}

                        {/* Collapsed Tooltip */}
                        {!isExpandedDesktop && (
                          <div className="absolute left-full ml-2.5 px-2.5 py-1 bg-[#FFFFFF] text-[#0A0A0A] text-xs font-sans font-medium rounded border border-[#E5E5E5] shadow-md whitespace-nowrap opacity-0 group-hover:opacity-100 group-focus:opacity-100 pointer-events-none transition-opacity duration-150 z-50">
                            {item.label}
                          </div>
                        )}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>

        {/* Sidebar Footer — Architectural Security Badge */}
        <div className="p-3 border-t border-[#E5E5E5] bg-[#F8FAFC]">
          {isExpandedDesktop ? (
            <div className="rounded-md border border-[#E5E5E5] bg-[#FFFFFF] p-2.5 text-xs text-slate-600 font-mono space-y-1 shadow-2xs">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider font-sans flex items-center gap-1.5 font-semibold">
                <Lock className="h-3 w-3 text-[#2563EB]" />
                <span>Tap Architecture</span>
              </div>
              <div className="text-[#2563EB] font-semibold text-[11px] truncate">
                UNIDIRECTIONAL / READ ONLY
              </div>
            </div>
          ) : (
            <div className="flex justify-center">
              <div
                className="group relative flex h-8 w-8 items-center justify-center rounded-md border border-[#E5E5E5] bg-[#FFFFFF] text-[#2563EB] cursor-help shadow-2xs"
                title="Unidirectional / Read Only"
              >
                <Lock className="h-4 w-4" />
                <div className="absolute left-full ml-2.5 px-2.5 py-1 bg-[#FFFFFF] text-[#0A0A0A] text-xs font-mono font-medium rounded border border-[#E5E5E5] shadow-md whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-150 z-50">
                  Unidirectional / Read Only
                </div>
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
