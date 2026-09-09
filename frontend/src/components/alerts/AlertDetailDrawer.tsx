import { useEffect, useRef, type FC } from 'react';
import { Link } from 'react-router-dom';
import { X, ExternalLink, ShieldAlert, Cpu, Network, FileText, CheckCircle, Info } from 'lucide-react';
import type { ThreatAlert } from '../../types/alert';
import { SeverityBadge } from '../common/SeverityBadge';
import { ThreatClassBadge } from '../common/ThreatClassBadge';
import { ConfidenceGauge } from '../common/ConfidenceGauge';

export interface AlertDetailDrawerProps {
  alert: ThreatAlert | null;
  isOpen: boolean;
  onClose: () => void;
}

export const AlertDetailDrawer: FC<AlertDetailDrawerProps> = ({
  alert,
  isOpen,
  onClose,
}) => {
  const drawerRef = useRef<HTMLElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (isOpen && alert) {
      // 1. Save currently focused element
      if (document.activeElement && document.activeElement instanceof HTMLElement) {
        previousFocusRef.current = document.activeElement;
      }

      // 2. Move focus into drawer
      const focusTimer = setTimeout(() => {
        if (closeButtonRef.current) {
          closeButtonRef.current.focus();
        } else if (drawerRef.current) {
          drawerRef.current.focus();
        }
      }, 10);

      // 3. Global keyboard listener for Escape & Focus Trapping
      const handleGlobalKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          e.preventDefault();
          onClose();
          return;
        }

        if (e.key === 'Tab' && drawerRef.current) {
          const focusableSelectors =
            'button:not([disabled]), a[href]:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])';

          const rawElements = Array.from(
            drawerRef.current.querySelectorAll<HTMLElement>(focusableSelectors)
          );

          // Filter visible elements (compatible with both browser layout and jsdom)
          const focusableElements = rawElements.filter((el) => {
            if (el.offsetWidth > 0 || el.offsetHeight > 0 || el.getClientRects().length > 0) return true;
            try {
              const style = window.getComputedStyle(el);
              return style.display !== 'none' && style.visibility !== 'hidden';
            } catch {
              return true;
            }
          });

          if (focusableElements.length === 0) {
            e.preventDefault();
            drawerRef.current.focus();
            return;
          }

          const firstElement = focusableElements[0];
          const lastElement = focusableElements[focusableElements.length - 1];

          if (e.shiftKey) {
            // Shift + Tab: if on first element or focus is outside drawer
            if (
              document.activeElement === firstElement ||
              !drawerRef.current.contains(document.activeElement)
            ) {
              e.preventDefault();
              lastElement.focus();
            }
          } else {
            // Tab: if on last element or focus is outside drawer
            if (
              document.activeElement === lastElement ||
              !drawerRef.current.contains(document.activeElement)
            ) {
              e.preventDefault();
              firstElement.focus();
            }
          }
        }
      };

      document.addEventListener('keydown', handleGlobalKeyDown);

      return () => {
        clearTimeout(focusTimer);
        document.removeEventListener('keydown', handleGlobalKeyDown);
        // Restore focus when closing/unmounting
        if (previousFocusRef.current && previousFocusRef.current.isConnected) {
          previousFocusRef.current.focus();
        }
      };
    }
  }, [isOpen, alert, onClose]);

  if (!isOpen || !alert) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-over Drawer Panel */}
      <aside
        ref={drawerRef}
        className="fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col border-l border-[var(--panel-border)] bg-[var(--panel-bg)] text-slate-100 shadow-2xl transition-transform duration-300 ease-in-out focus:outline-none"
        aria-labelledby="alert-drawer-title"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
      >
        {/* Drawer Header */}
        <div className="flex items-center justify-between border-b border-[var(--panel-border)] px-5 py-4 bg-slate-950/40">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded bg-rose-950/80 text-rose-400 border border-rose-800/50">
              <ShieldAlert className="h-4 w-4" />
            </div>
            <div>
              <h2 id="alert-drawer-title" className="text-sm font-bold text-slate-100 tracking-wide font-sans">
                Alert Detail Inspector
              </h2>
              <p className="text-[11px] font-mono text-slate-400">
                Flow: {alert.flow_id}
              </p>
            </div>
          </div>

          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 focus-ring"
            aria-label="Close detail inspector drawer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Drawer Content Viewport */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Key Classification Banner */}
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--panel-border)] bg-slate-900/60 p-3.5">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={alert.severity} size="md" />
              <ThreatClassBadge threatClass={alert.threat_class} size="md" />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-slate-400 font-sans">Confidence:</span>
              <ConfidenceGauge confidence={alert.confidence} size="md" />
            </div>
          </div>

          {/* Network Flow Parameters */}
          <div className="rounded-lg border border-[var(--panel-border)] bg-slate-900/40 p-4 space-y-3">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5 text-cyan-400" />
              Network Flow Metadata
            </h3>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Timestamp</span>
                <span className="text-slate-200">{alert.timestamp}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Flow ID</span>
                <span className="text-cyan-400 font-medium break-all">{alert.flow_id}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Source IP</span>
                <span className="text-slate-200">{alert.source_ip || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Destination IP</span>
                <span className="text-slate-200">{alert.destination_ip || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Protocol</span>
                <span className="text-slate-200">{alert.protocol || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Model Version</span>
                <span className="text-slate-300 flex items-center gap-1">
                  <Cpu className="h-3 w-3 text-slate-400" />
                  {alert.model_version || 'N/A'}
                </span>
              </div>
            </div>
          </div>

          {/* Backend Explanation Callout */}
          {alert.explanation && (
            <div className="rounded-lg border border-cyan-900/40 bg-cyan-950/20 p-3.5">
              <h4 className="text-xs font-semibold text-cyan-300 font-sans mb-1 flex items-center gap-1.5">
                <FileText className="h-3.5 w-3.5 text-cyan-400" />
                Backend Intelligence Explanation
              </h4>
              <p className="text-xs text-slate-300 font-sans leading-relaxed break-words">
                {alert.explanation}
              </p>
            </div>
          )}

          {/* Evidence Signals List */}
          <div className="space-y-2.5">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
              Evidence Signals ({alert.evidence.length})
            </h3>

            {alert.evidence.length === 0 ? (
              <div className="rounded border border-[var(--panel-border)] p-3 text-xs text-slate-400 font-sans">
                No evidence signals attached to this alert.
              </div>
            ) : (
              alert.evidence.map((sig, idx) => (
                <div
                  key={`${sig.signal_name}-${idx}`}
                  className="rounded-lg border border-[var(--panel-border)] bg-slate-900/40 p-3.5 text-xs space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-semibold text-slate-200 break-all">
                      {sig.signal_name}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${
                        sig.direction === 'supporting'
                          ? 'border-amber-800/50 bg-amber-950/30 text-amber-300'
                          : sig.direction === 'contradicting'
                          ? 'border-blue-800/50 bg-blue-950/30 text-blue-300'
                          : 'border-slate-700 bg-slate-800 text-slate-300'
                      }`}
                    >
                      {sig.direction === 'supporting' && <CheckCircle className="h-3 w-3" />}
                      {sig.direction === 'neutral' && <Info className="h-3 w-3" />}
                      {sig.direction}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400">
                    <div>
                      <span>Observed Value: </span>
                      <strong className="text-slate-200 break-all">{sig.value}</strong>
                    </div>
                    <div>
                      <span>Reliability: </span>
                      <strong className="text-slate-200">
                        {Math.round(sig.reliability * 100)}%
                      </strong>
                    </div>
                  </div>

                  {Boolean(sig.supporting_features?.length) && (
                    <div className="pt-1 flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] text-slate-400 font-sans">Features:</span>
                      {sig.supporting_features?.map((feat) => (
                        <span
                          key={feat}
                          className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-cyan-300 border border-slate-700 break-all"
                        >
                          {feat}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Drawer Footer Navigation */}
        <div className="border-t border-[var(--panel-border)] bg-slate-950/60 p-4">
          <Link
            to={`/alerts/flow/${alert.flow_id}`}
            onClick={onClose}
            className="flex w-full items-center justify-center gap-2 rounded-md border border-cyan-800/50 bg-cyan-950/40 px-4 py-2 text-xs font-semibold text-cyan-300 hover:bg-cyan-900/50 focus-ring transition-colors"
          >
            <span>View Full Flow Investigation</span>
            <ExternalLink className="h-4 w-4" />
          </Link>
        </div>
      </aside>
    </>
  );
};
