import type { FC } from 'react';
import { Layers } from 'lucide-react';
import type { NetworkFeatureRecord } from '../../types/feature';

export interface NetworkFeaturesTableProps {
  features: NetworkFeatureRecord[];
}

export const NetworkFeaturesTable: FC<NetworkFeaturesTableProps> = ({ features }) => {
  if (!features || features.length === 0) {
    return (
      <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2 border-b border-[var(--panel-border-subtle)] pb-3">
          <Layers className="h-4 w-4 text-cyan-400" />
          Extracted Network Feature Records
        </h3>
        <p className="py-4 text-center text-xs text-slate-400 font-sans">
          No network feature records observed for this flow.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
          <Layers className="h-4 w-4 text-cyan-400" />
          Extracted Network Feature Records ({features.length})
        </h3>
        <span className="text-xs text-slate-400 font-mono">Backend Telemetry</span>
      </div>

      <div className="space-y-4">
        {features.map((record, idx) => (
          <div
            key={`${record.flow_id}-${record.timestamp}-${idx}`}
            className="rounded-lg border border-slate-800 bg-slate-900/40 p-4 space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2 text-xs font-mono">
              <span className="text-slate-300">
                Timestamp: <strong className="text-slate-100">{record.timestamp}</strong>
              </span>
              <div className="flex items-center gap-3 text-slate-400 text-[11px]">
                {record.entity_id && (
                  <span>
                    Entity: <strong className="text-cyan-300">{record.entity_id}</strong>
                  </span>
                )}
                {record.window_id && (
                  <span>
                    Window: <strong className="text-cyan-300">{record.window_id}</strong>
                  </span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 font-mono text-xs">
              {Object.entries(record.features).map(([featKey, featVal]) => (
                <div
                  key={featKey}
                  className="flex items-center justify-between rounded border border-slate-800/80 bg-slate-950/60 p-2"
                >
                  <span className="text-slate-400 truncate text-[11px] font-sans" title={featKey}>
                    {featKey}
                  </span>
                  <span className="text-cyan-300 font-bold ml-2 font-mono">
                    {featVal === null || featVal === undefined
                      ? 'null'
                      : typeof featVal === 'boolean'
                      ? featVal
                        ? 'true'
                        : 'false'
                      : String(featVal)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
