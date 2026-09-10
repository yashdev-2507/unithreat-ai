import type { FC } from 'react';
import { Layers } from 'lucide-react';
import type { NetworkFeatureRecord } from '../../types/feature';

export interface NetworkFeaturesTableProps {
  features: NetworkFeatureRecord[];
}

export const NetworkFeaturesTable: FC<NetworkFeaturesTableProps> = ({ features }) => {
  if (!features || features.length === 0) {
    return (
      <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-3 shadow-2xs">
        <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2 border-b border-[#E5E5E5] pb-3">
          <Layers className="h-4 w-4 text-[#2563EB]" />
          Extracted Network Feature Records
        </h3>
        <p className="py-4 text-center text-xs text-[#525252] font-sans">
          No network feature records observed for this flow.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs">
      <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
        <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2">
          <Layers className="h-4 w-4 text-[#2563EB]" />
          Extracted Network Feature Records ({features.length})
        </h3>
        <span className="text-xs text-slate-500 font-mono">Backend Telemetry</span>
      </div>

      <div className="space-y-4">
        {features.map((record, idx) => (
          <div
            key={`${record.flow_id}-${record.timestamp}-${idx}`}
            className="rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-4 space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#E5E5E5] pb-2 text-xs font-mono">
              <span className="text-[#525252]">
                Timestamp: <strong className="text-[#0A0A0A]">{record.timestamp}</strong>
              </span>
              <div className="flex items-center gap-3 text-slate-500 text-[11px]">
                {record.entity_id && (
                  <span>
                    Entity: <strong className="text-[#2563EB]">{record.entity_id}</strong>
                  </span>
                )}
                {record.window_id && (
                  <span>
                    Window: <strong className="text-[#2563EB]">{record.window_id}</strong>
                  </span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 font-mono text-xs">
              {Object.entries(record.features).map(([featKey, featVal]) => (
                <div
                  key={featKey}
                  className="flex items-center justify-between rounded border border-[#E5E5E5] bg-[#FFFFFF] p-2"
                >
                  <span className="text-slate-600 truncate text-[11px] font-sans" title={featKey}>
                    {featKey}
                  </span>
                  <span className="text-[#2563EB] font-bold ml-2 font-mono">
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
