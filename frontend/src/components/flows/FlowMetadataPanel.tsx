import type { FC } from 'react';
import { Network, Activity, Clock, Server } from 'lucide-react';
import type { PassiveFlow } from '../../types/flow';
import { StatusPill } from '../common/StatusPill';

export interface FlowMetadataPanelProps {
  flow: PassiveFlow;
}

export const FlowMetadataPanel: FC<FlowMetadataPanelProps> = ({ flow }) => {
  return (
    <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
          <Network className="h-4 w-4 text-cyan-400" />
          Passive Flow Metadata
        </h3>
        {flow.direction ? (
          <StatusPill status={flow.direction} size="sm" />
        ) : (
          <span className="text-xs text-slate-400 font-mono">Direction: N/A</span>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 text-xs font-mono">
        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans flex items-center gap-1">
            <Clock className="h-3 w-3 text-slate-400" />
            Timestamp
          </span>
          <span className="text-slate-200 font-bold mt-0.5 block truncate">
            {flow.timestamp}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans">Flow ID</span>
          <span className="text-cyan-400 font-bold mt-0.5 block truncate">
            {flow.flow_id}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans">Source Endpoint</span>
          <span className="text-slate-200 font-bold mt-0.5 block truncate">
            {flow.src_ip}:{flow.src_port !== null && flow.src_port !== undefined ? flow.src_port : 'N/A'}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans">Destination Endpoint</span>
          <span className="text-slate-200 font-bold mt-0.5 block truncate">
            {flow.dst_ip}:{flow.dst_port !== null && flow.dst_port !== undefined ? flow.dst_port : 'N/A'}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans flex items-center gap-1">
            <Server className="h-3 w-3 text-slate-400" />
            Protocol
          </span>
          <span className="text-slate-200 font-bold mt-0.5 block">
            {flow.protocol || 'N/A'}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans flex items-center gap-1">
            <Activity className="h-3 w-3 text-slate-400" />
            Duration
          </span>
          <span className="text-slate-200 font-bold mt-0.5 block">
            {flow.duration !== null && flow.duration !== undefined ? `${flow.duration}s` : 'N/A'}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans">Packet Count</span>
          <span className="text-slate-200 font-bold mt-0.5 block">
            {flow.packet_count !== null && flow.packet_count !== undefined
              ? flow.packet_count.toLocaleString()
              : 'N/A'}
          </span>
        </div>

        <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <span className="text-slate-400 block text-[11px] font-sans">Byte Count</span>
          <span className="text-slate-200 font-bold mt-0.5 block">
            {flow.byte_count !== null && flow.byte_count !== undefined
              ? flow.byte_count.toLocaleString()
              : 'N/A'}
          </span>
        </div>
      </div>

      {flow.tcp_flags && (
        <div className="rounded border border-slate-800 bg-slate-900/40 p-3 text-xs font-mono">
          <span className="text-slate-400 text-[11px] font-sans block">TCP Flags</span>
          <span className="text-amber-300 font-bold mt-0.5 inline-block rounded bg-amber-950/40 border border-amber-800/40 px-2 py-0.5">
            {flow.tcp_flags}
          </span>
        </div>
      )}
    </div>
  );
};
