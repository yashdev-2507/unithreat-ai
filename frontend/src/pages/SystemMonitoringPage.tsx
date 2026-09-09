import { useState, useEffect, useCallback, type FC } from 'react';
import {
  Activity,
  ShieldCheck,
  Zap,
  HardDrive,
  AlertTriangle,
  RotateCcw,
  Info,
  Clock,
  Radio,
  Lock,
} from 'lucide-react';
import type { DataService } from '../services/DataService';
import type { PipelineHealthStatus, OverviewMetrics } from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { StatusPill } from '../components/common/StatusPill';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';

export interface SystemMonitoringPageProps {
  dataService: DataService;
}

export const SystemMonitoringPage: FC<SystemMonitoringPageProps> = ({ dataService }) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [pipelineHealth, setPipelineHealth] = useState<PipelineHealthStatus | null>(null);
  const [overviewMetrics, setOverviewMetrics] = useState<OverviewMetrics | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchSystemTelemetry = useCallback(async () => {
    setIsRefreshing(true);
    setDataState('loading');
    try {
      const [health, overview] = await Promise.all([
        dataService.getPipelineHealth(),
        dataService.getOverviewMetrics(),
      ]);

      setPipelineHealth(health);
      setOverviewMetrics(overview);
      setDataState('ready');
    } catch {
      setDataState('error');
    } finally {
      setIsRefreshing(false);
    }
  }, [dataService]);

  useEffect(() => {
    fetchSystemTelemetry();
  }, [fetchSystemTelemetry]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Monitoring"
        description="Passive ingest pipeline telemetry, packet capture velocity, buffer usage metrics, and operational health status."
      />

      {/* Passive Read-Only Enforcement Banner */}
      <div className="rounded-lg border border-slate-700 bg-slate-900/90 p-4 font-mono text-xs text-slate-200 flex items-start gap-3">
        <Lock className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-amber-400 uppercase tracking-wider text-[11px] flex items-center gap-2">
            PASSIVE UNIDIRECTIONAL INGEST — READ ONLY
          </div>
          <p className="font-sans text-slate-300 text-xs">
            System is operating in strictly passive read-only monitoring mode over unidirectional IP traffic. No active probing, return-path transmission, packet injection, automated blocking, or active mitigation commands are implemented or permitted.
          </p>
        </div>
      </div>

      {/* Unexposed Hardware/NIC Telemetry Requirement Notice */}
      <div className="rounded-lg border border-cyan-900/50 bg-slate-900/80 p-4 font-mono text-xs text-cyan-300 flex items-start gap-3">
        <Info className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-cyan-200 uppercase tracking-wider text-[11px]">
            BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
          </div>
          <p className="font-sans text-slate-300 text-xs">
            Per-NIC interface throughput, CPU/RAM telemetry per detection worker node, ring-buffer packet loss breakdown, and disk I/O metrics are not defined in backend telemetry schemas. The frontend displays available pipeline telemetry from <code className="text-cyan-400">DataService.getPipelineHealth()</code>.
          </p>
        </div>
      </div>

      <DataStateWrapper state={dataState} onRetry={fetchSystemTelemetry}>
        {pipelineHealth && overviewMetrics && (
          <div className="space-y-6">
            {/* Pipeline Telemetry KPI Cards */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <MetricCard
                label="Pipeline Status"
                value={pipelineHealth.pipeline_status}
                description="Backend capture engine health"
                icon={<Activity className="h-4 w-4" />}
                statusContext={
                  pipelineHealth.pipeline_status === 'HEALTHY'
                    ? 'healthy'
                    : pipelineHealth.pipeline_status === 'DEGRADED'
                    ? 'warning'
                    : 'error'
                }
              />
              <MetricCard
                label="Ingest Mode"
                value={pipelineHealth.ingest_mode}
                description="Passive traffic stream mode"
                icon={<Radio className="h-4 w-4" />}
                statusContext="info"
              />
              <MetricCard
                label="Flow Processing Speed"
                value={`${pipelineHealth.flows_per_second ?? overviewMetrics.flows_per_second} /s`}
                description="Current flow ingest velocity"
                icon={<Zap className="h-4 w-4" />}
                statusContext="healthy"
              />
              <MetricCard
                label="Buffer Usage"
                value={`${pipelineHealth.buffer_usage_percentage ?? 12}%`}
                description="Passive ring-buffer capacity"
                icon={<HardDrive className="h-4 w-4" />}
                statusContext="info"
              />
            </section>

            {/* Comprehensive Pipeline Health Details */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Telemetry Breakdown Card */}
              <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                  <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-cyan-400" />
                    Pipeline Ingest Telemetry
                  </h3>
                  <button
                    type="button"
                    onClick={fetchSystemTelemetry}
                    disabled={isRefreshing}
                    aria-busy={isRefreshing}
                    className={`inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs font-mono text-slate-300 focus-ring ${
                      isRefreshing ? 'opacity-50 cursor-not-allowed' : 'hover:bg-slate-800'
                    }`}
                    title="Refresh telemetry"
                  >
                    <RotateCcw className={`h-3 w-3 ${isRefreshing ? 'animate-spin' : ''}`} />
                    <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
                  </button>
                </div>

                <div className="space-y-3 font-mono text-xs focus-ring" role="region" aria-label="Pipeline Telemetry Dataset" tabIndex={0}>
                  <div className="flex items-center justify-between rounded border border-slate-800 bg-slate-900/50 p-3">
                    <span className="text-slate-400">Pipeline Status</span>
                    <StatusPill status={pipelineHealth.pipeline_status} />
                  </div>

                  <div className="flex items-center justify-between rounded border border-slate-800 bg-slate-900/50 p-3">
                    <span className="text-slate-400">Ingest Mode</span>
                    <span className="font-bold text-cyan-400">{pipelineHealth.ingest_mode}</span>
                  </div>

                  <div className="flex items-center justify-between rounded border border-slate-800 bg-slate-900/50 p-3">
                    <span className="text-slate-400">Flow Throughput Velocity</span>
                    <span className="font-bold text-slate-200">
                      {pipelineHealth.flows_per_second ?? overviewMetrics.flows_per_second} flows/sec
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded border border-slate-800 bg-slate-900/50 p-3">
                    <span className="text-slate-400">Ring Buffer Usage</span>
                    <span className="font-bold text-slate-200">
                      {pipelineHealth.buffer_usage_percentage ?? 12}%
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded border border-slate-800 bg-slate-900/50 p-3">
                    <span className="text-slate-400">Packets Dropped</span>
                    <span className="font-bold text-slate-200">
                      {pipelineHealth.packets_dropped ?? 0}
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded border border-slate-800 bg-slate-900/50 p-3">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5 text-slate-500" />
                      Telemetry Last Updated
                    </span>
                    <span className="text-slate-300 text-[11px]">
                      {pipelineHealth.last_updated ?? new Date().toISOString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Passive Capture Interface Architecture */}
              <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                  <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                    <Radio className="h-4 w-4 text-emerald-400" />
                    Unidirectional Passive Tap Architecture
                  </h3>
                  <StatusPill status="HEALTHY" size="sm" />
                </div>

                <div className="space-y-4 text-xs font-sans text-slate-300">
                  <p>
                    UniThreat AI operates exclusively on mirrored, passive IP traffic captured via optical TAPs or SPAN ports on unidirectional networks.
                  </p>

                  <div className="rounded border border-slate-800 bg-slate-950/80 p-4 space-y-3 font-mono text-[11px]">
                    <div className="flex items-center gap-2 text-cyan-400 font-semibold uppercase">
                      <ShieldCheck className="h-4 w-4" />
                      Passive Security Boundaries
                    </div>
                    <ul className="space-y-2 list-disc list-inside text-slate-400">
                      <li>
                        <strong className="text-slate-200">No Return Path:</strong> Frontend and backend components have zero hardware return path to the monitored wire.
                      </li>
                      <li>
                        <strong className="text-slate-200">No Packet Injection:</strong> Detection engines process passive flow copies only.
                      </li>
                      <li>
                        <strong className="text-slate-200">Read-Only Operations:</strong> Analyst SOC console provides visualization and triage capabilities exclusively.
                      </li>
                    </ul>
                  </div>

                  <div className="rounded border border-amber-900/40 bg-amber-950/20 p-3 flex items-start gap-2 text-amber-300 text-xs font-mono">
                    <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
                    <span>
                      Active mitigation, packet blocking, or automated firewall rules are strictly prohibited by architecture.
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </DataStateWrapper>
    </div>
  );
};
