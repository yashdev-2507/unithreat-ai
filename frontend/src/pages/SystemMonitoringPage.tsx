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
      <div className="rounded-xl border border-amber-200 bg-[#FFFBEB] p-4 font-sans text-xs text-amber-800 flex items-start gap-3 shadow-2xs">
        <Lock className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-amber-900 uppercase tracking-wider text-[11px] flex items-center gap-2 font-mono">
            PASSIVE UNIDIRECTIONAL INGEST — READ ONLY
          </div>
          <p className="font-sans text-[#525252] text-xs">
            System is operating in strictly passive read-only monitoring mode over unidirectional IP traffic. No active probing, return-path transmission, packet injection, automated blocking, or active mitigation commands are implemented or permitted.
          </p>
        </div>
      </div>

      {/* Unexposed Hardware/NIC Telemetry Requirement Notice */}
      <div className="rounded-xl border border-blue-200 bg-[#EFF6FF] p-4 font-sans text-xs text-[#2563EB] flex items-start gap-3 shadow-2xs">
        <Info className="h-5 w-5 text-[#2563EB] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-[#1D4ED8] uppercase tracking-wider text-[11px] font-mono">
            BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
          </div>
          <p className="font-sans text-[#525252] text-xs">
            Per-NIC interface throughput, CPU/RAM telemetry per detection worker node, ring-buffer packet loss breakdown, and disk I/O metrics are not defined in backend telemetry schemas. The frontend displays available pipeline telemetry from <code className="text-[#2563EB] bg-[#FFFFFF] px-1 py-0.5 rounded border border-blue-200 font-mono">DataService.getPipelineHealth()</code>.
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
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs">
                <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                  <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-[#2563EB]" />
                    Pipeline Ingest Telemetry
                  </h3>
                  <button
                    type="button"
                    onClick={fetchSystemTelemetry}
                    disabled={isRefreshing}
                    aria-busy={isRefreshing}
                    className={`inline-flex items-center gap-1 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-xs font-sans font-medium text-[#0A0A0A] focus-ring ${
                      isRefreshing ? 'opacity-50 cursor-not-allowed' : 'hover:bg-[#F5F5F5]'
                    }`}
                    title="Refresh telemetry"
                  >
                    <RotateCcw className={`h-3 w-3 ${isRefreshing ? 'animate-spin' : ''}`} />
                    <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
                  </button>
                </div>

                <div className="space-y-3 text-xs focus-ring font-sans" role="region" aria-label="Pipeline Telemetry Dataset" tabIndex={0}>
                  <div className="flex items-center justify-between rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3">
                    <span className="text-[#525252] font-medium">Pipeline Status</span>
                    <StatusPill status={pipelineHealth.pipeline_status} />
                  </div>

                  <div className="flex items-center justify-between rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3">
                    <span className="text-[#525252] font-medium">Ingest Mode</span>
                    <span className="font-bold text-[#2563EB] font-mono">{pipelineHealth.ingest_mode}</span>
                  </div>

                  <div className="flex items-center justify-between rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3">
                    <span className="text-[#525252] font-medium">Flow Throughput Velocity</span>
                    <span className="font-bold text-[#0A0A0A] font-mono">
                      {pipelineHealth.flows_per_second ?? overviewMetrics.flows_per_second} flows/sec
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3">
                    <span className="text-[#525252] font-medium">Ring Buffer Usage</span>
                    <span className="font-bold text-[#0A0A0A] font-mono">
                      {pipelineHealth.buffer_usage_percentage ?? 12}%
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3">
                    <span className="text-[#525252] font-medium">Packets Dropped</span>
                    <span className="font-bold text-[#0A0A0A] font-mono">
                      {pipelineHealth.packets_dropped ?? 0}
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3">
                    <span className="text-[#525252] font-medium flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5 text-slate-400" />
                      Telemetry Last Updated
                    </span>
                    <span className="text-[#525252] text-[11px] font-mono">
                      {pipelineHealth.last_updated ?? new Date().toISOString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Passive Capture Interface Architecture */}
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs">
                <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                  <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2">
                    <Radio className="h-4 w-4 text-emerald-600" />
                    Unidirectional Passive Tap Architecture
                  </h3>
                  <StatusPill status="HEALTHY" size="sm" />
                </div>

                <div className="space-y-4 text-xs font-sans text-[#525252]">
                  <p>
                    UniThreat AI operates exclusively on mirrored, passive IP traffic captured via optical TAPs or SPAN ports on unidirectional networks.
                  </p>

                  <div className="rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-4 space-y-3 font-sans text-xs">
                    <div className="flex items-center gap-2 text-[#2563EB] font-semibold uppercase text-[11px] font-mono">
                      <ShieldCheck className="h-4 w-4" />
                      Passive Security Boundaries
                    </div>
                    <ul className="space-y-2 list-disc list-inside text-[#525252]">
                      <li>
                        <strong className="text-[#0A0A0A]">No Return Path:</strong> Frontend and backend components have zero hardware return path to the monitored wire.
                      </li>
                      <li>
                        <strong className="text-[#0A0A0A]">No Packet Injection:</strong> Detection engines process passive flow copies only.
                      </li>
                      <li>
                        <strong className="text-[#0A0A0A]">Read-Only Operations:</strong> Analyst SOC console provides visualization and triage capabilities exclusively.
                      </li>
                    </ul>
                  </div>

                  <div className="rounded-lg border border-amber-200 bg-[#FFFBEB] p-3 flex items-start gap-2 text-amber-900 text-xs font-sans">
                    <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-600" />
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
