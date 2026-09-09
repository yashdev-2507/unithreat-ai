import { useState, useEffect, useCallback, type FC } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Bell,
  Eye,
  Network,
  Radio,
  Server,
  ShieldAlert,
} from 'lucide-react';
import type { DataService } from '../services/DataService';
import type {
  OverviewMetrics,
  PipelineHealthStatus,
  PaginatedResponse,
  ThreatAlert,
} from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ThreatClassBadge } from '../components/common/ThreatClassBadge';
import { ConfidenceGauge } from '../components/common/ConfidenceGauge';
import { StatusPill } from '../components/common/StatusPill';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

export interface OverviewPageProps {
  dataService: DataService;
}

export const OverviewPage: FC<OverviewPageProps> = ({
  dataService,
}) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [health, setHealth] = useState<PipelineHealthStatus | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<PaginatedResponse<ThreatAlert> | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const fetchOverviewData = useCallback(async () => {
    setDataState('loading');
    try {
      const [overviewData, healthData, alertsData] = await Promise.all([
        dataService.getOverviewMetrics(),
        dataService.getPipelineHealth(),
        dataService.getAlerts({ page: 1, limit: 5 }),
      ]);

      setMetrics(overviewData);
      setHealth(healthData);
      setRecentAlerts(alertsData);
      setDataState('ready');
    } catch {
      setDataState('error');
    }
  }, [dataService]);

  useEffect(() => {
    fetchOverviewData();
  }, [fetchOverviewData]);

  const handleInspectAlert = (alert: ThreatAlert) => {
    setSelectedAlert(alert);
    setIsDrawerOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Executive Overview"
        description="Operational security metrics, system pipeline telemetry, and recent threat alert observations."
      />

      <DataStateWrapper state={dataState} onRetry={fetchOverviewData}>
        {metrics && health && recentAlerts && (
          <div className="space-y-6">
            {/* Section 1: KPI Overview Cards */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              <MetricCard
                label="Total Flows"
                value={metrics.total_flows}
                description="Observed passive flows"
                icon={<Network className="h-4 w-4" />}
                statusContext="neutral"
              />
              <MetricCard
                label="Current Flow Rate"
                value={`${metrics.flows_per_second} /s`}
                description="Flows per second"
                icon={<Radio className="h-4 w-4" />}
                statusContext="info"
              />
              <MetricCard
                label="Total Alerts"
                value={metrics.total_alerts}
                description="Threat alerts generated"
                icon={<Bell className="h-4 w-4" />}
                statusContext="warning"
              />
              <MetricCard
                label="Active Source IPs"
                value={metrics.active_source_ips}
                description="Unique source IP addresses"
                icon={<Activity className="h-4 w-4" />}
                statusContext="neutral"
              />
              <MetricCard
                label="Active Destination IPs"
                value={metrics.active_destination_ips}
                description="Unique destination IP addresses"
                icon={<Activity className="h-4 w-4" />}
                statusContext="neutral"
              />
            </section>

            {/* Section 2: Severity Summary & Threat Class Breakdown */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Severity Summary Card */}
              <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                  <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-rose-400" />
                    Alert Severity Summary
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">
                    Total: {metrics.total_alerts}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 font-mono">
                  <div className="rounded border border-rose-900/40 bg-rose-950/20 p-3">
                    <div className="text-[11px] text-rose-400 font-sans font-medium uppercase">
                      Critical
                    </div>
                    <div className="text-2xl font-bold text-rose-300 mt-1">
                      {metrics.critical_alerts}
                    </div>
                  </div>
                  <div className="rounded border border-orange-900/40 bg-orange-950/20 p-3">
                    <div className="text-[11px] text-orange-400 font-sans font-medium uppercase">
                      High
                    </div>
                    <div className="text-2xl font-bold text-orange-300 mt-1">
                      {metrics.high_alerts}
                    </div>
                  </div>
                  <div className="rounded border border-amber-900/40 bg-amber-950/20 p-3">
                    <div className="text-[11px] text-amber-400 font-sans font-medium uppercase">
                      Medium
                    </div>
                    <div className="text-2xl font-bold text-amber-300 mt-1">
                      {metrics.medium_alerts}
                    </div>
                  </div>
                  <div className="rounded border border-slate-700/50 bg-slate-800/30 p-3">
                    <div className="text-[11px] text-slate-400 font-sans font-medium uppercase">
                      Low
                    </div>
                    <div className="text-2xl font-bold text-slate-300 mt-1">
                      {metrics.low_alerts}
                    </div>
                  </div>
                </div>
              </div>

              {/* Threat-Class Distribution Card */}
              <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4 lg:col-span-2">
                <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                  <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                    <AlertOctagon className="h-4 w-4 text-cyan-400" />
                    Threat Class Distribution
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">Backend Intelligence</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {Object.entries(metrics.threat_counts_by_class).map(([threatClass, count]) => (
                    <div
                      key={threatClass}
                      className="flex items-center justify-between rounded border border-slate-800 bg-slate-900/50 p-2.5"
                    >
                      <ThreatClassBadge threatClass={threatClass} size="sm" />
                      <span className="font-mono text-sm font-bold text-slate-200">
                        {count} {count === 1 ? 'alert' : 'alerts'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Section 3: Ingest Pipeline Telemetry */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <Server className="h-4 w-4 text-cyan-400" />
                  Pipeline Telemetry Status
                </h3>
                <div className="flex items-center gap-2">
                  <StatusPill status={health.pipeline_status} size="sm" />
                  <StatusPill status={health.ingest_mode} size="sm" />
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
                  <span className="text-slate-400 block text-[11px] font-sans">
                    Ingest Rate
                  </span>
                  <span className="text-slate-200 text-sm font-bold mt-0.5 block">
                    {health.flows_per_second !== undefined ? `${health.flows_per_second} /s` : 'N/A'}
                  </span>
                </div>
                <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
                  <span className="text-slate-400 block text-[11px] font-sans">
                    Buffer Usage
                  </span>
                  <span className="text-slate-200 text-sm font-bold mt-0.5 block">
                    {health.buffer_usage_percentage !== undefined ? `${health.buffer_usage_percentage}%` : 'N/A'}
                  </span>
                </div>
                <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
                  <span className="text-slate-400 block text-[11px] font-sans">
                    Packets Dropped
                  </span>
                  <span className="text-slate-200 text-sm font-bold mt-0.5 block">
                    {health.packets_dropped !== undefined ? health.packets_dropped : 'N/A'}
                  </span>
                </div>
                <div className="rounded border border-slate-800 bg-slate-900/40 p-3">
                  <span className="text-slate-400 block text-[11px] font-sans">
                    Last Telemetry Sync
                  </span>
                  <span className="text-slate-200 text-xs font-bold mt-0.5 block truncate">
                    {health.last_updated || 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            {/* Section 4: Recent Alerts Table */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    Recent Threat Observations
                  </h3>
                </div>
                <Link
                  to="/alerts"
                  className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 font-sans hover:underline flex items-center gap-1"
                >
                  View All Alerts ({metrics.total_alerts}) &rarr;
                </Link>
              </div>

              {recentAlerts.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-400 font-sans">
                  No recent threat alerts observed.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring" role="region" aria-label="Recent Threat Observations Dataset" tabIndex={0}>
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-mono text-[11px] border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">Threat Class</th>
                        <th className="py-2.5 px-3">Confidence</th>
                        <th className="py-2.5 px-3">Flow ID</th>
                        <th className="py-2.5 px-3">Source IP</th>
                        <th className="py-2.5 px-3">Destination IP</th>
                        <th className="py-2.5 px-3 text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {recentAlerts.data.map((alert) => (
                        <tr
                          key={`${alert.flow_id}-${alert.timestamp}-${alert.threat_class}`}
                          className="hover:bg-slate-800/30 transition-colors"
                        >
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {alert.timestamp}
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <SeverityBadge severity={alert.severity} size="sm" />
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <ThreatClassBadge threatClass={alert.threat_class} size="sm" />
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <ConfidenceGauge confidence={alert.confidence} size="sm" />
                          </td>
                          <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                            <Link
                              to={`/alerts/flow/${alert.flow_id}`}
                              className="text-cyan-400 hover:underline"
                              title={`Inspect flow ${alert.flow_id}`}
                            >
                              {alert.flow_id}
                            </Link>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {alert.source_ip || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {alert.destination_ip || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => handleInspectAlert(alert)}
                              className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-slate-200 hover:bg-slate-700 focus-ring font-mono"
                              title="Inspect evidence details"
                            >
                              <Eye className="h-3 w-3" />
                              <span>Details</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </DataStateWrapper>

      {/* Alert Detail Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </div>
  );
};
