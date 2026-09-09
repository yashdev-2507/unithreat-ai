import { useState, useEffect, useCallback, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  AlertOctagon,
  Eye,
  Filter,
  RotateCcw,
  Search,
  Activity,
  Bell,
} from 'lucide-react';
import type { DataService } from '../services/DataService';
import type {
  OverviewMetrics,
  PaginatedResponse,
  ThreatAlert,
  SeverityLevel,
  AlertQueryParams,
} from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ThreatClassBadge } from '../components/common/ThreatClassBadge';
import { ConfidenceGauge } from '../components/common/ConfidenceGauge';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';
import { PaginationControls } from '../components/common/PaginationControls';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

export interface ThreatAnalysisPageProps {
  dataService: DataService;
}

const SEVERITY_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const THREAT_CLASS_OPTIONS = [
  'ALL',
  'Volumetric / Protocol DDoS',
  'Botnet C2 Beaconing',
  'DGA / DNS Tunneling',
  'Malware Inside Encrypted Sessions',
  'Reconnaissance / Port Scanning',
  'Data Exfiltration',
];

export const ThreatAnalysisPage: FC<ThreatAnalysisPageProps> = ({ dataService }) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [alertsResponse, setAlertsResponse] = useState<PaginatedResponse<ThreatAlert> | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  // Filters state
  const [page, setPage] = useState<number>(1);
  const [limit] = useState<number>(10);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [threatClassFilter, setThreatClassFilter] = useState<string>('ALL');
  const [searchIpInput, setSearchIpInput] = useState<string>('');

  const fetchThreatAnalysisData = useCallback(async () => {
    setDataState('loading');
    try {
      const queryParams: AlertQueryParams = {
        page,
        limit,
      };

      if (severityFilter !== 'ALL') {
        queryParams.severity = severityFilter as SeverityLevel;
      }

      if (threatClassFilter !== 'ALL') {
        queryParams.threat_class = threatClassFilter;
      }

      if (searchIpInput.trim()) {
        queryParams.search_ip = searchIpInput.trim();
      }

      const [overviewData, alertsData] = await Promise.all([
        dataService.getOverviewMetrics(),
        dataService.getAlerts(queryParams),
      ]);

      setMetrics(overviewData);
      setAlertsResponse(alertsData);

      if (alertsData.data.length === 0 && overviewData.total_alerts === 0) {
        setDataState('empty');
      } else {
        setDataState('ready');
      }
    } catch {
      setDataState('error');
    }
  }, [dataService, page, limit, severityFilter, threatClassFilter, searchIpInput]);

  useEffect(() => {
    fetchThreatAnalysisData();
  }, [fetchThreatAnalysisData]);

  const handleFilterChange = (setter: (val: string) => void, val: string) => {
    setter(val);
    setPage(1); // Reset to page 1 on filter change
  };

  const handleResetFilters = () => {
    setSeverityFilter('ALL');
    setThreatClassFilter('ALL');
    setSearchIpInput('');
    setPage(1);
  };

  const handleInspectAlert = (alert: ThreatAlert) => {
    setSelectedAlert(alert);
    setIsDrawerOpen(true);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Analysis"
        description="High-level security intelligence view summarizing authoritative backend alert telemetry, threat class distributions, and severity metrics."
      />

      <DataStateWrapper state={dataState} onRetry={fetchThreatAnalysisData}>
        {metrics && alertsResponse && (
          <div className="space-y-6">
            {/* KPI Summary Cards */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <MetricCard
                label="Total Threat Alerts"
                value={metrics.total_alerts}
                description="Authoritative backend alerts"
                icon={<Bell className="h-4 w-4" />}
                statusContext="warning"
              />
              <MetricCard
                label="Critical Severity"
                value={metrics.critical_alerts}
                description="Immediate priority alerts"
                icon={<ShieldAlert className="h-4 w-4" />}
                statusContext="error"
              />
              <MetricCard
                label="High Severity"
                value={metrics.high_alerts}
                description="Elevated priority alerts"
                icon={<ShieldAlert className="h-4 w-4" />}
                statusContext="warning"
              />
              <MetricCard
                label="Active Threat Classes"
                value={Object.keys(metrics.threat_counts_by_class).length}
                description="Detected threat categories"
                icon={<Activity className="h-4 w-4" />}
                statusContext="info"
              />
            </section>

            {/* Severity Breakdown & Threat-Class Distribution Cards */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Severity Distribution Card */}
              <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                  <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-rose-400" />
                    Severity Breakdown
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

            {/* Filter Control Bar */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--panel-border-subtle)] pb-3">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                  <Filter className="h-4 w-4 text-cyan-400" />
                  <span>Alert Filters</span>
                </div>

                <button
                  type="button"
                  onClick={handleResetFilters}
                  className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs font-mono text-slate-300 hover:bg-slate-800 hover:text-slate-100 focus-ring"
                >
                  <RotateCcw className="h-3 w-3" />
                  <span>Reset Filters</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-sans">
                {/* IP Search Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="threat-ip-search" className="block text-[11px] font-mono text-slate-400">
                    Search IP Address
                  </label>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
                    <input
                      id="threat-ip-search"
                      type="text"
                      value={searchIpInput}
                      onChange={(e: ChangeEvent<HTMLInputElement>) =>
                        handleFilterChange(setSearchIpInput, e.target.value)
                      }
                      placeholder="Filter by source or dest IP..."
                      className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 pl-8 pr-3 font-mono text-xs text-slate-200 placeholder-slate-500 focus-ring"
                    />
                  </div>
                </div>

                {/* Severity Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="threat-severity-filter" className="block text-[11px] font-mono text-slate-400">
                    Severity Level
                  </label>
                  <select
                    id="threat-severity-filter"
                    value={severityFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setSeverityFilter, e.target.value)
                    }
                    className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 px-2.5 font-mono text-xs text-slate-200 focus-ring"
                  >
                    {SEVERITY_OPTIONS.map((sev) => (
                      <option key={sev} value={sev}>
                        {sev === 'ALL' ? 'All Severities' : sev}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Threat Class Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="threat-class-filter" className="block text-[11px] font-mono text-slate-400">
                    Threat Class
                  </label>
                  <select
                    id="threat-class-filter"
                    value={threatClassFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setThreatClassFilter, e.target.value)
                    }
                    className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 px-2.5 font-mono text-xs text-slate-200 focus-ring"
                  >
                    {THREAT_CLASS_OPTIONS.map((tc) => (
                      <option key={tc} value={tc}>
                        {tc === 'ALL' ? 'All Threat Classes' : tc}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Authoritative Threat Alerts Table */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-400" />
                  Authoritative Threat Alerts ({alertsResponse.total})
                </h3>
              </div>

              {alertsResponse.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-400 font-sans">
                  No threat alerts found matching filter criteria.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring" role="region" aria-label="Threat Analysis Alert Dataset" tabIndex={0}>
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
                        <th className="py-2.5 px-3">Protocol</th>
                        <th className="py-2.5 px-3">Model Version</th>
                        <th className="py-2.5 px-3 text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {alertsResponse.data.map((alert) => (
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
                              to={`/flows/${alert.flow_id}`}
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
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {alert.protocol || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                            {alert.model_version || 'N/A'}
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

            {/* Pagination Controls */}
            <PaginationControls
              page={alertsResponse.page}
              limit={alertsResponse.limit}
              total={alertsResponse.total}
              hasMore={alertsResponse.has_more}
              onPageChange={(newPage) => setPage(newPage)}
            />
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
