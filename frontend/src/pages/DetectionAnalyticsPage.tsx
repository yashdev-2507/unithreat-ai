import { useState, useEffect, useCallback, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  ShieldAlert,
  AlertOctagon,
  Filter,
  RotateCcw,
  Search,
  Eye,
  Info,
  Layers,
  Zap,
} from 'lucide-react';
import type { DataService } from '../services/DataService';
import type {
  OverviewMetrics,
  PaginatedResponse,
  ThreatAlert,
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

export interface DetectionAnalyticsPageProps {
  dataService: DataService;
}

/** SIH 6 Core Threat Categories */
const SIH_THREAT_CATEGORIES = [
  'Volumetric / Protocol DDoS',
  'Botnet C2 Beaconing',
  'DGA / DNS Tunneling',
  'Malware Inside Encrypted Sessions',
  'Reconnaissance / Port Scanning',
  'Data Exfiltration',
] as const;

export const DetectionAnalyticsPage: FC<DetectionAnalyticsPageProps> = ({ dataService }) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [alertsResponse, setAlertsResponse] = useState<PaginatedResponse<ThreatAlert> | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  // Filters state
  const [page, setPage] = useState<number>(1);
  const [limit] = useState<number>(10);
  const [threatClassFilter, setThreatClassFilter] = useState<string>('ALL');
  const [searchIpInput, setSearchIpInput] = useState<string>('');

  const fetchAnalyticsData = useCallback(async () => {
    setDataState('loading');
    try {
      const queryParams: AlertQueryParams = {
        page,
        limit,
      };

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
  }, [dataService, page, limit, threatClassFilter, searchIpInput]);

  useEffect(() => {
    fetchAnalyticsData();
  }, [fetchAnalyticsData]);

  const handleCategoryClick = (category: string) => {
    if (threatClassFilter === category) {
      setThreatClassFilter('ALL');
    } else {
      setThreatClassFilter(category);
    }
    setPage(1);
  };

  const handleFilterChange = (setter: (val: string) => void, val: string) => {
    setter(val);
    setPage(1);
  };

  const handleResetFilters = () => {
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
        title="Detection Analytics"
        description="Backend-driven threat category telemetry, SIH threat class breakdowns, and category-filtered alert inspection."
      />

      {/* Unexposed Time-Series Telemetry Requirement Notice */}
      <div className="rounded-lg border border-cyan-900/50 bg-slate-900/80 p-4 font-mono text-xs text-cyan-300 flex items-start gap-3">
        <Info className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-cyan-200 uppercase tracking-wider text-[11px]">
            BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
          </div>
          <p className="font-sans text-slate-300 text-xs">
            Protocol/traffic time-series flow rate trends, packet velocity graphs, and detection latency histograms are not defined in backend telemetry schemas. The frontend strictly displays category detection totals provided by backend telemetry.
          </p>
        </div>
      </div>

      <DataStateWrapper state={dataState} onRetry={fetchAnalyticsData}>
        {metrics && alertsResponse && (
          <div className="space-y-6">
            {/* High-Level Overview Metrics */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <MetricCard
                label="Total Detected Alerts"
                value={metrics.total_alerts}
                description="Aggregated backend detection count"
                icon={<ShieldAlert className="h-4 w-4" />}
                statusContext="warning"
              />
              <MetricCard
                label="Monitored Flow Volume"
                value={metrics.total_flows}
                description="Passive records processed"
                icon={<Layers className="h-4 w-4" />}
                statusContext="info"
              />
              <MetricCard
                label="Flow Throughput Rate"
                value={`${metrics.flows_per_second} /s`}
                description="Backend ingestion velocity"
                icon={<Zap className="h-4 w-4" />}
                statusContext="healthy"
              />
              <MetricCard
                label="Active Threat Categories"
                value={Object.keys(metrics.threat_counts_by_class).length}
                description="SIH threat classes detected"
                icon={<Activity className="h-4 w-4" />}
                statusContext="info"
              />
            </section>

            {/* SIH 6 Threat Category Grid */}
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-2">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <AlertOctagon className="h-4 w-4 text-cyan-400" />
                  SIH Threat Category Telemetry Breakdown
                </h3>
                <span className="text-xs text-slate-400 font-mono">
                  Click category to filter table below
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {SIH_THREAT_CATEGORIES.map((category) => {
                  const count = metrics.threat_counts_by_class[category] || 0;
                  const isSelected = threatClassFilter === category;

                  return (
                    <button
                      key={category}
                      type="button"
                      onClick={() => handleCategoryClick(category)}
                      aria-pressed={isSelected}
                      className={`text-left transition-all rounded-lg border p-4 space-y-3 focus-ring ${
                        isSelected
                          ? 'border-cyan-500 bg-cyan-950/30 ring-1 ring-cyan-500'
                          : 'border-[var(--panel-border)] bg-[var(--panel-bg)] hover:border-slate-700 hover:bg-slate-900/60'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <ThreatClassBadge threatClass={category} size="sm" />
                        <span className="font-mono text-lg font-bold text-slate-100">
                          {count}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-xs text-slate-400 font-mono pt-1 border-t border-slate-800/60">
                        <span>Status: {count > 0 ? 'ACTIVE' : 'NO DETECTIONS'}</span>
                        <span className="text-cyan-400 hover:underline">
                          {isSelected ? 'Filter Active' : 'Filter Alerts →'}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Filter Control Bar */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--panel-border-subtle)] pb-3">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                  <Filter className="h-4 w-4 text-cyan-400" />
                  <span>Category Alert Filters</span>
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

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-sans">
                {/* IP Search Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="analytics-ip-search" className="block text-[11px] font-mono text-slate-400">
                    Search IP Address
                  </label>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
                    <input
                      id="analytics-ip-search"
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

                {/* Threat Class Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="analytics-class-filter" className="block text-[11px] font-mono text-slate-400">
                    SIH Threat Category
                  </label>
                  <select
                    id="analytics-class-filter"
                    value={threatClassFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setThreatClassFilter, e.target.value)
                    }
                    className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 px-2.5 font-mono text-xs text-slate-200 focus-ring"
                  >
                    <option value="ALL">All Threat Categories</option>
                    {SIH_THREAT_CATEGORIES.map((cat) => (
                      <option key={cat} value={cat}>
                        {cat}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Authoritative Category Alert Records */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-cyan-400" />
                  Backend Category Alert Records ({alertsResponse.total})
                </h3>
              </div>

              {alertsResponse.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-400 font-sans">
                  No alert records match the selected category filters.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring" role="region" aria-label="Detection Analytics Category Alert Dataset" tabIndex={0}>
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-mono text-[11px] border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">Threat Category</th>
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
