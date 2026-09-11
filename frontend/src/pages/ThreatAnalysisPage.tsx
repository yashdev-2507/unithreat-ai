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

import { CANONICAL_THREAT_FILTER_OPTIONS } from '../constants/threats';

export interface ThreatAnalysisPageProps {
  dataService: DataService;
}

const SEVERITY_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

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
    setPage(1);
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
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs">
                <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                  <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-rose-600" />
                    Severity Breakdown
                  </h3>
                  <span className="text-xs text-slate-500 font-mono">
                    Total: {metrics.total_alerts}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 font-mono">
                  <div className="rounded-lg border border-rose-200 bg-rose-50 p-3">
                    <div className="text-[11px] text-rose-700 font-sans font-bold uppercase">
                      Critical
                    </div>
                    <div className="text-2xl font-bold text-rose-700 mt-1 font-sans">
                      {metrics.critical_alerts}
                    </div>
                  </div>
                  <div className="rounded-lg border border-orange-200 bg-orange-50 p-3">
                    <div className="text-[11px] text-orange-700 font-sans font-bold uppercase">
                      High
                    </div>
                    <div className="text-2xl font-bold text-orange-700 mt-1 font-sans">
                      {metrics.high_alerts}
                    </div>
                  </div>
                  <div className="rounded-lg border border-amber-200 bg-amber-50 p-3">
                    <div className="text-[11px] text-amber-700 font-sans font-bold uppercase">
                      Medium
                    </div>
                    <div className="text-2xl font-bold text-amber-700 mt-1 font-sans">
                      {metrics.medium_alerts}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-slate-100 p-3">
                    <div className="text-[11px] text-slate-600 font-sans font-bold uppercase">
                      Low
                    </div>
                    <div className="text-2xl font-bold text-slate-700 mt-1 font-sans">
                      {metrics.low_alerts}
                    </div>
                  </div>
                </div>
              </div>

              {/* Threat-Class Distribution Card */}
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 lg:col-span-2 shadow-2xs">
                <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                  <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2">
                    <AlertOctagon className="h-4 w-4 text-[#2563EB]" />
                    Threat Class Distribution
                  </h3>
                  <span className="text-xs text-slate-500 font-mono">Backend Intelligence</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {Object.entries(metrics.threat_counts_by_class).map(([threatClass, count]) => (
                    <div
                      key={threatClass}
                      className="flex items-center justify-between rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-2.5"
                    >
                      <ThreatClassBadge threatClass={threatClass} size="sm" />
                      <span className="font-mono text-sm font-bold text-[#0A0A0A]">
                        {count} {count === 1 ? 'alert' : 'alerts'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Filter Control Bar */}
            <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-4 shadow-2xs">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E5E5] pb-3">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#0A0A0A] font-sans">
                  <Filter className="h-4 w-4 text-[#2563EB]" />
                  <span>Alert Filters</span>
                </div>

                <button
                  type="button"
                  onClick={handleResetFilters}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-xs font-sans text-[#525252] hover:bg-[#F5F5F5] hover:text-[#0A0A0A] focus-ring"
                >
                  <RotateCcw className="h-3 w-3" />
                  <span>Reset Filters</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-sans">
                {/* IP Search Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="threat-ip-search" className="block text-xs font-medium font-sans text-[#525252]">
                    Search IP Address
                  </label>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                    <input
                      id="threat-ip-search"
                      type="text"
                      value={searchIpInput}
                      onChange={(e: ChangeEvent<HTMLInputElement>) =>
                        handleFilterChange(setSearchIpInput, e.target.value)
                      }
                      placeholder="Filter by source or dest IP..."
                      className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] py-1.5 pl-8 pr-3 font-mono text-xs text-[#0A0A0A] placeholder-slate-400 focus-ring"
                    />
                  </div>
                </div>

                {/* Severity Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="threat-severity-filter" className="block text-xs font-medium font-sans text-[#525252]">
                    Severity Level
                  </label>
                  <select
                    id="threat-severity-filter"
                    value={severityFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setSeverityFilter, e.target.value)
                    }
                    className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] py-1.5 px-2.5 font-sans text-xs text-[#0A0A0A] focus-ring"
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
                  <label htmlFor="threat-class-filter" className="block text-xs font-medium font-sans text-[#525252]">
                    Threat Class
                  </label>
                  <select
                    id="threat-class-filter"
                    value={threatClassFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setThreatClassFilter, e.target.value)
                    }
                    className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] py-1.5 px-2.5 font-sans text-xs text-[#0A0A0A] focus-ring"
                  >
                    {CANONICAL_THREAT_FILTER_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Authoritative Threat Alerts Table */}
            <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs">
              <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-600" />
                  Authoritative Threat Alerts ({alertsResponse.total})
                </h3>
              </div>

              {alertsResponse.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-[#525252] font-sans">
                  No threat alerts found matching filter criteria.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring rounded-lg border border-[#E5E5E5]" role="region" aria-label="Threat Analysis Alert Dataset" tabIndex={0}>
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-[#F8FAFC] text-[#525252] uppercase tracking-wider font-sans font-semibold text-[11px] border-b border-[#E5E5E5]">
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
                    <tbody className="divide-y divide-[#E5E5E5] bg-[#FFFFFF]">
                      {alertsResponse.data.map((alert) => (
                        <tr
                          key={`${alert.flow_id}-${alert.timestamp}-${alert.threat_class}`}
                          className="hover:bg-[#F5F5F5] transition-colors"
                        >
                          <td className="py-2.5 px-3 font-mono text-[#0A0A0A] whitespace-nowrap">
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
                              className="text-[#2563EB] hover:underline"
                              title={`Inspect flow ${alert.flow_id}`}
                            >
                              {alert.flow_id}
                            </Link>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[#525252] whitespace-nowrap">
                            {alert.source_ip || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[#525252] whitespace-nowrap">
                            {alert.destination_ip || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[#525252] whitespace-nowrap">
                            {alert.protocol || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-500 text-[11px] whitespace-nowrap">
                            {alert.model_version || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => handleInspectAlert(alert)}
                              className="inline-flex items-center gap-1 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-xs text-[#0A0A0A] hover:bg-[#F5F5F5] focus-ring font-sans font-medium transition-colors"
                              title="Inspect evidence details"
                            >
                              <Eye className="h-3.5 w-3.5 text-[#2563EB]" />
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
