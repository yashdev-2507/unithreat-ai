import { useState, useEffect, useCallback, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  Search,
  Filter,
  RotateCcw,
  Eye,
  Cpu,
} from 'lucide-react';
import type { DataService } from '../services/DataService';
import type {
  ThreatAlert,
  SeverityLevel,
  AlertQueryParams,
  PaginatedResponse,
} from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ThreatClassBadge } from '../components/common/ThreatClassBadge';
import { ConfidenceGauge } from '../components/common/ConfidenceGauge';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';
import { PaginationControls } from '../components/common/PaginationControls';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

export interface AlertsPageProps {
  dataService: DataService;
}

const SIH_THREAT_CLASSES = [
  'Volumetric / Protocol DDoS',
  'Botnet C2 Beaconing',
  'DGA / DNS Tunneling',
  'Malware Inside Encrypted Sessions',
  'Reconnaissance / Port Scanning',
  'Data Exfiltration',
];

export const AlertsPage: FC<AlertsPageProps> = ({
  dataService,
}) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [alertsResponse, setAlertsResponse] = useState<PaginatedResponse<ThreatAlert> | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  // Filter State
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(10);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [threatClassFilter, setThreatClassFilter] = useState<string>('ALL');
  const [searchIpInput, setSearchIpInput] = useState<string>('');
  const [flowIdInput, setFlowIdInput] = useState<string>('');
  const [minConfidence, setMinConfidence] = useState<string>('');

  const fetchAlerts = useCallback(async () => {
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

      if (flowIdInput.trim()) {
        queryParams.flow_id = flowIdInput.trim();
      }

      if (minConfidence !== '') {
        const parsedConf = parseFloat(minConfidence);
        if (!Number.isNaN(parsedConf)) {
          queryParams.min_confidence = parsedConf;
        }
      }

      const response = await dataService.getAlerts(queryParams);
      setAlertsResponse(response);

      if (response.data.length === 0) {
        setDataState('empty');
      } else {
        setDataState('ready');
      }
    } catch {
      setDataState('error');
    }
  }, [
    dataService,
    page,
    limit,
    severityFilter,
    threatClassFilter,
    searchIpInput,
    flowIdInput,
    minConfidence,
  ]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleFilterChange = (setter: (val: any) => void, val: any) => {
    setter(val);
    setPage(1); // Reset to page 1 on filter change
  };

  const handleResetFilters = () => {
    setSeverityFilter('ALL');
    setThreatClassFilter('ALL');
    setSearchIpInput('');
    setFlowIdInput('');
    setMinConfidence('');
    setPage(1);
  };

  const handleInspectAlert = (alert: ThreatAlert) => {
    setSelectedAlert(alert);
    setIsDrawerOpen(true);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Live Threat Alerts"
        description="Filterable, paginated passive network threat alerts observed by the detection pipeline."
        actions={
          <span className="inline-flex items-center gap-1.5 rounded border border-cyan-800/40 bg-cyan-950/30 px-2.5 py-1 text-xs font-medium text-cyan-300 font-mono">
            UNIDIRECTIONAL INGEST — READ ONLY
          </span>
        }
      />

      {/* Filter Bar Controls */}
      <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
            <Filter className="h-4 w-4 text-cyan-400" />
            <span>Alert Filter Controls</span>
          </div>
          <button
            type="button"
            onClick={handleResetFilters}
            className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 focus-ring font-mono"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>Reset Filters</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs font-sans">
          {/* Severity Filter */}
          <div>
            <label htmlFor="severity-filter" className="block text-slate-400 font-mono mb-1 text-[11px]">
              Severity Level
            </label>
            <select
              id="severity-filter"
              value={severityFilter}
              onChange={(e) => handleFilterChange(setSeverityFilter, e.target.value)}
              className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus-ring font-mono"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Threat Class Filter */}
          <div>
            <label htmlFor="threat-class-filter" className="block text-slate-400 font-mono mb-1 text-[11px]">
              Threat Class
            </label>
            <select
              id="threat-class-filter"
              value={threatClassFilter}
              onChange={(e) => handleFilterChange(setThreatClassFilter, e.target.value)}
              className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus-ring font-mono truncate"
            >
              <option value="ALL">All Threat Classes</option>
              {SIH_THREAT_CLASSES.map((tc) => (
                <option key={tc} value={tc}>
                  {tc}
                </option>
              ))}
            </select>
          </div>

          {/* Search IP Filter */}
          <div>
            <label htmlFor="search-ip-input" className="block text-slate-400 font-mono mb-1 text-[11px]">
              Search IP
            </label>
            <div className="relative">
              <input
                id="search-ip-input"
                type="text"
                value={searchIpInput}
                onChange={(e: ChangeEvent<HTMLInputElement>) =>
                  handleFilterChange(setSearchIpInput, e.target.value)
                }
                placeholder="e.g. 192.168.1.105"
                className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus-ring font-mono text-xs pl-8"
              />
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
            </div>
          </div>

          {/* Flow ID Filter */}
          <div>
            <label htmlFor="flow-id-input" className="block text-slate-400 font-mono mb-1 text-[11px]">
              Flow ID
            </label>
            <input
              id="flow-id-input"
              type="text"
              value={flowIdInput}
              onChange={(e: ChangeEvent<HTMLInputElement>) =>
                handleFilterChange(setFlowIdInput, e.target.value)
              }
              placeholder="e.g. flow-vol-001"
              className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus-ring font-mono text-xs"
            />
          </div>

          {/* Min Confidence Filter */}
          <div>
            <label htmlFor="min-confidence-input" className="block text-slate-400 font-mono mb-1 text-[11px]">
              Min Confidence (0..1)
            </label>
            <input
              id="min-confidence-input"
              type="number"
              step="0.05"
              min="0"
              max="1"
              value={minConfidence}
              onChange={(e: ChangeEvent<HTMLInputElement>) =>
                handleFilterChange(setMinConfidence, e.target.value)
              }
              placeholder="e.g. 0.85"
              className="w-full rounded border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus-ring font-mono text-xs"
            />
          </div>
        </div>
      </div>

      {/* Main Alert Table Section */}
      <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] flex flex-col overflow-hidden">
        <DataStateWrapper
          state={dataState}
          emptyTitle="No Threat Alerts Found"
          emptyMessage="No backend threat observations match your active filter parameters."
          onRetry={fetchAlerts}
        >
          {alertsResponse && alertsResponse.data.length > 0 && (
            <>
              <div className="overflow-x-auto focus-ring" role="region" aria-label="Live Threat Alerts Dataset" tabIndex={0}>
                <table className="w-full text-left text-xs font-sans">
                  <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-mono text-[11px] border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-3.5">Timestamp</th>
                      <th className="py-3 px-3.5">Severity</th>
                      <th className="py-3 px-3.5">Threat Class</th>
                      <th className="py-3 px-3.5">Confidence</th>
                      <th className="py-3 px-3.5">Flow ID</th>
                      <th className="py-3 px-3.5">Source IP</th>
                      <th className="py-3 px-3.5">Destination IP</th>
                      <th className="py-3 px-3.5">Protocol</th>
                      <th className="py-3 px-3.5">Model</th>
                      <th className="py-3 px-3.5 text-right">Inspect</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {alertsResponse.data.map((alert) => (
                      <tr
                        key={`${alert.flow_id}-${alert.timestamp}-${alert.threat_class}`}
                        className="hover:bg-slate-800/30 transition-colors"
                      >
                        <td className="py-3 px-3.5 font-mono text-slate-300 whitespace-nowrap">
                          {alert.timestamp}
                        </td>
                        <td className="py-3 px-3.5 whitespace-nowrap">
                          <SeverityBadge severity={alert.severity} size="sm" />
                        </td>
                        <td className="py-3 px-3.5 whitespace-nowrap">
                          <ThreatClassBadge threatClass={alert.threat_class} size="sm" />
                        </td>
                        <td className="py-3 px-3.5 whitespace-nowrap">
                          <ConfidenceGauge confidence={alert.confidence} size="sm" />
                        </td>
                        <td className="py-3 px-3.5 font-mono whitespace-nowrap">
                          <Link
                            to={`/alerts/flow/${alert.flow_id}`}
                            className="text-cyan-400 hover:underline font-medium"
                            title={`Inspect flow ${alert.flow_id}`}
                          >
                            {alert.flow_id}
                          </Link>
                        </td>
                        <td className="py-3 px-3.5 font-mono text-slate-300 whitespace-nowrap">
                          {alert.source_ip || 'N/A'}
                        </td>
                        <td className="py-3 px-3.5 font-mono text-slate-300 whitespace-nowrap">
                          {alert.destination_ip || 'N/A'}
                        </td>
                        <td className="py-3 px-3.5 font-mono text-slate-300 whitespace-nowrap">
                          {alert.protocol || 'N/A'}
                        </td>
                        <td className="py-3 px-3.5 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                          <span className="inline-flex items-center gap-1">
                            <Cpu className="h-3 w-3 text-slate-500" />
                            {alert.model_version || 'N/A'}
                          </span>
                        </td>
                        <td className="py-3 px-3.5 text-right whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => handleInspectAlert(alert)}
                            className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-700 focus-ring font-mono"
                            title="Inspect evidence & flow details"
                          >
                            <Eye className="h-3.5 w-3.5" />
                            <span>Details</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination Footer */}
              <PaginationControls
                page={alertsResponse.page}
                limit={alertsResponse.limit}
                total={alertsResponse.total}
                hasMore={alertsResponse.has_more}
                onPageChange={(newPage) => setPage(newPage)}
                onLimitChange={(newLimit) => {
                  setLimit(newLimit);
                  setPage(1);
                }}
              />
            </>
          )}
        </DataStateWrapper>
      </div>

      {/* Alert Detail Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </div>
  );
};
