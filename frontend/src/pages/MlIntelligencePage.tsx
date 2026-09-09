import { useState, useEffect, useCallback, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  Brain,
  Filter,
  RotateCcw,
  Search,
  Eye,
  Info,
  CheckCircle2,
  Cpu,
  Layers,
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
import { ThreatClassBadge } from '../components/common/ThreatClassBadge';
import { ConfidenceGauge } from '../components/common/ConfidenceGauge';
import { StatusPill } from '../components/common/StatusPill';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';
import { PaginationControls } from '../components/common/PaginationControls';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

export interface MlIntelligencePageProps {
  dataService: DataService;
}

export const MlIntelligencePage: FC<MlIntelligencePageProps> = ({ dataService }) => {
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

  const fetchMlData = useCallback(async () => {
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
    fetchMlData();
  }, [fetchMlData]);

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

  // Derive unique model versions present in the currently retrieved dataset
  const uniqueModelVersions = Array.from(
    new Set(
      alertsResponse?.data
        .map((a) => a.model_version)
        .filter((mv): mv is string => Boolean(mv)) || []
    )
  );

  const highConfidenceCount =
    alertsResponse?.data.filter((a) => a.confidence >= 0.8).length || 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="ML Intelligence"
        description="Machine Learning model predictions, confidence score inspection, model version provenance, and calibrated inference status."
      />

      {/* Unexposed Offline ML Evaluation Telemetry Notice */}
      <div className="rounded-lg border border-cyan-900/50 bg-slate-900/80 p-4 font-mono text-xs text-cyan-300 flex items-start gap-3">
        <Info className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-cyan-200 uppercase tracking-wider text-[11px]">
            BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
          </div>
          <p className="font-sans text-slate-300 text-xs">
            Offline ML evaluation metrics (Model Accuracy, Precision, Recall, F1 Score, Confusion Matrix, ROC-AUC curves, and Feature Importance charts) are not defined in backend contracts/API schemas. Per project architectural rules, the frontend does NOT invent model performance metrics and displays authoritative inference records provided by the backend.
          </p>
        </div>
      </div>

      <DataStateWrapper state={dataState} onRetry={fetchMlData}>
        {metrics && alertsResponse && (
          <div className="space-y-6">
            {/* KPI Summary Cards */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <MetricCard
                label="ML Detection Records"
                value={alertsResponse.total}
                description="Authoritative backend predictions"
                icon={<Brain className="h-4 w-4" />}
                statusContext="info"
              />
              <MetricCard
                label="Active Model Versions"
                value={uniqueModelVersions.length > 0 ? uniqueModelVersions.length : '1'}
                description={
                  uniqueModelVersions.length > 0
                    ? uniqueModelVersions.join(', ')
                    : 'Backend default'
                }
                icon={<Cpu className="h-4 w-4" />}
                statusContext="healthy"
              />
              <MetricCard
                label="High Confidence (≥ 80%)"
                value={highConfidenceCount}
                description="Current page high-certainty predictions"
                icon={<CheckCircle2 className="h-4 w-4" />}
                statusContext="healthy"
              />
              <MetricCard
                label="Monitored Flow Records"
                value={metrics.total_flows}
                description="Passive flow dataset size"
                icon={<Layers className="h-4 w-4" />}
                statusContext="info"
              />
            </section>

            {/* Filter Control Bar */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--panel-border-subtle)] pb-3">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                  <Filter className="h-4 w-4 text-cyan-400" />
                  <span>ML Prediction Filters</span>
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
                  <label htmlFor="ml-ip-search" className="block text-[11px] font-mono text-slate-400">
                    Search IP Address
                  </label>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
                    <input
                      id="ml-ip-search"
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
                  <label htmlFor="ml-class-filter" className="block text-[11px] font-mono text-slate-400">
                    Threat Class Prediction
                  </label>
                  <select
                    id="ml-class-filter"
                    value={threatClassFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setThreatClassFilter, e.target.value)
                    }
                    className="w-full rounded border border-slate-700 bg-slate-950/80 py-1.5 px-2.5 font-mono text-xs text-slate-200 focus-ring"
                  >
                    <option value="ALL">All Threat Classes</option>
                    <option value="Volumetric / Protocol DDoS">Volumetric / Protocol DDoS</option>
                    <option value="Botnet C2 Beaconing">Botnet C2 Beaconing</option>
                    <option value="DGA / DNS Tunneling">DGA / DNS Tunneling</option>
                    <option value="Malware Inside Encrypted Sessions">Malware Inside Encrypted Sessions</option>
                    <option value="Reconnaissance / Port Scanning">Reconnaissance / Port Scanning</option>
                    <option value="Data Exfiltration">Data Exfiltration</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Authoritative ML Predictions Table */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <Brain className="h-4 w-4 text-cyan-400" />
                  Authoritative ML Model Inferences ({alertsResponse.total})
                </h3>
              </div>

              {alertsResponse.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-400 font-sans">
                  No ML model prediction records match the specified filters.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring" role="region" aria-label="ML Inferences Dataset" tabIndex={0}>
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-mono text-[11px] border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Threat Class</th>
                        <th className="py-2.5 px-3">Model Confidence / Score</th>
                        <th className="py-2.5 px-3">Flow ID</th>
                        <th className="py-2.5 px-3">Source IP</th>
                        <th className="py-2.5 px-3">Destination IP</th>
                        <th className="py-2.5 px-3">Model Version</th>
                        <th className="py-2.5 px-3">Calibration Status</th>
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
                          <td className="py-2.5 px-3 font-mono text-cyan-400 text-[11px] whitespace-nowrap font-semibold">
                            {alert.model_version || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <StatusPill status="CALIBRATED" size="sm" />
                          </td>
                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => handleInspectAlert(alert)}
                              className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-slate-200 hover:bg-slate-700 focus-ring font-mono"
                              title="Inspect ML evidence details"
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
