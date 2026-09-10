import { useState, useEffect, useCallback, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  Search,
  Filter,
  RotateCcw,
  Eye,
  Cpu,
  ChevronLeft,
  ChevronRight,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Clock,
  Activity,
  Terminal,
} from 'lucide-react';
import type { DataService } from '../services/DataService';
import { webSocketService } from '../services/WebSocketService';
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

import { CANONICAL_THREAT_FILTER_OPTIONS } from '../constants/threats';

export interface AlertsPageProps {
  dataService: DataService;
}

export const AlertsPage: FC<AlertsPageProps> = ({
  dataService,
}) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [alertsResponse, setAlertsResponse] = useState<PaginatedResponse<ThreatAlert> | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

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

  // Listen for real-time WebSocket alerts to update feed without page refresh
  useEffect(() => {
    const unsubscribe = webSocketService.subscribe((newAlert: ThreatAlert) => {
      setAlertsResponse((prev) => {
        if (!prev) return prev;

        // Verify filter compatibility
        if (severityFilter !== 'ALL' && newAlert.severity !== severityFilter) {
          return prev;
        }
        if (threatClassFilter !== 'ALL' && newAlert.threat_class !== threatClassFilter) {
          return prev;
        }
        if (minConfidence !== '') {
          const parsedConf = parseFloat(minConfidence);
          if (!Number.isNaN(parsedConf) && newAlert.confidence < parsedConf) {
            return prev;
          }
        }
        if (searchIpInput.trim()) {
          const q = searchIpInput.trim().toLowerCase();
          const match =
            (newAlert.source_ip && newAlert.source_ip.toLowerCase().includes(q)) ||
            (newAlert.destination_ip && newAlert.destination_ip.toLowerCase().includes(q));
          if (!match) return prev;
        }
        if (flowIdInput.trim() && newAlert.flow_id !== flowIdInput.trim()) {
          return prev;
        }

        // Avoid duplicate alert
        if (prev.data.some((a) => a.flow_id === newAlert.flow_id)) {
          return prev;
        }

        // Prepend to visible page if currently on page 1
        const updatedData = page === 1 ? [newAlert, ...prev.data].slice(0, limit) : prev.data;
        return {
          ...prev,
          data: updatedData,
          total: prev.total + 1,
        };
      });

      setDataState((prev) => (prev === 'empty' ? 'ready' : prev));
    });

    return unsubscribe;
  }, [
    severityFilter,
    threatClassFilter,
    minConfidence,
    searchIpInput,
    flowIdInput,
    page,
    limit,
  ]);

  const handleFilterChange = (setter: (val: any) => void, val: any) => {
    setter(val);
    setPage(1);
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

  const handleCopyText = async (text: string, fieldName: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(fieldName);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // Silent catch per requirement
    }
  };

  // Derive active selected alert for Featured Panel (defaults to first item in dataset)
  const activeAlert =
    selectedAlert && alertsResponse?.data.some((a) => a.flow_id === selectedAlert.flow_id)
      ? selectedAlert
      : alertsResponse?.data?.[0] || null;

  const currentAlertIndex =
    alertsResponse && activeAlert
      ? alertsResponse.data.findIndex((a) => a.flow_id === activeAlert.flow_id)
      : -1;

  const hasPrev = currentAlertIndex > 0;
  const hasNext =
    alertsResponse && currentAlertIndex >= 0 && currentAlertIndex < alertsResponse.data.length - 1;

  const handlePrevAlert = () => {
    if (alertsResponse && hasPrev) {
      setSelectedAlert(alertsResponse.data[currentAlertIndex - 1]);
    }
  };

  const handleNextAlert = () => {
    if (alertsResponse && hasNext) {
      setSelectedAlert(alertsResponse.data[currentAlertIndex + 1]);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Live Threat Alerts"
        description="Filterable, paginated passive network threat alerts observed by the detection pipeline."
        actions={
          <span className="inline-flex items-center gap-1.5 rounded border border-blue-200 bg-[#EFF6FF] px-2.5 py-1 text-xs font-semibold text-[#2563EB] font-mono">
            UNIDIRECTIONAL INGEST — READ ONLY
          </span>
        }
      />

      {/* FEATURED SELECTED ALERT PANEL */}
      {dataState === 'ready' && activeAlert && alertsResponse && (
        <div className="rounded-2xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 sm:p-6 shadow-sm space-y-5 transition-all">
          {/* Featured Header & Navigation Controls */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E5E5] pb-4">
            <div className="flex items-center gap-2.5">
              <span className="flex h-2 w-2 rounded-full bg-[#2563EB] animate-pulse" />
              <span className="text-xs font-bold text-[#0A0A0A] uppercase tracking-wider font-mono">
                FEATURED THREAT OBSERVATION
              </span>
              <span className="text-xs text-slate-400 font-mono">
                (Flow: {activeAlert.flow_id})
              </span>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-slate-500">
                Alert <strong className="text-[#0A0A0A]">{currentAlertIndex + 1}</strong> of{' '}
                <strong className="text-[#0A0A0A]">{alertsResponse.data.length}</strong>
              </span>
              <div className="inline-flex rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-0.5">
                <button
                  type="button"
                  onClick={handlePrevAlert}
                  disabled={!hasPrev}
                  className="inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-medium font-mono text-[#0A0A0A] hover:bg-[#FFFFFF] disabled:opacity-30 disabled:hover:bg-transparent transition-colors focus-ring"
                  title="Previous Alert"
                >
                  <ChevronLeft className="h-4 w-4" />
                  <span>Prev</span>
                </button>
                <div className="w-px bg-[#E5E5E5] my-1" />
                <button
                  type="button"
                  onClick={handleNextAlert}
                  disabled={!hasNext}
                  className="inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-medium font-mono text-[#0A0A0A] hover:bg-[#FFFFFF] disabled:opacity-30 disabled:hover:bg-transparent transition-colors focus-ring"
                  title="Next Alert"
                >
                  <span>Next</span>
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Main 2-Column Grid Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Left Column: Circular Ring Confidence Gauge */}
            <div className="lg:col-span-4 flex flex-col items-center justify-center p-4 bg-[#F8FAFC] rounded-xl border border-[#E5E5E5] min-h-[260px]">
              <ConfidenceGauge
                confidence={activeAlert.confidence}
                variant="ring"
                size="lg"
                severity={activeAlert.severity}
              />
              <div className="mt-3 flex items-center gap-2 text-xs font-mono text-slate-500">
                <Activity className="h-3.5 w-3.5 text-[#2563EB]" />
                <span>ML Pipeline Confidence Gauge</span>
              </div>
            </div>

            {/* Right Column: Threat Details, Specs, Signals & Actions */}
            <div className="lg:col-span-8 space-y-4">
              {/* Badges & Meta Row */}
              <div className="flex flex-wrap items-center gap-2.5">
                <SeverityBadge severity={activeAlert.severity} size="md" />
                <ThreatClassBadge threatClass={activeAlert.threat_class} size="md" />
                <span className="inline-flex items-center gap-1 text-xs text-slate-500 font-mono ml-auto">
                  <Clock className="h-3.5 w-3.5 text-slate-400" />
                  {activeAlert.timestamp}
                </span>
              </div>

              {/* Title & Description */}
              <div>
                <h3 className="text-2xl sm:text-[26px] font-bold font-sans text-[#0A0A0A] tracking-tight leading-tight">
                  {activeAlert.threat_class}
                </h3>
                <p className="text-sm sm:text-[15px] text-[#525252] font-sans mt-1.5 leading-relaxed">
                  {activeAlert.explanation ||
                    'Passive threat observation identified by pipeline telemetry.'}
                </p>
              </div>

              {/* Technical Specifications Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#F8FAFC] p-3 rounded-lg border border-[#E5E5E5] text-xs font-mono">
                <div>
                  <span className="block text-slate-400 text-[10px] uppercase">Source IP</span>
                  <div className="flex items-center justify-between mt-0.5 text-[#0A0A0A] font-semibold">
                    <span className="truncate">{activeAlert.source_ip || 'N/A'}</span>
                    {activeAlert.source_ip && (
                      <button
                        type="button"
                        onClick={() => handleCopyText(activeAlert.source_ip!, 'src_ip')}
                        className="text-slate-400 hover:text-[#0A0A0A] focus-ring p-0.5"
                        title="Copy Source IP"
                      >
                        {copiedField === 'src_ip' ? (
                          <Check className="h-3 w-3 text-emerald-600" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                <div>
                  <span className="block text-slate-400 text-[10px] uppercase">Destination IP</span>
                  <div className="flex items-center justify-between mt-0.5 text-[#0A0A0A] font-semibold">
                    <span className="truncate">{activeAlert.destination_ip || 'N/A'}</span>
                    {activeAlert.destination_ip && (
                      <button
                        type="button"
                        onClick={() => handleCopyText(activeAlert.destination_ip!, 'dst_ip')}
                        className="text-slate-400 hover:text-[#0A0A0A] focus-ring p-0.5"
                        title="Copy Destination IP"
                      >
                        {copiedField === 'dst_ip' ? (
                          <Check className="h-3 w-3 text-emerald-600" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                <div>
                  <span className="block text-slate-400 text-[10px] uppercase">Protocol</span>
                  <span className="block mt-0.5 text-[#0A0A0A] font-semibold">
                    {activeAlert.protocol || 'N/A'}
                  </span>
                </div>

                <div>
                  <span className="block text-slate-400 text-[10px] uppercase">Model Version</span>
                  <div className="flex items-center gap-1 mt-0.5 text-slate-600">
                    <Terminal className="h-3 w-3 text-slate-400" />
                    <span className="truncate">{activeAlert.model_version || 'N/A'}</span>
                  </div>
                </div>
              </div>

              {/* Primary Evidence Signals */}
              {activeAlert.evidence && activeAlert.evidence.length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[11px] font-mono font-bold text-slate-500 uppercase tracking-wider">
                    PRIMARY EVIDENCE SIGNALS ({activeAlert.evidence.length})
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {activeAlert.evidence.map((sig, idx) => (
                      <span
                        key={`${sig.signal_name}-${idx}`}
                        className="inline-flex items-center gap-1.5 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-xs text-[#0A0A0A] font-mono shadow-2xs"
                        title={`Reliability: ${Math.round(sig.reliability * 100)}% | Direction: ${sig.direction}`}
                      >
                        <ShieldAlert className="h-3 w-3 text-[#2563EB]" />
                        <span>{sig.signal_name}</span>
                        <span className="text-[10px] text-slate-400 font-sans">
                          ({sig.value})
                        </span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* CTA Row */}
              <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-[#E5E5E5]">
                <button
                  type="button"
                  onClick={() => handleInspectAlert(activeAlert)}
                  className="inline-flex items-center gap-2 rounded-lg bg-[#2563EB] px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 transition-colors shadow-2xs focus-ring"
                >
                  <Eye className="h-4 w-4" />
                  <span>Inspect Alert Details</span>
                </button>

                <Link
                  to={`/alerts/flow/${activeAlert.flow_id}`}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[#E5E5E5] bg-[#FFFFFF] px-3.5 py-2 text-xs font-medium font-mono text-[#0A0A0A] hover:bg-[#F5F5F5] transition-colors focus-ring"
                >
                  <span>Investigate Flow ({activeAlert.flow_id})</span>
                  <ExternalLink className="h-3.5 w-3.5 text-slate-400" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar Controls */}
      <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-3 shadow-2xs">
        <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-2">
          <div className="flex items-center gap-2 text-xs font-bold text-[#0A0A0A] uppercase tracking-wider font-sans">
            <Filter className="h-4 w-4 text-[#2563EB]" />
            <span>Alert Filter Controls</span>
          </div>
          <button
            type="button"
            onClick={handleResetFilters}
            className="inline-flex items-center gap-1 text-xs text-[#525252] hover:text-[#0A0A0A] focus-ring font-sans"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>Reset Filters</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs font-sans">
          {/* Severity Filter */}
          <div>
            <label htmlFor="severity-filter" className="block text-[#525252] font-sans font-medium mb-1 text-xs">
              Severity Level
            </label>
            <select
              id="severity-filter"
              value={severityFilter}
              onChange={(e) => handleFilterChange(setSeverityFilter, e.target.value)}
              className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] px-2.5 py-1.5 text-[#0A0A0A] focus-ring font-sans"
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
            <label htmlFor="threat-class-filter" className="block text-[#525252] font-sans font-medium mb-1 text-xs">
              Threat Class
            </label>
            <select
              id="threat-class-filter"
              value={threatClassFilter}
              onChange={(e) => handleFilterChange(setThreatClassFilter, e.target.value)}
              className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] px-2.5 py-1.5 text-[#0A0A0A] focus-ring font-sans truncate"
            >
              {CANONICAL_THREAT_FILTER_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {/* Search IP Filter */}
          <div>
            <label htmlFor="search-ip-input" className="block text-[#525252] font-sans font-medium mb-1 text-xs">
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
                className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] px-2.5 py-1.5 text-[#0A0A0A] focus-ring font-mono text-xs pl-8"
              />
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
            </div>
          </div>

          {/* Flow ID Filter */}
          <div>
            <label htmlFor="flow-id-input" className="block text-[#525252] font-sans font-medium mb-1 text-xs">
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
              className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] px-2.5 py-1.5 text-[#0A0A0A] focus-ring font-mono text-xs"
            />
          </div>

          {/* Min Confidence Filter */}
          <div>
            <label htmlFor="min-confidence-input" className="block text-[#525252] font-sans font-medium mb-1 text-xs">
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
              className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] px-2.5 py-1.5 text-[#0A0A0A] focus-ring font-mono text-xs"
            />
          </div>
        </div>
      </div>

      {/* Main Alert Table Section */}
      <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] flex flex-col overflow-hidden shadow-2xs">
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
                  <thead className="bg-[#F8FAFC] text-[#525252] uppercase tracking-wider font-sans font-semibold text-[11px] border-b border-[#E5E5E5]">
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
                  <tbody className="divide-y divide-[#E5E5E5] bg-[#FFFFFF]">
                    {alertsResponse.data.map((alert) => {
                      const isSelected = activeAlert?.flow_id === alert.flow_id;
                      return (
                        <tr
                          key={`${alert.flow_id}-${alert.timestamp}-${alert.threat_class}`}
                          onClick={() => setSelectedAlert(alert)}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-blue-50/60 font-medium border-l-4 border-l-[#2563EB]'
                              : 'hover:bg-[#F5F5F5]'
                          }`}
                        >
                          <td className="py-3 px-3.5 font-mono text-[#0A0A0A] whitespace-nowrap">
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
                              onClick={(e) => e.stopPropagation()}
                              className="text-[#2563EB] hover:underline font-semibold"
                              title={`Inspect flow ${alert.flow_id}`}
                            >
                              {alert.flow_id}
                            </Link>
                          </td>
                          <td className="py-3 px-3.5 font-mono text-[#525252] whitespace-nowrap">
                            {alert.source_ip || 'N/A'}
                          </td>
                          <td className="py-3 px-3.5 font-mono text-[#525252] whitespace-nowrap">
                            {alert.destination_ip || 'N/A'}
                          </td>
                          <td className="py-3 px-3.5 font-mono text-[#525252] whitespace-nowrap">
                            {alert.protocol || 'N/A'}
                          </td>
                          <td className="py-3 px-3.5 font-mono text-slate-500 text-[11px] whitespace-nowrap">
                            <span className="inline-flex items-center gap-1">
                              <Cpu className="h-3 w-3 text-slate-400" />
                              {alert.model_version || 'N/A'}
                            </span>
                          </td>
                          <td className="py-3 px-3.5 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleInspectAlert(alert);
                              }}
                              className="inline-flex items-center gap-1 rounded border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-xs text-[#0A0A0A] hover:bg-[#F5F5F5] focus-ring font-mono transition-colors"
                              title="Inspect evidence & flow details"
                            >
                              <Eye className="h-3.5 w-3.5 text-[#2563EB]" />
                              <span>Details</span>
                            </button>
                          </td>
                        </tr>
                      );
                    })}
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

      {/* Alert Detail Drawer / Modal */}
      <AlertDetailDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </div>
  );
};
