import { useState, useEffect, useCallback, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  Activity,
  AlertOctagon,
  Bell,
  Clock,
  Eye,
  Filter,
  Layers,
  RotateCcw,
  Search,
  ShieldAlert,
  Zap,
  Target,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  LabelList,
  CartesianGrid,
} from 'recharts';
import type { DataService } from '../services/DataService';
import type {
  OverviewMetrics,
  PaginatedResponse,
  ThreatAlert,
  AlertQueryParams,
} from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ThreatClassBadge } from '../components/common/ThreatClassBadge';
import { ConfidenceGauge } from '../components/common/ConfidenceGauge';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';
import { PaginationControls } from '../components/common/PaginationControls';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

import {
  SIH_THREAT_CATEGORIES_CONFIG,
  CANONICAL_THREAT_FILTER_OPTIONS,
  getThreatCategoryCount,
} from '../constants/threats';

export interface DetectionAnalyticsPageProps {
  dataService: DataService;
}

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

  // Process Threat Class Distribution for Recharts Horizontal Bar Chart
  const threatChartData = metrics
    ? Object.entries(metrics.threat_counts_by_class)
        .map(([threatClass, count]) => ({
          fullName: threatClass,
          name: getShortThreatLabel(threatClass),
          count,
        }))
        .sort((a, b) => b.count - a.count)
    : [];

  // Calculate severity proportions from metrics
  const totalAlerts = metrics?.total_alerts || 0;
  const criticalPct = totalAlerts > 0 ? ((metrics?.critical_alerts || 0) / totalAlerts) * 100 : 0;
  const highPct = totalAlerts > 0 ? ((metrics?.high_alerts || 0) / totalAlerts) * 100 : 0;
  const mediumPct = totalAlerts > 0 ? ((metrics?.medium_alerts || 0) / totalAlerts) * 100 : 0;
  const lowPct = totalAlerts > 0 ? ((metrics?.low_alerts || 0) / totalAlerts) * 100 : 0;

  // Calculate confidence bands from current alert records
  const loadedAlerts = alertsResponse?.data || [];
  const highConfidenceCount = loadedAlerts.filter((a) => a.confidence >= 0.9).length;
  const modConfidenceCount = loadedAlerts.filter((a) => a.confidence >= 0.7 && a.confidence < 0.9).length;
  const lowConfidenceCount = loadedAlerts.filter((a) => a.confidence < 0.7).length;

  return (
    <div className="space-y-7">
      {/* 1. Analytics Command Header */}
      <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 mb-6 border-b border-[#E5E5E5]">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <Target className="h-6 w-6 text-[#2563EB] shrink-0" />
            <h1 className="text-2xl sm:text-[32px] font-bold tracking-tight text-[#0A0A0A] font-sans leading-tight">
              Detection Analytics
            </h1>
          </div>
          <p className="text-sm sm:text-[15px] text-[#525252] font-sans mt-1.5 max-w-3xl leading-relaxed">
            Security detection distribution, category analytics, and model confidence across observed passive IP traffic
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="inline-flex items-center gap-1.5 rounded bg-[#EFF6FF] border border-blue-200 px-2.5 py-1 text-xs font-mono text-[#2563EB]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#2563EB] shrink-0" aria-hidden="true" />
            <span className="font-semibold text-[10px] tracking-wide">PASSIVE DETECTIONS — READ ONLY</span>
          </div>
        </div>
      </header>

      <DataStateWrapper state={dataState} onRetry={fetchAnalyticsData}>
        {metrics && alertsResponse && (
          <motion.div
            className="space-y-7"
            variants={containerVariants}
            initial="hidden"
            animate="visible"
          >
            {/* 2. Primary Detection Signals Rail */}
            <motion.section variants={itemVariants} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="rounded-xl bg-[#FFFFFF] p-4 border border-[#E5E5E5] border-l-4 border-l-rose-500 shadow-2xs flex flex-col justify-between">
                <div className="flex items-center justify-between text-xs font-sans text-[#525252]">
                  <span className="font-mono uppercase font-semibold text-[#0A0A0A] text-[11px]">
                    Total Detected Alerts
                  </span>
                  <Bell className="h-4 w-4 text-rose-600" />
                </div>
                <div className="my-2">
                  <span className="text-3xl font-bold text-[#0A0A0A] font-sans tracking-tight">
                    {metrics.total_alerts.toLocaleString()}
                  </span>
                </div>
                <span className="text-[11px] text-[#737373] font-sans">
                  Aggregated detection engine count
                </span>
              </div>

              <div className="rounded-xl bg-[#FFFFFF] p-4 border border-[#E5E5E5] border-l-4 border-l-[#2563EB] shadow-2xs flex flex-col justify-between">
                <div className="flex items-center justify-between text-xs font-sans text-[#525252]">
                  <span className="font-mono uppercase font-semibold text-[#0A0A0A] text-[11px]">
                    Monitored Flow Volume
                  </span>
                  <Layers className="h-4 w-4 text-[#2563EB]" />
                </div>
                <div className="my-2">
                  <span className="text-3xl font-bold text-[#2563EB] font-sans tracking-tight">
                    {metrics.total_flows.toLocaleString()}
                  </span>
                </div>
                <span className="text-[11px] text-[#737373] font-sans">
                  Passive records processed
                </span>
              </div>

              <div className="rounded-xl bg-[#FFFFFF] p-4 border border-[#E5E5E5] border-l-4 border-l-emerald-500 shadow-2xs flex flex-col justify-between">
                <div className="flex items-center justify-between text-xs font-sans text-[#525252]">
                  <span className="font-mono uppercase font-semibold text-[#0A0A0A] text-[11px]">
                    Flow Throughput Rate
                  </span>
                  <Zap className="h-4 w-4 text-emerald-600" />
                </div>
                <div className="my-2">
                  <span className="text-3xl font-bold text-emerald-600 font-sans tracking-tight">
                    {metrics.flows_per_second} <span className="text-sm font-normal text-[#525252]">/s</span>
                  </span>
                </div>
                <span className="text-[11px] text-[#737373] font-sans">
                  Backend ingestion velocity
                </span>
              </div>

              <div className="rounded-xl bg-[#FFFFFF] p-4 border border-[#E5E5E5] border-l-4 border-l-amber-500 shadow-2xs flex flex-col justify-between">
                <div className="flex items-center justify-between text-xs font-sans text-[#525252]">
                  <span className="font-mono uppercase font-semibold text-[#0A0A0A] text-[11px]">
                    Active Threat Categories
                  </span>
                  <Activity className="h-4 w-4 text-amber-600" />
                </div>
                <div className="my-2">
                  <span className="text-3xl font-bold text-amber-600 font-sans tracking-tight">
                    {Object.keys(metrics.threat_counts_by_class).length} <span className="text-sm font-normal text-[#525252]">/ 6</span>
                  </span>
                </div>
                <span className="text-[11px] text-[#737373] font-sans">
                  SIH threat classes detected
                </span>
              </div>
            </motion.section>

            {/* 3. Threat Class Distribution Chart & Severity Breakout */}
            <motion.section variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              {/* Threat Class Bar Chart */}
              <div className="lg:col-span-2 rounded-xl bg-[#FFFFFF] p-5 border border-[#E5E5E5] space-y-4 shadow-2xs flex flex-col justify-between">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 pb-3 border-b border-[#E5E5E5]">
                  <div>
                    <div className="flex items-center gap-2">
                      <AlertOctagon className="h-4 w-4 text-[#2563EB] shrink-0" />
                      <h2 className="text-xs font-bold text-[#0A0A0A] uppercase tracking-wider font-mono">
                        THREAT CATEGORY DISTRIBUTION
                      </h2>
                    </div>
                    <p className="text-xs text-[#525252] font-sans mt-0.5">
                      Authoritative threat observations by detected SIH category
                    </p>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 bg-[#F8FAFC] px-2.5 py-1 rounded border border-[#E5E5E5] self-start sm:self-auto">
                    Category Breakdown
                  </span>
                </div>

                {/* Recharts BarChart */}
                <div className="h-60 w-full pt-1">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={threatChartData}
                      margin={{ top: 5, right: 40, left: 10, bottom: 5 }}
                    >
                      <CartesianGrid stroke="#E5E5E5" strokeDasharray="3 3" horizontal={true} vertical={false} />
                      <XAxis
                        type="number"
                        stroke="#64748b"
                        fontSize={10}
                        tickLine={false}
                        allowDecimals={false}
                        axisLine={{ stroke: '#E5E5E5' }}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        stroke="#525252"
                        fontSize={11}
                        tickLine={false}
                        axisLine={{ stroke: '#E5E5E5' }}
                        width={145}
                      />
                      <Tooltip content={<CustomThreatTooltip />} cursor={{ fill: '#F5F5F5', opacity: 0.8 }} />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={18}>
                        {threatChartData.map((_entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={index === 0 ? '#2563EB' : index === 1 ? '#3B82F6' : '#60A5FA'}
                          />
                        ))}
                        <LabelList
                          dataKey="count"
                          position="right"
                          fill="#2563EB"
                          fontSize={11}
                          fontFamily="monospace"
                          fontWeight="bold"
                        />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="flex items-center justify-between text-[11px] text-[#525252] font-mono pt-2 border-t border-[#E5E5E5]">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-[#2563EB]" />
                    Categorical Threat Density
                  </span>
                  <span>Authoritative Sensor Stream</span>
                </div>
              </div>

              {/* Severity & Confidence Summary Surface */}
              <div className="rounded-xl bg-[#FFFFFF] p-5 border border-[#E5E5E5] space-y-4 flex flex-col justify-between shadow-2xs">
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                    <h2 className="text-xs font-bold text-[#0A0A0A] uppercase tracking-wider font-mono flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-rose-600" />
                      Severity Breakout
                    </h2>
                    <span className="text-xs text-slate-500 font-mono">
                      Total: {totalAlerts}
                    </span>
                  </div>

                  {/* Proportional Stacked Severity Rail */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-[#525252] font-sans">
                      <span>Proportional Distribution</span>
                    </div>
                    <div className="flex h-2.5 w-full overflow-hidden rounded bg-slate-100 border border-slate-200">
                      {criticalPct > 0 && (
                        <div
                          style={{ width: `${criticalPct}%` }}
                          className="bg-rose-500 transition-all duration-300"
                          title={`Critical: ${metrics.critical_alerts}`}
                        />
                      )}
                      {highPct > 0 && (
                        <div
                          style={{ width: `${highPct}%` }}
                          className="bg-orange-500 transition-all duration-300"
                          title={`High: ${metrics.high_alerts}`}
                        />
                      )}
                      {mediumPct > 0 && (
                        <div
                          style={{ width: `${mediumPct}%` }}
                          className="bg-amber-500 transition-all duration-300"
                          title={`Medium: ${metrics.medium_alerts}`}
                        />
                      )}
                      {lowPct > 0 && (
                        <div
                          style={{ width: `${lowPct}%` }}
                          className="bg-slate-400 transition-all duration-300"
                          title={`Low: ${metrics.low_alerts}`}
                        />
                      )}
                    </div>
                  </div>

                  {/* Aligned Severity Rows */}
                  <div className="space-y-2 pt-1 text-xs font-sans">
                    <div className="flex items-center justify-between px-2.5 py-1.5 rounded bg-rose-50 border border-rose-200">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-rose-600" aria-hidden="true" />
                        <span className="font-semibold text-rose-700 uppercase text-[11px]">Critical</span>
                      </div>
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-bold text-rose-700">{metrics.critical_alerts}</span>
                        <span className="text-[10px] text-rose-600">({criticalPct.toFixed(0)}%)</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between px-2.5 py-1.5 rounded bg-orange-50 border border-orange-200">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-orange-600" aria-hidden="true" />
                        <span className="font-semibold text-orange-700 uppercase text-[11px]">High</span>
                      </div>
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-bold text-orange-700">{metrics.high_alerts}</span>
                        <span className="text-[10px] text-orange-600">({highPct.toFixed(0)}%)</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between px-2.5 py-1.5 rounded bg-amber-50 border border-amber-200">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-amber-600" aria-hidden="true" />
                        <span className="font-semibold text-amber-700 uppercase text-[11px]">Medium</span>
                      </div>
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-bold text-amber-700">{metrics.medium_alerts}</span>
                        <span className="text-[10px] text-amber-600">({mediumPct.toFixed(0)}%)</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between px-2.5 py-1.5 rounded bg-slate-100 border border-slate-200">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-slate-500" aria-hidden="true" />
                        <span className="font-semibold text-slate-700 uppercase text-[11px]">Low</span>
                      </div>
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-bold text-slate-700">{metrics.low_alerts}</span>
                        <span className="text-[10px] text-slate-500">({lowPct.toFixed(0)}%)</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Model Confidence Breakdown */}
                <div className="pt-3 border-t border-[#E5E5E5] space-y-2">
                  <span className="text-[11px] font-mono font-semibold uppercase text-slate-500 tracking-wider">
                    Model Confidence Distribution ({loadedAlerts.length} Records)
                  </span>
                  <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                    <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-2">
                      <span className="text-emerald-700 text-[10px] block font-sans font-medium">≥90% High</span>
                      <span className="font-bold text-emerald-700 mt-0.5 block">{highConfidenceCount}</span>
                    </div>
                    <div className="rounded-lg border border-blue-200 bg-[#EFF6FF] p-2">
                      <span className="text-[#2563EB] text-[10px] block font-sans font-medium">70-89% Mod</span>
                      <span className="font-bold text-[#2563EB] mt-0.5 block">{modConfidenceCount}</span>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-100 p-2">
                      <span className="text-slate-600 text-[10px] block font-sans font-medium">&lt;70% Low</span>
                      <span className="font-bold text-slate-700 mt-0.5 block">{lowConfidenceCount}</span>
                    </div>
                  </div>
                </div>
              </div>
            </motion.section>

            {/* 4. Interactive SIH Threat Category Filter Grid */}
            <motion.section variants={itemVariants} className="space-y-3">
              <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-2">
                <h2 className="text-xs font-bold text-[#0A0A0A] uppercase tracking-wider font-mono flex items-center gap-2">
                  <AlertOctagon className="h-4 w-4 text-[#2563EB]" />
                  SIH Threat Category Telemetry Breakdown
                </h2>
                <span className="text-[11px] text-slate-500 font-mono">
                  Click category to filter table below
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {SIH_THREAT_CATEGORIES_CONFIG.map((category) => {
                  const count = getThreatCategoryCount(
                    metrics.threat_counts_by_class,
                    category.backendKeys,
                    category.legacyLabel
                  );
                  const isSelected = threatClassFilter === category.primaryKey;

                  return (
                    <button
                      key={category.id}
                      type="button"
                      onClick={() => handleCategoryClick(category.primaryKey)}
                      aria-pressed={isSelected}
                      className={`text-left transition-all rounded-xl border p-3.5 space-y-2.5 focus-ring ${
                        isSelected
                          ? 'border-[#2563EB] bg-[#EFF6FF] ring-1 ring-[#2563EB]'
                          : 'border-[#E5E5E5] bg-[#FFFFFF] hover:border-slate-300 hover:bg-[#F5F5F5]'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <ThreatClassBadge threatClass={category.label} size="sm" />
                        <span className="font-mono text-lg font-bold text-slate-100">
                          {count}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1 border-t border-[#E5E5E5]">
                        <span>Status: {count > 0 ? 'ACTIVE' : 'NO DETECTIONS'}</span>
                        <span className="text-[#2563EB] hover:underline font-sans font-medium">
                          {isSelected ? 'Filter Active' : 'Filter Alerts →'}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </motion.section>

            {/* 5. Filter Control Bar */}
            <motion.section variants={itemVariants} className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-4 shadow-2xs">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E5E5] pb-3">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#0A0A0A] font-mono">
                  <Filter className="h-4 w-4 text-[#2563EB]" />
                  <span>Category Alert Filters</span>
                </div>

                <button
                  type="button"
                  onClick={handleResetFilters}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-xs font-mono text-slate-600 hover:bg-[#F5F5F5] hover:text-[#0A0A0A] focus-ring transition-colors"
                >
                  <RotateCcw className="h-3 w-3" />
                  <span>Reset Filters</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-sans">
                {/* IP Search Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="analytics-ip-search" className="block text-[11px] font-mono text-slate-500">
                    Search IP Address
                  </label>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                    <input
                      id="analytics-ip-search"
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

                {/* Threat Class Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="analytics-class-filter" className="block text-[11px] font-mono text-slate-500">
                    SIH Threat Category
                  </label>
                  <select
                    id="analytics-class-filter"
                    value={threatClassFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setThreatClassFilter, e.target.value)
                    }
                    className="w-full rounded-lg border border-[#D4D4D4] bg-[#FFFFFF] py-1.5 px-2.5 font-mono text-xs text-[#0A0A0A] focus-ring"
                  >
                    {CANONICAL_THREAT_FILTER_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </motion.section>

            {/* 6. Authoritative Category Alert Records Table */}
            <motion.section variants={itemVariants} className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs">
              <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                <h2 className="text-xs font-bold text-[#0A0A0A] uppercase tracking-wider font-mono flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-600" />
                  Backend Category Alert Records ({alertsResponse.total})
                </h2>
              </div>

              {alertsResponse.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-[#525252] font-sans">
                  No alert records match the selected category filters.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring rounded-lg border border-[#E5E5E5]" role="region" aria-label="Detection Analytics Category Alert Dataset" tabIndex={0}>
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-[#F8FAFC] text-slate-500 uppercase tracking-wider font-mono text-[11px] border-b border-[#E5E5E5]">
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
                              className="text-[#2563EB] hover:underline font-semibold"
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
                              className="inline-flex items-center gap-1 rounded border border-[#E5E5E5] bg-[#FFFFFF] px-2 py-1 text-[11px] text-[#0A0A0A] hover:bg-[#F5F5F5] focus-ring font-mono transition-colors"
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
            </motion.section>

            {/* 7. Pagination Controls */}
            <PaginationControls
              page={alertsResponse.page}
              limit={alertsResponse.limit}
              total={alertsResponse.total}
              hasMore={alertsResponse.has_more}
              onPageChange={(newPage) => setPage(newPage)}
            />

            {/* 8. Compact Time-Series Telemetry Data Gap Notice */}
            <motion.section variants={itemVariants}>
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] px-4 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs shadow-2xs">
                <div className="flex items-center gap-2 text-[#525252]">
                  <Clock className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                  <span className="font-semibold text-[#0A0A0A] font-mono uppercase text-[11px]">
                    Detection Time-Series Telemetry:
                  </span>
                  <span className="text-[#525252] font-sans text-[11px]">
                    Historical flow rate graphs and detection latency histograms are not defined in backend telemetry schemas
                  </span>
                </div>
                <span className="inline-flex items-center rounded border border-[#E5E5E5] bg-[#F8FAFC] px-2 py-0.5 text-[10px] font-mono text-slate-500 self-start sm:self-auto">
                  BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
                </span>
              </div>
            </motion.section>
          </motion.div>
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
