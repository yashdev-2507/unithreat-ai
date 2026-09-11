import { useState, useEffect, useCallback, useMemo, type FC, type ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  Brain,
  Cpu,
  Layers,
  CheckCircle2,
  Filter,
  RotateCcw,
  Search,
  Eye,
  Info,
  ShieldCheck,
  Gauge,
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
  MlPrediction,
} from '../types';
import { CANONICAL_THREAT_FILTER_OPTIONS } from '../constants/threats';
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

/** SIH 6 Core Threat Categories */
const SIH_THREAT_CATEGORIES = [
  'Volumetric / Protocol DDoS',
  'Botnet C2 Beaconing',
  'DGA / DNS Tunneling',
  'Malware Inside Encrypted Sessions',
  'Reconnaissance / Port Scanning',
  'Data Exfiltration',
] as const;

/** Color mapping per threat category using restrained UniThreat cyan/teal palette */
const THREAT_COLOR_MAP: Record<string, string> = {
  'Volumetric / Protocol DDoS': '#06b6d4', // cyan-500
  'Botnet C2 Beaconing': '#0891b2', // cyan-600
  'DGA / DNS Tunneling': '#0284c7', // sky-600
  'Malware Inside Encrypted Sessions': '#38bdf8', // sky-400
  'Reconnaissance / Port Scanning': '#22d3ee', // cyan-400
  'Data Exfiltration': '#14b8a6', // teal-500
};

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 6 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.2 } },
};

// Concise threat category presentation labels without altering authoritative backend data
function getShortThreatLabel(fullThreatClass: string): string {
  const tc = (fullThreatClass || '').toLowerCase();
  if (tc.includes('ddos') || tc.includes('volumetric')) return 'DDoS / Volumetric';
  if (tc.includes('botnet') || tc.includes('beacon') || tc.includes('c2')) return 'Botnet C2';
  if (tc.includes('dga') || tc.includes('dns')) return 'DGA / DNS Tunnel';
  if (tc.includes('encrypted') || tc.includes('malware')) return 'Encrypted Malware';
  if (tc.includes('recon') || tc.includes('scan')) return 'Recon / Port Scan';
  if (tc.includes('exfiltration') || tc.includes('data')) return 'Data Exfiltration';
  return fullThreatClass;
}

// Render calibration status pill based strictly on backend field
function renderCalibrationPill(calibrated?: boolean | null) {
  if (calibrated === true) {
    return <StatusPill status="CALIBRATED" size="sm" />;
  }
  if (calibrated === false) {
    return <StatusPill status="NOT CALIBRATED" size="sm" />;
  }
  return (
    <span className="font-mono text-[10px] text-slate-500 bg-[#F8FAFC] border border-[#E5E5E5] px-2 py-0.5 rounded-md">
      CALIBRATION UNAVAILABLE
    </span>
  );
}

// Custom Tooltip popover for ML threat prediction distribution
const CustomThreatTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-3 shadow-lg text-xs font-sans space-y-1.5 min-w-[200px]">
        <div className="flex items-center gap-2 border-b border-[#E5E5E5] pb-1.5">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: data.fill }} />
          <span className="font-semibold text-[#0A0A0A] font-mono text-[11px]">{data.name}</span>
        </div>
        <div className="text-[#525252] text-[11px]">
          Category: <span className="font-medium text-[#0A0A0A]">{data.fullName}</span>
        </div>
        <div className="text-[#2563EB] font-mono font-bold text-xs pt-0.5 flex justify-between items-center">
          <span>Inferences:</span>
          <span>
            {data.count} {data.count === 1 ? 'record' : 'records'}
          </span>
        </div>
      </div>
    );
  }
  return null;
};

export const MlIntelligencePage: FC<MlIntelligencePageProps> = ({ dataService }) => {
  const [dataState, setDataState] = useState<DataState>('loading');
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [alertsResponse, setAlertsResponse] = useState<PaginatedResponse<ThreatAlert> | null>(null);
  const [predictionsMap, setPredictionsMap] = useState<Record<string, MlPrediction>>({});
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

      // Fetch actual backend predictions to inspect calibration status
      const uniqueFlowIds = Array.from(
        new Set(alertsData.data.map((a) => a.flow_id).filter((id): id is string => Boolean(id)))
      );
      if (uniqueFlowIds.length > 0) {
        const predEntries = await Promise.all(
          uniqueFlowIds.map(async (fId) => {
            try {
              const preds = await dataService.getMlPredictionsByFlowId(fId);
              return [fId, preds[0] || null] as const;
            } catch {
              return [fId, null] as const;
            }
          })
        );
        const newPredMap: Record<string, MlPrediction> = {};
        for (const [fId, pred] of predEntries) {
          if (pred) {
            newPredMap[fId] = pred;
          }
        }
        setPredictionsMap(newPredMap);
      } else {
        setPredictionsMap({});
      }

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

  // Derive unique model versions dynamically from authoritative backend data
  const uniqueModelVersions = useMemo(() => {
    if (!alertsResponse?.data) return [];
    return Array.from(
      new Set(
        alertsResponse.data
          .map((a) => a.model_version)
          .filter((mv): mv is string => Boolean(mv))
      )
    );
  }, [alertsResponse]);

  // Data-driven primary model version string (no hardcoded fallbacks)
  const primaryModelVersion = useMemo(() => {
    if (uniqueModelVersions.length === 0) return 'UNSPECIFIED';
    return uniqueModelVersions.join(', ');
  }, [uniqueModelVersions]);

  // Derive threat prediction distribution for Recharts horizontal BarChart
  const threatDistributionData = useMemo(() => {
    if (!metrics?.threat_counts_by_class) return [];

    return SIH_THREAT_CATEGORIES.map((cat) => {
      const matchingKey = Object.keys(metrics.threat_counts_by_class).find(
        (k) =>
          k.toLowerCase() === cat.toLowerCase() ||
          getShortThreatLabel(k) === getShortThreatLabel(cat)
      );
      const count = matchingKey ? metrics.threat_counts_by_class[matchingKey] : 0;
      return {
        name: getShortThreatLabel(cat),
        fullName: cat,
        count,
        fill: THREAT_COLOR_MAP[cat] || '#06b6d4',
      };
    });
  }, [metrics]);

  // Derive Model Confidence Breakdown stats across loaded dataset (Strict thresholds: ≥90%, 70-89%, <70%)
  const confidenceStats = useMemo(() => {
    if (!alertsResponse?.data || alertsResponse.data.length === 0) {
      return {
        highCount: 0,
        highPct: 0,
        medCount: 0,
        medPct: 0,
        lowCount: 0,
        lowPct: 0,
        avgConfidence: 0,
        totalCount: 0,
      };
    }

    const data = alertsResponse.data;
    const total = data.length;
    let high = 0;
    let med = 0;
    let low = 0;
    let sumConf = 0;

    for (const a of data) {
      const c = a.confidence;
      sumConf += c;
      if (c >= 0.9) {
        high++;
      } else if (c >= 0.7) {
        med++;
      } else {
        low++;
      }
    }

    return {
      highCount: high,
      highPct: Math.round((high / total) * 100),
      medCount: med,
      medPct: Math.round((med / total) * 100),
      lowCount: low,
      lowPct: Math.round((low / total) * 100),
      avgConfidence: (sumConf / total) * 100,
      totalCount: total,
    };
  }, [alertsResponse]);

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6 pb-8"
    >
      {/* Command Header */}
      <motion.div
        variants={itemVariants}
        className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#E5E5E5] pb-5"
      >
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl sm:text-[32px] font-bold tracking-tight text-[#0A0A0A] font-sans leading-tight">
              ML Intelligence
            </h1>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-blue-200 bg-[#EFF6FF] px-2.5 py-1 text-xs font-mono font-medium text-[#2563EB]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#2563EB] animate-pulse" />
              PASSIVE ML ANALYSIS — READ ONLY
            </span>
          </div>
          <p className="text-sm sm:text-[15px] text-[#525252] mt-1.5 font-sans leading-relaxed">
            Model predictions and confidence across passively observed traffic
          </p>
        </div>

        {/* Live Ingest / Engine Provenance Badge */}
        <div className="flex items-center gap-2">
          <div className="inline-flex items-center gap-2 rounded-lg border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1.5 text-xs font-mono text-[#0A0A0A] shadow-2xs">
            <Cpu className="h-4 w-4 text-[#2563EB]" />
            <span className="text-[#525252]">ENGINE:</span>
            <span className="text-[#2563EB] font-semibold">{primaryModelVersion}</span>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" title="Engine Status: Active" />
          </div>
        </div>
      </motion.div>

      {/* Unexposed Offline ML Evaluation Telemetry Notice */}
      <motion.div
        variants={itemVariants}
        className="rounded-xl border border-blue-200 bg-[#EFF6FF] p-4 font-mono text-xs text-[#2563EB] flex items-start gap-3 shadow-2xs"
      >
        <Info className="h-5 w-5 text-[#2563EB] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-[#1D4ED8] uppercase tracking-wider text-[11px]">
            BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
          </div>
          <p className="font-sans text-[#525252] text-xs leading-relaxed">
            Offline ML evaluation metrics (Model Accuracy, Precision, Recall, F1 Score, Confusion Matrix, ROC-AUC curves, Feature Importance, Loss, and Data Drift) are not defined in backend contracts/API schemas. Per project architectural rules, the frontend does NOT invent model performance metrics and displays authoritative inference records provided by the backend.
          </p>
        </div>
      </motion.div>

      <DataStateWrapper state={dataState} onRetry={fetchMlData}>
        {metrics && alertsResponse && (
          <div className="space-y-6">
            {/* Primary ML Signal Cards */}
            <motion.section
              variants={itemVariants}
              className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
            >
              {/* Card 1: Total Alert Records */}
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 shadow-2xs relative overflow-hidden">
                <div className="absolute top-0 right-0 h-16 w-16 bg-blue-500/5 rounded-bl-full pointer-events-none" />
                <div className="flex items-center justify-between text-[#525252] text-xs font-mono mb-2">
                  <span>TOTAL ALERT RECORDS</span>
                  <Brain className="h-4 w-4 text-[#2563EB]" />
                </div>
                <div className="text-2xl font-bold font-mono text-[#0A0A0A] tracking-tight">
                  {alertsResponse.total.toLocaleString()}
                </div>
                <div className="text-[11px] font-sans text-[#525252] mt-1 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#2563EB] shrink-0" />
                  Authoritative alert records in query result
                </div>
              </div>

              {/* Card 2: Monitored Flows */}
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 shadow-2xs relative overflow-hidden">
                <div className="absolute top-0 right-0 h-16 w-16 bg-blue-500/5 rounded-bl-full pointer-events-none" />
                <div className="flex items-center justify-between text-[#525252] text-xs font-mono mb-2">
                  <span>MONITORED FLOWS</span>
                  <Layers className="h-4 w-4 text-[#2563EB]" />
                </div>
                <div className="text-2xl font-bold font-mono text-[#0A0A0A] tracking-tight">
                  {metrics.total_flows.toLocaleString()}
                </div>
                <div className="text-[11px] font-sans text-[#525252] mt-1 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-blue-500 shrink-0" />
                  Passive flow dataset size
                </div>
              </div>

              {/* Card 3: Active Model Version */}
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 shadow-2xs relative overflow-hidden">
                <div className="absolute top-0 right-0 h-16 w-16 bg-emerald-500/5 rounded-bl-full pointer-events-none" />
                <div className="flex items-center justify-between text-[#525252] text-xs font-mono mb-2">
                  <span>MODEL VERSION</span>
                  <Cpu className="h-4 w-4 text-emerald-500" />
                </div>
                <div className="text-sm font-bold font-mono text-[#2563EB] truncate mt-1">
                  {primaryModelVersion}
                </div>
                <div className="text-[11px] font-sans text-[#525252] mt-2 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 shrink-0" />
                  <span>Backend model version</span>
                </div>
              </div>

              {/* Card 4: High Confidence Predictions (≥ 90%) */}
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 shadow-2xs relative overflow-hidden">
                <div className="absolute top-0 right-0 h-16 w-16 bg-emerald-500/5 rounded-bl-full pointer-events-none" />
                <div className="flex items-center justify-between text-[#525252] text-xs font-mono mb-2">
                  <span>HIGH CONFIDENCE (≥90%)</span>
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                </div>
                <div className="text-2xl font-bold font-mono text-[#0A0A0A] tracking-tight">
                  {confidenceStats.highCount}
                  <span className="text-xs text-[#525252] ml-2 font-normal font-sans">
                    ({confidenceStats.highPct}%)
                  </span>
                </div>
                <div className="text-[11px] font-sans text-[#525252] mt-1 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 shrink-0" />
                  Current batch high-confidence records
                </div>
              </div>
            </motion.section>

            {/* Model Identity & Pipeline Specifications Banner */}
            <motion.section
              variants={itemVariants}
              className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 font-sans text-xs space-y-3 shadow-2xs"
            >
              <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-2.5">
                <div className="flex items-center gap-2 font-mono text-xs font-semibold text-[#0A0A0A] uppercase tracking-wider">
                  <ShieldCheck className="h-4 w-4 text-[#2563EB]" />
                  <span>Model Pipeline Specifications</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-[#2563EB] bg-[#EFF6FF] border border-blue-200 px-2 py-0.5 rounded-md">
                    PASSIVE INFERENCE
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-[#525252] pt-1 font-mono text-[11px]">
                <div className="space-y-1">
                  <div className="text-slate-400 uppercase text-[10px]">Active Model Version</div>
                  <div className="font-semibold text-[#0A0A0A]">{primaryModelVersion}</div>
                </div>

                <div className="space-y-1">
                  <div className="text-slate-400 uppercase text-[10px]">Feature Space</div>
                  <div className="font-semibold text-[#0A0A0A]">
                    Passive Unidirectional Flow Metadata
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="text-slate-400 uppercase text-[10px]">Operational Constraint</div>
                  <div className="font-semibold text-[#2563EB]">
                    Strictly Read-Only (Zero Return-Path Injection)
                  </div>
                </div>
              </div>
            </motion.section>

            {/* Visual Analytics Surface (Threat Distribution + Model Confidence Breakdown) */}
            <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column (7 cols): Threat Class Prediction Distribution */}
              <div className="lg:col-span-7 rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs flex flex-col justify-between">
                <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                  <div>
                    <h2 className="text-sm font-semibold text-[#0A0A0A] uppercase tracking-wider font-mono flex items-center gap-2">
                      <Brain className="h-4 w-4 text-[#2563EB]" />
                      Threat Class Prediction Distribution
                    </h2>
                    <p className="text-[11px] text-[#525252] font-sans mt-0.5">
                      Model classifications across the 6 SIH threat categories
                    </p>
                  </div>
                  <span className="font-mono text-[11px] text-[#525252] bg-[#F8FAFC] border border-[#E5E5E5] px-2 py-0.5 rounded-md">
                    AUTHORITATIVE COUNTS
                  </span>
                </div>

                {/* Horizontal Recharts BarChart */}
                <div className="h-[280px] w-full pt-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      layout="vertical"
                      data={threatDistributionData}
                      margin={{ top: 5, right: 35, left: 10, bottom: 5 }}
                    >
                      <CartesianGrid horizontal={false} stroke="#E5E5E5" strokeDasharray="3 3" />
                      <XAxis
                        type="number"
                        tick={{ fill: '#525252', fontSize: 10, fontFamily: 'monospace' }}
                        axisLine={{ stroke: '#E5E5E5' }}
                        tickLine={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        tick={{ fill: '#0A0A0A', fontSize: 11, fontFamily: 'sans-serif' }}
                        axisLine={{ stroke: '#E5E5E5' }}
                        tickLine={false}
                        width={130}
                      />
                      <Tooltip content={<CustomThreatTooltip />} cursor={{ fill: 'rgba(0,0,0,0.02)' }} />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={18}>
                        {threatDistributionData.map((entry) => (
                          <Cell key={`cell-${entry.fullName}`} fill={entry.fill} />
                        ))}
                        <LabelList
                          dataKey="count"
                          position="right"
                          fill="#525252"
                          style={{ fontSize: '11px', fontFamily: 'monospace', fontWeight: 600 }}
                        />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Right Column (5 cols): Model Confidence Breakdown */}
              <div className="lg:col-span-5 rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs flex flex-col justify-between">
                <div className="border-b border-[#E5E5E5] pb-3">
                  <h2 className="text-sm font-semibold text-[#0A0A0A] uppercase tracking-wider font-mono flex items-center gap-2">
                    <Gauge className="h-4 w-4 text-[#2563EB]" />
                    Model Confidence Breakdown
                  </h2>
                  <p className="text-[11px] text-[#525252] font-sans mt-0.5">
                    Confidence distribution across current retrieved predictions
                  </p>
                </div>

                <div className="space-y-4 font-sans text-xs">
                  {/* High Confidence Bar (≥ 90%) */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between items-center font-mono">
                      <span className="text-[#0A0A0A] font-medium flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full bg-emerald-500" />
                        High Confidence (≥ 90%)
                      </span>
                      <span className="text-emerald-600 font-bold">
                        {confidenceStats.highCount} ({confidenceStats.highPct}%)
                      </span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-[#F1F5F9] border border-[#E2E8F0] overflow-hidden">
                      <div
                        className="h-full bg-emerald-500 rounded-full transition-all duration-300"
                        style={{ width: `${confidenceStats.highPct}%` }}
                      />
                    </div>
                  </div>

                  {/* Moderate Confidence Bar (70% - 89%) */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between items-center font-mono">
                      <span className="text-[#0A0A0A] font-medium flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full bg-amber-500" />
                        Moderate Confidence (70% – 89%)
                      </span>
                      <span className="text-amber-600 font-bold">
                        {confidenceStats.medCount} ({confidenceStats.medPct}%)
                      </span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-[#F1F5F9] border border-[#E2E8F0] overflow-hidden">
                      <div
                        className="h-full bg-amber-500 rounded-full transition-all duration-300"
                        style={{ width: `${confidenceStats.medPct}%` }}
                      />
                    </div>
                  </div>

                  {/* Low Confidence Bar (< 70%) */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between items-center font-mono">
                      <span className="text-[#0A0A0A] font-medium flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full bg-slate-400" />
                        Low Confidence (&lt; 70%)
                      </span>
                      <span className="text-[#525252] font-bold">
                        {confidenceStats.lowCount} ({confidenceStats.lowPct}%)
                      </span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-[#F1F5F9] border border-[#E2E8F0] overflow-hidden">
                      <div
                        className="h-full bg-slate-400 rounded-full transition-all duration-300"
                        style={{ width: `${confidenceStats.lowPct}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Mean Prediction Score Summary Box */}
                <div className="rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3 text-xs font-mono space-y-1.5">
                  <div className="flex justify-between items-center">
                    <span className="text-[#525252]">MEAN PREDICTION SCORE:</span>
                    <span className="text-[#2563EB] font-bold">
                      {confidenceStats.avgConfidence.toFixed(1)}%
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-500 font-sans">
                    Aggregate of returned prediction scores; not model accuracy.
                  </p>
                </div>
              </div>
            </motion.div>

            {/* Filter Control Bar */}
            <motion.div
              variants={itemVariants}
              className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-4 shadow-2xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E5E5] pb-3">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#0A0A0A] font-mono">
                  <Filter className="h-4 w-4 text-[#2563EB]" />
                  <span>ML Prediction Dataset Filters</span>
                </div>

                <button
                  type="button"
                  onClick={handleResetFilters}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-xs font-mono text-[#0A0A0A] hover:bg-[#F5F5F5] transition-colors focus-ring"
                >
                  <RotateCcw className="h-3 w-3 text-[#525252]" />
                  <span>Reset Filters</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-sans">
                {/* Search IP Filter */}
                <div className="space-y-1.5">
                  <label htmlFor="ml-ip-search" className="block text-[11px] font-mono text-[#525252]">
                    Search IP Address
                  </label>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                    <input
                      id="ml-ip-search"
                      type="text"
                      value={searchIpInput}
                      onChange={(e: ChangeEvent<HTMLInputElement>) =>
                        handleFilterChange(setSearchIpInput, e.target.value)
                      }
                      placeholder="Filter by source or dest IP..."
                      className="w-full rounded-md border border-[#E5E5E5] bg-[#FFFFFF] py-1.5 pl-8 pr-3 font-mono text-xs text-[#0A0A0A] placeholder-slate-400 focus-ring"
                    />
                  </div>
                </div>

                {/* Threat Class Dropdown */}
                <div className="space-y-1.5">
                  <label htmlFor="ml-class-filter" className="block text-[11px] font-mono text-[#525252]">
                    Threat Class Prediction
                  </label>
                  <select
                    id="ml-class-filter"
                    value={threatClassFilter}
                    onChange={(e: ChangeEvent<HTMLSelectElement>) =>
                      handleFilterChange(setThreatClassFilter, e.target.value)
                    }
                    className="w-full rounded-md border border-[#E5E5E5] bg-[#FFFFFF] py-1.5 px-2.5 font-mono text-xs text-[#0A0A0A] focus-ring"
                  >
                    {CANONICAL_THREAT_FILTER_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </motion.div>

            {/* Authoritative ML Predictions Dataset Table */}
            <motion.div
              variants={itemVariants}
              className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs"
            >
              <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
                <h3 className="text-sm font-semibold text-[#0A0A0A] uppercase tracking-wider font-mono flex items-center gap-2">
                  <Brain className="h-4 w-4 text-[#2563EB]" />
                  Authoritative Threat Alert Records ({alertsResponse.total})
                </h3>
              </div>

              {alertsResponse.data.length === 0 ? (
                <div className="py-8 text-center text-xs text-[#525252] font-sans">
                  No ML model prediction records match the specified filters.
                </div>
              ) : (
                <div
                  className="overflow-x-auto focus-ring"
                  role="region"
                  aria-label="ML Inferences Dataset"
                  tabIndex={0}
                >
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-[#F8FAFC] text-[#525252] uppercase tracking-wider font-mono text-[11px] border-b border-[#E5E5E5]">
                      <tr>
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">Threat Class</th>
                        <th className="py-2.5 px-3">Model Confidence</th>
                        <th className="py-2.5 px-3">Flow ID</th>
                        <th className="py-2.5 px-3">Source / Dest IP</th>
                        <th className="py-2.5 px-3">Model Version</th>
                        <th className="py-2.5 px-3">Calibration Status</th>
                        <th className="py-2.5 px-3 text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#E5E5E5]">
                      {alertsResponse.data.map((alert) => (
                        <tr
                          key={`${alert.flow_id}-${alert.timestamp}-${alert.threat_class}`}
                          className="hover:bg-[#F5F5F5] transition-colors"
                        >
                          <td className="py-2.5 px-3 font-mono text-[#525252] whitespace-nowrap">
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
                            <span>{alert.source_ip || 'N/A'}</span>
                            <span className="text-slate-400 mx-1">→</span>
                            <span>{alert.destination_ip || 'N/A'}</span>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[#2563EB] text-[11px] whitespace-nowrap font-semibold">
                            {alert.model_version || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            {(() => {
                              const pred = alert.flow_id ? predictionsMap[alert.flow_id] : null;
                              if (pred?.calibrated === true) {
                                return <StatusPill status="CALIBRATED" size="sm" />;
                              }
                              return (
                                <StatusPill
                                  status="UNCALIBRATED · RF VOTING"
                                  size="sm"
                                />
                              );
                            })()}
                          </td>
                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => handleInspectAlert(alert)}
                              className="inline-flex items-center gap-1 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2 py-1 text-[11px] text-[#0A0A0A] hover:bg-[#F5F5F5] transition-colors focus-ring font-mono"
                              title="Inspect ML evidence details"
                            >
                              <Eye className="h-3 w-3 text-[#2563EB]" />
                              <span>Details</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </motion.div>

            {/* Pagination Controls */}
            <motion.div variants={itemVariants}>
              <PaginationControls
                page={alertsResponse.page}
                limit={alertsResponse.limit}
                total={alertsResponse.total}
                hasMore={alertsResponse.has_more}
                onPageChange={(newPage) => setPage(newPage)}
              />
            </motion.div>
          </div>
        )}
      </DataStateWrapper>

      {/* Alert Detail Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </motion.div>
  );
};
