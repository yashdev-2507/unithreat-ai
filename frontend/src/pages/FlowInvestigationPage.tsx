import { useState, useEffect, useCallback, type FC } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ShieldAlert, Eye, ArrowLeft } from 'lucide-react';
import type { DataService } from '../services/DataService';
import type {
  PassiveFlow,
  NetworkFeatureRecord,
  MlPrediction,
  ThreatAlert,
} from '../types';
import { PageHeader } from '../components/layout/PageHeader';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ThreatClassBadge } from '../components/common/ThreatClassBadge';
import { ConfidenceGauge } from '../components/common/ConfidenceGauge';
import { DataStateWrapper, type DataState } from '../components/common/DataStateWrapper';
import { FlowMetadataPanel } from '../components/flows/FlowMetadataPanel';
import { ProtocolMetadataPanel } from '../components/flows/ProtocolMetadataPanel';
import { NetworkFeaturesTable } from '../components/flows/NetworkFeaturesTable';
import { MlPredictionsPanel } from '../components/flows/MlPredictionsPanel';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

export interface FlowInvestigationPageProps {
  dataService: DataService;
}

export const FlowInvestigationPage: FC<FlowInvestigationPageProps> = ({ dataService }) => {
  const { flowId } = useParams<{ flowId: string }>();

  const [dataState, setDataState] = useState<DataState>('loading');
  const [flow, setFlow] = useState<PassiveFlow | null>(null);
  const [features, setFeatures] = useState<NetworkFeatureRecord[]>([]);
  const [mlPredictions, setMlPredictions] = useState<MlPrediction[]>([]);
  const [relatedAlerts, setRelatedAlerts] = useState<ThreatAlert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const fetchFlowData = useCallback(async () => {
    if (!flowId) {
      setDataState('error');
      return;
    }

    setDataState('loading');
    try {
      const [flowData, featuresData, predictionsData, alertsResponse] = await Promise.all([
        dataService.getFlowById(flowId),
        dataService.getFeaturesByFlowId(flowId),
        dataService.getMlPredictionsByFlowId(flowId),
        dataService.getAlerts({ flow_id: flowId }),
      ]);

      if (!flowData) {
        setFlow(null);
        setDataState('empty');
        return;
      }

      setFlow(flowData);
      setFeatures(featuresData);
      setMlPredictions(predictionsData);
      setRelatedAlerts(alertsResponse.data);
      setDataState('ready');
    } catch {
      setDataState('error');
    }
  }, [dataService, flowId]);

  useEffect(() => {
    fetchFlowData();
  }, [fetchFlowData]);

  const handleInspectAlert = (alert: ThreatAlert) => {
    setSelectedAlert(alert);
    setIsDrawerOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title={`Flow Investigation: ${flowId || 'N/A'}`}
        description="Comprehensive passive flow metadata, protocol parameters, extracted feature records, ML model predictions, and related threat alerts."
        actions={
          <Link
            to="/flows"
            className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-mono text-slate-300 hover:bg-slate-800 hover:text-slate-100 focus-ring"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Back to Passive Flow Explorer</span>
          </Link>
        }
      />

      <DataStateWrapper state={dataState} onRetry={fetchFlowData}>
        {flow ? (
          <div className="space-y-6">
            {/* Section 1: Flow Core Parameters */}
            <FlowMetadataPanel flow={flow} />

            {/* Section 2: Passive Protocol Metadata (DNS, TLS, QUIC) */}
            <ProtocolMetadataPanel flow={flow} />

            {/* Section 3: Extracted Network Feature Records */}
            <NetworkFeaturesTable features={features} />

            {/* Section 4: Backend ML Model Predictions */}
            <MlPredictionsPanel predictions={mlPredictions} />

            {/* Section 5: Related Threat Alerts Table */}
            <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-400" />
                  Related Threat Alerts ({relatedAlerts.length})
                </h3>
                <span className="text-xs text-slate-400 font-mono">
                  Filtered by flow_id: {flow.flow_id}
                </span>
              </div>

              {relatedAlerts.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-400 font-sans">
                  No threat alerts triggered for this flow ID.
                </div>
              ) : (
                <div className="overflow-x-auto focus-ring" role="region" aria-label="Related Threat Alerts Dataset" tabIndex={0}>
                  <table className="w-full text-left text-xs font-sans">
                    <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-mono text-[11px] border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">Threat Class</th>
                        <th className="py-2.5 px-3">Confidence</th>
                        <th className="py-2.5 px-3">Source IP</th>
                        <th className="py-2.5 px-3">Destination IP</th>
                        <th className="py-2.5 px-3">Protocol</th>
                        <th className="py-2.5 px-3">Model Version</th>
                        <th className="py-2.5 px-3 text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {relatedAlerts.map((alert) => (
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
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {alert.source_ip || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {alert.destination_ip || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                            {alert.protocol || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-400 whitespace-nowrap">
                            {alert.model_version || 'N/A'}
                          </td>
                          <td className="py-2.5 px-3 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => handleInspectAlert(alert)}
                              className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-slate-200 hover:bg-slate-700 focus-ring font-mono"
                              title="Inspect alert evidence details"
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
        ) : (
          <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-8 text-center">
            <h3 className="text-base font-semibold text-slate-200 font-sans">
              Passive Flow Record Not Found
            </h3>
            <p className="mt-1 text-xs text-slate-400 font-sans max-w-md mx-auto">
              No passive flow record matching ID <code className="text-cyan-400">{flowId}</code> was found in the DataService.
            </p>
            <div className="mt-4">
              <Link
                to="/flows"
                className="inline-flex items-center gap-1.5 rounded border border-cyan-800/50 bg-cyan-950/40 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-900/50 focus-ring font-mono"
              >
                <span>Return to Flow Explorer</span>
              </Link>
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
