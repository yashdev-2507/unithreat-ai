import type {
  ThreatAlert,
  PassiveFlow,
  NetworkFeatureRecord,
  MlPrediction,
  OverviewMetrics,
  PipelineHealthStatus,
  AlertQueryParams,
  FlowQueryParams,
  PaginatedResponse,
} from '../types';

/**
 * Common DataService interface abstraction for UniThreat AI frontend.
 * Provides a backend-decoupled contract interface for retrieving threat intelligence,
 * passive network flows, network features, ML predictions, and pipeline telemetry.
 */
export interface DataService {
  getOverviewMetrics(): Promise<OverviewMetrics>;
  getAlerts(params?: AlertQueryParams): Promise<PaginatedResponse<ThreatAlert>>;
  getFlows(params?: FlowQueryParams): Promise<PaginatedResponse<PassiveFlow>>;
  getFlowById(flowId: string): Promise<PassiveFlow | null>;
  getFeaturesByFlowId(flowId: string): Promise<NetworkFeatureRecord[]>;
  getMlPredictionsByFlowId(flowId: string): Promise<MlPrediction[]>;
  getPipelineHealth(): Promise<PipelineHealthStatus>;
}
