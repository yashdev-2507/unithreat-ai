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
import type { DataService } from './DataService';
import {
  MOCK_ALERTS,
  MOCK_FLOWS,
  MOCK_FEATURES,
  MOCK_ML_PREDICTIONS,
  MOCK_OVERVIEW_METRICS,
  MOCK_PIPELINE_HEALTH,
  MOCK_DATA_ENVIRONMENT_BANNER,
} from './mockData';

/**
 * Deterministic, contract-compliant mock data service for UniThreat AI frontend.
 * Provides simulated passive network traffic observations and threat intelligence.
 */
export class MockDataService implements DataService {
  private alerts: ThreatAlert[];
  private flows: PassiveFlow[];
  private features: NetworkFeatureRecord[];
  private mlPredictions: MlPrediction[];
  private overviewMetrics: OverviewMetrics;
  private pipelineHealth: PipelineHealthStatus;

  constructor(
    customData?: {
      alerts?: ThreatAlert[];
      flows?: PassiveFlow[];
      features?: NetworkFeatureRecord[];
      mlPredictions?: MlPrediction[];
      overviewMetrics?: OverviewMetrics;
      pipelineHealth?: PipelineHealthStatus;
    }
  ) {
    this.alerts = customData?.alerts ?? [...MOCK_ALERTS];
    this.flows = customData?.flows ?? [...MOCK_FLOWS];
    this.features = customData?.features ?? [...MOCK_FEATURES];
    this.mlPredictions = customData?.mlPredictions ?? [...MOCK_ML_PREDICTIONS];
    this.overviewMetrics = customData?.overviewMetrics ?? { ...MOCK_OVERVIEW_METRICS };
    this.pipelineHealth = customData?.pipelineHealth ?? { ...MOCK_PIPELINE_HEALTH };
  }

  /**
   * Environment indicator confirming mock data usage.
   */
  public getEnvironmentStatus(): { isMock: boolean; label: string } {
    return {
      isMock: true,
      label: MOCK_DATA_ENVIRONMENT_BANNER,
    };
  }

  /**
   * Retrieve threat alerts matching optional filter criteria with deterministic pagination.
   */
  public async getAlerts(params: AlertQueryParams = {}): Promise<PaginatedResponse<ThreatAlert>> {
    let filtered = [...this.alerts];

    if (params.severity) {
      filtered = filtered.filter((a) => a.severity === params.severity);
    }

    if (params.threat_class) {
      filtered = filtered.filter((a) => a.threat_class === params.threat_class);
    }

    if (params.min_confidence !== undefined) {
      filtered = filtered.filter((a) => a.confidence >= params.min_confidence!);
    }

    if (params.max_confidence !== undefined) {
      filtered = filtered.filter((a) => a.confidence <= params.max_confidence!);
    }

    if (params.search_ip) {
      const query = params.search_ip.toLowerCase();
      filtered = filtered.filter(
        (a) =>
          (a.source_ip && a.source_ip.toLowerCase().includes(query)) ||
          (a.destination_ip && a.destination_ip.toLowerCase().includes(query))
      );
    }

    if (params.flow_id) {
      filtered = filtered.filter((a) => a.flow_id === params.flow_id);
    }

    if (params.start_time) {
      const startTime = new Date(params.start_time).getTime();
      filtered = filtered.filter((a) => new Date(a.timestamp).getTime() >= startTime);
    }

    if (params.end_time) {
      const endTime = new Date(params.end_time).getTime();
      filtered = filtered.filter((a) => new Date(a.timestamp).getTime() <= endTime);
    }

    const page = Math.max(1, params.page ?? 1);
    const limit = Math.max(1, params.limit ?? 10);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedData = filtered.slice(startIndex, endIndex);

    return {
      data: paginatedData,
      total: filtered.length,
      page,
      limit,
      has_more: endIndex < filtered.length,
    };
  }

  /**
   * Retrieve passive network flows matching optional filter criteria with deterministic pagination.
   */
  public async getFlows(params: FlowQueryParams = {}): Promise<PaginatedResponse<PassiveFlow>> {
    let filtered = [...this.flows];

    if (params.protocol) {
      const query = params.protocol.toLowerCase();
      filtered = filtered.filter((f) => f.protocol.toLowerCase() === query);
    }

    if (params.direction) {
      filtered = filtered.filter((f) => f.direction === params.direction);
    }

    if (params.search_ip) {
      const query = params.search_ip.toLowerCase();
      filtered = filtered.filter(
        (f) => f.src_ip.toLowerCase().includes(query) || f.dst_ip.toLowerCase().includes(query)
      );
    }

    if (params.start_time) {
      const startTime = new Date(params.start_time).getTime();
      filtered = filtered.filter((f) => new Date(f.timestamp).getTime() >= startTime);
    }

    if (params.end_time) {
      const endTime = new Date(params.end_time).getTime();
      filtered = filtered.filter((f) => new Date(f.timestamp).getTime() <= endTime);
    }

    const page = Math.max(1, params.page ?? 1);
    const limit = Math.max(1, params.limit ?? 10);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedData = filtered.slice(startIndex, endIndex);

    return {
      data: paginatedData,
      total: filtered.length,
      page,
      limit,
      has_more: endIndex < filtered.length,
    };
  }

  /**
   * Retrieve a specific passive flow record by its flow_id.
   */
  public async getFlowById(flowId: string): Promise<PassiveFlow | null> {
    const flow = this.flows.find((f) => f.flow_id === flowId);
    return flow ? { ...flow } : null;
  }

  /**
   * Retrieve all network feature records corresponding to a flow_id.
   */
  public async getFeaturesByFlowId(flowId: string): Promise<NetworkFeatureRecord[]> {
    return this.features.filter((ft) => ft.flow_id === flowId);
  }

  /**
   * Retrieve all ML prediction records corresponding to a flow_id.
   */
  public async getMlPredictionsByFlowId(flowId: string): Promise<MlPrediction[]> {
    return this.mlPredictions.filter((p) => p.flow_id === flowId);
  }

  /**
   * Retrieve simulated aggregate overview metrics.
   */
  public async getOverviewMetrics(): Promise<OverviewMetrics> {
    return { ...this.overviewMetrics };
  }

  /**
   * Retrieve simulated pipeline health telemetry status.
   */
  public async getPipelineHealth(): Promise<PipelineHealthStatus> {
    return { ...this.pipelineHealth };
  }
}

/** Default singleton instance of MockDataService */
export const mockDataService = new MockDataService();
