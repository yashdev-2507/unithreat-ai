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

/**
 * Concrete HTTP DataService for UniThreat AI frontend.
 * Communicates with the FastAPI backend REST API endpoints conforming to authoritative contracts.
 * Strictly avoids inventing cybersecurity intelligence, scores, or fake telemetry.
 */
export class HttpDataService implements DataService {
  private baseUrl: string;
  private lastFlowCount = 0;
  private lastFlowTimestamp = 0;

  constructor(baseUrl?: string) {
    const envUrl =
      typeof import.meta !== 'undefined'
        ? (import.meta.env?.VITE_API_BASE_URL as string | undefined)
        : undefined;

    this.baseUrl = (baseUrl ?? envUrl ?? 'http://localhost:8000').replace(/\/+$/, '');
  }

  /**
   * Environment indicator confirming live backend integration.
   */
  public getEnvironmentStatus(): { isMock: boolean; label: string } {
    return {
      isMock: false,
      label: 'LIVE BACKEND — REALTIME DETECTION',
    };
  }

  /**
   * Fetch aggregate overview metrics from backend GET /stats and GET /health.
   */
  public async getOverviewMetrics(): Promise<OverviewMetrics> {
    const [statsRes, healthRes, flowsRes] = await Promise.all([
      fetch(`${this.baseUrl}/stats`),
      fetch(`${this.baseUrl}/health`),
      fetch(`${this.baseUrl}/flows?limit=100`).catch(() => null),
    ]);

    if (!statsRes.ok) {
      throw new Error(`Failed to fetch stats: ${statsRes.status} ${statsRes.statusText}`);
    }
    if (!healthRes.ok) {
      throw new Error(`Failed to fetch health: ${healthRes.status} ${healthRes.statusText}`);
    }

    const stats = await statsRes.json();
    const health = await healthRes.json();

    // Compute active distinct IPs from real recent flows
    let activeSrcIps = 0;
    let activeDstIps = 0;
    if (flowsRes && flowsRes.ok) {
      try {
        const flows: PassiveFlow[] = await flowsRes.json();
        const srcSet = new Set<string>();
        const dstSet = new Set<string>();
        for (const f of flows) {
          if (f.src_ip) srcSet.add(f.src_ip);
          if (f.dst_ip) dstSet.add(f.dst_ip);
        }
        activeSrcIps = srcSet.size;
        activeDstIps = dstSet.size;
      } catch {
        // Leave at 0 if flow parse fails
      }
    }

    // Velocity computation between invocations
    const now = Date.now();
    let flowsPerSec = 0;
    if (this.lastFlowTimestamp > 0 && now > this.lastFlowTimestamp) {
      const elapsedSec = (now - this.lastFlowTimestamp) / 1000;
      const deltaFlows = (stats.total_flows_processed ?? 0) - this.lastFlowCount;
      flowsPerSec = Math.max(0, Math.round(deltaFlows / elapsedSec));
    }
    this.lastFlowCount = stats.total_flows_processed ?? 0;
    this.lastFlowTimestamp = now;

    return {
      total_flows: stats.total_flows_processed ?? 0,
      flows_per_second: flowsPerSec,
      total_alerts: stats.total_alerts_stored ?? 0,
      critical_alerts: stats.by_severity?.CRITICAL ?? 0,
      high_alerts: stats.by_severity?.HIGH ?? 0,
      medium_alerts: stats.by_severity?.MEDIUM ?? 0,
      low_alerts: stats.by_severity?.LOW ?? 0,
      active_source_ips: activeSrcIps,
      active_destination_ips: activeDstIps,
      threat_counts_by_class: stats.by_threat_class ?? {},
      ingest_status: health.status === 'ok' ? 'HEALTHY' : 'UNAVAILABLE',
    };
  }

  /**
   * Retrieve threat alerts from backend GET /alerts with optional filters and deterministic pagination.
   */
  public async getAlerts(params: AlertQueryParams = {}): Promise<PaginatedResponse<ThreatAlert>> {
    // If specific flow_id lookup requested:
    if (params.flow_id) {
      const singleRes = await fetch(`${this.baseUrl}/alerts/${encodeURIComponent(params.flow_id)}`);
      if (singleRes.status === 404) {
        return {
          data: [],
          total: 0,
          page: 1,
          limit: params.limit ?? 10,
          has_more: false,
        };
      }
      if (!singleRes.ok) {
        throw new Error(`Failed to fetch alert for flow_id ${params.flow_id}: ${singleRes.status}`);
      }
      const alert: ThreatAlert = await singleRes.json();
      return {
        data: [alert],
        total: 1,
        page: 1,
        limit: params.limit ?? 10,
        has_more: false,
      };
    }

    const query = new URLSearchParams();
    if (params.threat_class && params.threat_class !== 'ALL') {
      query.set('threat_class', params.threat_class);
    }
    if (params.severity) {
      query.set('severity', params.severity);
    }
    if (params.min_confidence !== undefined) {
      query.set('min_confidence', params.min_confidence.toString());
    }
    // Retrieve up to 1000 items from backend bounded store
    query.set('limit', '1000');

    const url = `${this.baseUrl}/alerts${query.toString() ? `?${query.toString()}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to fetch alerts: ${res.status} ${res.statusText}`);
    }

    let alerts: ThreatAlert[] = await res.json();

    // Client-side filtering for parameters not handled natively by the backend ring-buffer
    if (params.max_confidence !== undefined) {
      alerts = alerts.filter((a) => a.confidence <= params.max_confidence!);
    }
    if (params.search_ip) {
      const q = params.search_ip.toLowerCase();
      alerts = alerts.filter(
        (a) =>
          (a.source_ip && a.source_ip.toLowerCase().includes(q)) ||
          (a.destination_ip && a.destination_ip.toLowerCase().includes(q))
      );
    }
    if (params.start_time) {
      const startTime = new Date(params.start_time).getTime();
      alerts = alerts.filter((a) => new Date(a.timestamp).getTime() >= startTime);
    }
    if (params.end_time) {
      const endTime = new Date(params.end_time).getTime();
      alerts = alerts.filter((a) => new Date(a.timestamp).getTime() <= endTime);
    }

    const page = Math.max(1, params.page ?? 1);
    const limit = Math.max(1, params.limit ?? 10);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedData = alerts.slice(startIndex, endIndex);

    return {
      data: paginatedData,
      total: alerts.length,
      page,
      limit,
      has_more: endIndex < alerts.length,
    };
  }

  /**
   * Retrieve passive network flows from backend GET /flows with optional filters and deterministic pagination.
   */
  public async getFlows(params: FlowQueryParams = {}): Promise<PaginatedResponse<PassiveFlow>> {
    const query = new URLSearchParams();
    if (params.protocol) {
      query.set('protocol', params.protocol);
    }
    query.set('limit', '2000');

    const url = `${this.baseUrl}/flows${query.toString() ? `?${query.toString()}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to fetch flows: ${res.status} ${res.statusText}`);
    }

    let flows: PassiveFlow[] = await res.json();

    if (params.direction) {
      flows = flows.filter((f) => f.direction === params.direction);
    }
    if (params.search_ip) {
      const q = params.search_ip.toLowerCase();
      flows = flows.filter(
        (f) =>
          (f.src_ip && f.src_ip.toLowerCase().includes(q)) ||
          (f.dst_ip && f.dst_ip.toLowerCase().includes(q))
      );
    }
    if (params.start_time) {
      const startTime = new Date(params.start_time).getTime();
      flows = flows.filter((f) => new Date(f.timestamp).getTime() >= startTime);
    }
    if (params.end_time) {
      const endTime = new Date(params.end_time).getTime();
      flows = flows.filter((f) => new Date(f.timestamp).getTime() <= endTime);
    }

    const page = Math.max(1, params.page ?? 1);
    const limit = Math.max(1, params.limit ?? 10);
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedData = flows.slice(startIndex, endIndex);

    return {
      data: paginatedData,
      total: flows.length,
      page,
      limit,
      has_more: endIndex < flows.length,
    };
  }

  /**
   * Retrieve a specific raw flow record by flow_id from GET /flows/{flow_id}.
   */
  public async getFlowById(flowId: string): Promise<PassiveFlow | null> {
    const res = await fetch(`${this.baseUrl}/flows/${encodeURIComponent(flowId)}`);
    if (res.status === 404) {
      return null;
    }
    if (!res.ok) {
      throw new Error(`Failed to fetch flow ${flowId}: ${res.status} ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Retrieve extracted network feature records by flow_id from GET /features/{flow_id}.
   */
  public async getFeaturesByFlowId(flowId: string): Promise<NetworkFeatureRecord[]> {
    const res = await fetch(`${this.baseUrl}/features/${encodeURIComponent(flowId)}`);
    if (res.status === 404) {
      return [];
    }
    if (!res.ok) {
      throw new Error(`Failed to fetch features for ${flowId}: ${res.status} ${res.statusText}`);
    }
    const feat = await res.json();
    return feat ? [feat] : [];
  }

  /**
   * Retrieve ML prediction results by flow_id from GET /predictions/{flow_id}.
   */
  public async getMlPredictionsByFlowId(flowId: string): Promise<MlPrediction[]> {
    const res = await fetch(`${this.baseUrl}/predictions/${encodeURIComponent(flowId)}`);
    if (res.status === 404) {
      return [];
    }
    if (!res.ok) {
      throw new Error(`Failed to fetch ML predictions for ${flowId}: ${res.status} ${res.statusText}`);
    }
    const pred = await res.json();
    return pred ? [pred] : [];
  }

  /**
   * Retrieve pipeline health telemetry from GET /health.
   */
  public async getPipelineHealth(): Promise<PipelineHealthStatus> {
    const res = await fetch(`${this.baseUrl}/health`);
    if (!res.ok) {
      throw new Error(`Failed to fetch pipeline health: ${res.status} ${res.statusText}`);
    }
    const data = await res.json();
    const isOk = data.status === 'ok';

    const bufferUsage =
      data.total_alerts_stored !== undefined
        ? Math.min(100, Math.round((data.total_alerts_stored / 1000) * 100))
        : 0;

    return {
      ingest_mode: 'LIVE',
      pipeline_status: isOk ? 'HEALTHY' : 'DEGRADED',
      flows_per_second: 0,
      buffer_usage_percentage: bufferUsage,
      last_updated: new Date().toISOString(),
    };
  }
}
