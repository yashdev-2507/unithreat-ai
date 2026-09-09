/**
 * API & Transport Models (Separated from Authoritative Contracts)
 *
 * NOTE: Any endpoint paths, query parameter structures, system telemetry shapes,
 * or wrapper objects not defined in contracts/ are explicitly marked as:
 * BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
 */

import type { SeverityLevel } from './alert';

/** Transport connection status between frontend and DataService/backend */
export type TransportStatus = 'CONNECTED' | 'DISCONNECTED' | 'RECONNECTING';

/** Pipeline ingest mode */
export type IngestMode = 'LIVE' | 'REPLAY';

/** Standard Paginated Response Envelope */
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  has_more: boolean;
}

/** Alert Query Filters */
export interface AlertQueryParams {
  page?: number;
  limit?: number;
  severity?: SeverityLevel;
  threat_class?: string;
  min_confidence?: number;
  max_confidence?: number;
  search_ip?: string;
  flow_id?: string;
  start_time?: string;
  end_time?: string;
}

/** Flow Query Filters */
export interface FlowQueryParams {
  page?: number;
  limit?: number;
  protocol?: string;
  direction?: string;
  search_ip?: string;
  start_time?: string;
  end_time?: string;
}

/**
 * BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
 * Aggregate Overview Metrics payload shape from backend API.
 */
export interface OverviewMetrics {
  total_flows: number;
  flows_per_second: number;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  active_source_ips: number;
  active_destination_ips: number;
  threat_counts_by_class: Record<string, number>;
  ingest_status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE';
}

/**
 * BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
 * System Pipeline Health Telemetry payload shape from backend API.
 */
export interface PipelineHealthStatus {
  ingest_mode: IngestMode;
  pipeline_status: 'HEALTHY' | 'DEGRADED' | 'ERROR' | 'UNAVAILABLE';
  flows_per_second?: number;
  buffer_usage_percentage?: number;
  packets_dropped?: number;
  last_updated?: string;
}

/**
 * BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED
 * Source IP Aggregation Summary for Threat Analysis (TopSourcesTable).
 */
export interface SourceAggregation {
  source_ip: string;
  alert_count: number;
  primary_threat_class: string;
  max_severity: SeverityLevel;
  first_seen: string;
  last_seen: string;
}
