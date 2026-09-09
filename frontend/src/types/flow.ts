/**
 * Normalized Passive Flow Event
 * Source of truth: contracts/flow-schema.json
 */

export type FlowDirection = 'inbound' | 'outbound' | 'internal' | 'unknown';

export interface PassiveFlow {
  flow_id: string;
  /** ISO date-time string */
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol: string;
  direction?: FlowDirection | null;
  /** Duration in seconds, minimum 0 */
  duration?: number | null;
  /** Packet count, minimum 0 */
  packet_count?: number | null;
  /** Byte count, minimum 0 */
  byte_count?: number | null;
  tcp_flags?: string | null;
  dns?: Record<string, unknown> | null;
  tls?: Record<string, unknown> | null;
  quic?: Record<string, unknown> | null;
}
