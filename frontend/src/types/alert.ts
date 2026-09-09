/**
 * Standardized Threat Alert
 * Source of truth: contracts/alert-schema.json
 */

import type { ThreatEvidenceSignal } from './evidence';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ThreatAlert {
  /** ISO date-time string */
  timestamp: string;
  flow_id: string;
  threat_class: string;
  /** Confidence score between 0 and 1 */
  confidence: number;
  severity: SeverityLevel;
  evidence: ThreatEvidenceSignal[];
  source_ip?: string | null;
  destination_ip?: string | null;
  protocol?: string | null;
  model_version?: string | null;
  explanation?: string | null;
}
