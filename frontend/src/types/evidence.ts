/**
 * Threat Evidence Signal
 * Source of truth: contracts/evidence-schema.json
 */

export type EvidenceDirection = 'supporting' | 'contradicting' | 'neutral';

export interface ThreatEvidenceSignal {
  signal_name: string;
  value: number;
  direction: EvidenceDirection;
  /** Reliability score between 0 and 1 */
  reliability: number;
  supporting_features: string[];
  threat_class?: string | null;
}
