/**
 * Network Feature Record
 * Source of truth: contracts/feature-schema.json
 */

export interface NetworkFeatureRecord {
  flow_id: string;
  /** ISO date-time string */
  timestamp: string;
  entity_id?: string | null;
  window_id?: string | null;
  features: Record<string, number | string | boolean | null>;
}
