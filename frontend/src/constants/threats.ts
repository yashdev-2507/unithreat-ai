/**
 * Canonical Threat Class Definitions & UI Label Mappings
 *
 * Authoritative Backend Threat Classes:
 *   - DDOS
 *   - RECONNAISSANCE
 *   - DGA
 *   - DNS_TUNNELING
 *   - C2_BEACONING
 *   - ENCRYPTED_ANOMALY
 *   - DATA_EXFILTRATION
 *
 * Source of truth: contracts/alert-schema.json & contracts/ml-prediction-schema.json
 */

export interface ThreatCategoryDefinition {
  id: string;
  label: string;
  backendKeys: readonly string[];
  primaryKey: string;
  legacyLabel?: string;
}

/**
 * The 6 Core SIH Threat Categories mapped to backend canonical keys.
 */
export const SIH_THREAT_CATEGORIES_CONFIG: ThreatCategoryDefinition[] = [
  {
    id: 'ddos',
    label: 'Volumetric / Protocol DDoS',
    backendKeys: ['DDOS'],
    primaryKey: 'DDOS',
    legacyLabel: 'Volumetric / Protocol DDoS',
  },
  {
    id: 'c2_beaconing',
    label: 'Botnet C2 Beaconing',
    backendKeys: ['C2_BEACONING'],
    primaryKey: 'C2_BEACONING',
    legacyLabel: 'Botnet C2 Beaconing',
  },
  {
    id: 'dga_dns',
    label: 'DGA / DNS Tunneling',
    backendKeys: ['DGA', 'DNS_TUNNELING'],
    primaryKey: 'DGA',
    legacyLabel: 'DGA / DNS Tunneling',
  },
  {
    id: 'encrypted_anomaly',
    label: 'Malware Inside Encrypted Sessions',
    backendKeys: ['ENCRYPTED_ANOMALY'],
    primaryKey: 'ENCRYPTED_ANOMALY',
    legacyLabel: 'Malware Inside Encrypted Sessions',
  },
  {
    id: 'reconnaissance',
    label: 'Reconnaissance / Port Scanning',
    backendKeys: ['RECONNAISSANCE'],
    primaryKey: 'RECONNAISSANCE',
    legacyLabel: 'Reconnaissance / Port Scanning',
  },
  {
    id: 'data_exfiltration',
    label: 'Data Exfiltration',
    backendKeys: ['DATA_EXFILTRATION'],
    primaryKey: 'DATA_EXFILTRATION',
    legacyLabel: 'Data Exfiltration',
  },
];

/**
 * Filter dropdown options mapping canonical backend keys to human-readable UI labels.
 */
export const CANONICAL_THREAT_FILTER_OPTIONS = [
  { value: 'ALL', label: 'All Threat Classes' },
  { value: 'DDOS', label: 'Volumetric / Protocol DDoS (DDOS)' },
  { value: 'RECONNAISSANCE', label: 'Reconnaissance / Port Scanning (RECONNAISSANCE)' },
  { value: 'DGA', label: 'DGA Domains (DGA)' },
  { value: 'DNS_TUNNELING', label: 'DNS Tunneling (DNS_TUNNELING)' },
  { value: 'C2_BEACONING', label: 'Botnet C2 Beaconing (C2_BEACONING)' },
  { value: 'ENCRYPTED_ANOMALY', label: 'Malware Inside Encrypted Sessions (ENCRYPTED_ANOMALY)' },
  { value: 'DATA_EXFILTRATION', label: 'Data Exfiltration (DATA_EXFILTRATION)' },
] as const;

/**
 * Helper to sum threat counts for category cards from backend statistics.
 * Checks canonical backend keys first, falling back to legacy labels for mock data compatibility.
 */
export function getThreatCategoryCount(
  threatCounts: Record<string, number> | undefined,
  backendKeys: readonly string[],
  legacyLabel?: string
): number {
  if (!threatCounts) return 0;
  let total = 0;
  for (const k of backendKeys) {
    if (typeof threatCounts[k] === 'number') {
      total += threatCounts[k];
    }
  }
  if (total === 0 && legacyLabel && typeof threatCounts[legacyLabel] === 'number') {
    total += threatCounts[legacyLabel];
  }
  return total;
}

/**
 * Helper to match an alert's threat_class against a filter value, supporting both
 * canonical backend keys ('DDOS') and legacy mock labels ('Volumetric / Protocol DDoS').
 */
export function matchThreatClass(alertClass: string | null | undefined, filterClass: string): boolean {
  if (!alertClass) return false;
  if (alertClass === filterClass) return true;
  for (const cat of SIH_THREAT_CATEGORIES_CONFIG) {
    const matchesFilter =
      (cat.backendKeys as readonly string[]).includes(filterClass) ||
      cat.legacyLabel === filterClass ||
      cat.primaryKey === filterClass;
    const matchesAlert =
      (cat.backendKeys as readonly string[]).includes(alertClass) ||
      cat.legacyLabel === alertClass ||
      cat.primaryKey === alertClass;
    if (matchesFilter && matchesAlert) {
      return true;
    }
  }
  return false;
}

