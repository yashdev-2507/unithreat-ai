import type {
  ThreatAlert,
  PassiveFlow,
  NetworkFeatureRecord,
  MlPrediction,
  OverviewMetrics,
  PipelineHealthStatus,
} from '../types';

/**
 * Standardized frontend banner / indicator string for mock data.
 * Keeps simulated environment status explicit without modifying API contract models.
 */
export const MOCK_DATA_ENVIRONMENT_BANNER = 'DEMO / REPLAY DATA — SIMULATED ENVIRONMENT';

/**
 * Deterministic Passive Flow records covering multiple protocols, directions,
 * and valid contract-compliant nullable/optional field variations.
 */
export const MOCK_FLOWS: PassiveFlow[] = [
  // 1. Standard Outbound HTTPS/TLS Flow
  {
    flow_id: 'flow-vol-001',
    timestamp: '2026-09-08T10:00:00Z',
    src_ip: '192.168.1.105',
    dst_ip: '10.0.0.50',
    src_port: 54321,
    dst_port: 80,
    protocol: 'TCP',
    direction: 'inbound',
    duration: 12.4,
    packet_count: 145000,
    byte_count: 92800000,
    tcp_flags: 'SYN,ACK',
    dns: null,
    tls: null,
    quic: null,
  },
  // 2. High-volume TCP DDoS target flow
  {
    flow_id: 'flow-vol-002',
    timestamp: '2026-09-08T10:01:00Z',
    src_ip: '192.168.1.106',
    dst_ip: '10.0.0.50',
    src_port: 54322,
    dst_port: 80,
    protocol: 'TCP',
    direction: 'inbound',
    duration: 11.2,
    packet_count: 180000,
    byte_count: 115200000,
    tcp_flags: 'SYN',
    dns: null,
    tls: null,
    quic: null,
  },
  // 3. Botnet C2 Beaconing Periodic UDP/HTTP Flow
  {
    flow_id: 'flow-bot-001',
    timestamp: '2026-09-08T10:02:15Z',
    src_ip: '172.16.4.12',
    dst_ip: '198.51.100.44',
    src_port: 49152,
    dst_port: 8080,
    protocol: 'TCP',
    direction: 'outbound',
    duration: 2.1,
    packet_count: 18,
    byte_count: 1420,
    tcp_flags: 'ACK,PSH',
    dns: null,
    tls: null,
    quic: null,
  },
  // 4. DGA / DNS Tunneling High-Frequency Queries
  {
    flow_id: 'flow-dga-001',
    timestamp: '2026-09-08T10:03:00Z',
    src_ip: '172.16.4.88',
    dst_ip: '1.1.1.1',
    src_port: 53530,
    dst_port: 53,
    protocol: 'UDP',
    direction: 'outbound',
    duration: 0.45,
    packet_count: 8,
    byte_count: 940,
    tcp_flags: null,
    dns: {
      query_name: 'cx89a27f90q1.random-sub.example.net',
      query_type: 'TXT',
      response_code: 'NOERROR',
    },
    tls: null,
    quic: null,
  },
  // 5. Encrypted Malware Session with TLS Metadata
  {
    flow_id: 'flow-enc-001',
    timestamp: '2026-09-08T10:04:30Z',
    src_ip: '10.10.2.14',
    dst_ip: '203.0.113.195',
    src_port: 58210,
    dst_port: 443,
    protocol: 'TLS',
    direction: 'outbound',
    duration: 45.8,
    packet_count: 240,
    byte_count: 184000,
    tcp_flags: 'ACK,PSH',
    dns: null,
    tls: {
      sni: 'secure-update.suspicious-domain.org',
      ja3: '771,49195-49199-52392,0-13-43,0-1',
      version: 'TLSv1.3',
      cipher_suite: 'TLS_AES_256_GCM_SHA384',
    },
    quic: null,
  },
  // 6. Reconnaissance / SYN Port Scanning
  {
    flow_id: 'flow-scan-001',
    timestamp: '2026-09-08T10:06:00Z',
    src_ip: '198.51.100.99',
    dst_ip: '10.0.0.12',
    src_port: 33110,
    dst_port: 22,
    protocol: 'TCP',
    direction: 'inbound',
    duration: 0.05,
    packet_count: 1,
    byte_count: 60,
    tcp_flags: 'SYN',
    dns: null,
    tls: null,
    quic: null,
  },
  // 7. Data Exfiltration via High Volume Outbound
  {
    flow_id: 'flow-exfil-001',
    timestamp: '2026-09-08T10:08:12Z',
    src_ip: '10.0.4.15',
    dst_ip: '198.51.100.200',
    src_port: 60100,
    dst_port: 443,
    protocol: 'QUIC',
    direction: 'outbound',
    duration: 320.0,
    packet_count: 85000,
    byte_count: 125000000,
    tcp_flags: null,
    dns: null,
    tls: null,
    quic: {
      sni: 'cloud-storage-staging.external-dest.io',
      version: '1',
      cipher: 'AEAD_AES_128_GCM',
    },
  },
  // 8. Low-severity anomaly / internal flow with null port & null duration
  {
    flow_id: 'flow-low-001',
    timestamp: '2026-09-08T10:09:45Z',
    src_ip: '10.0.0.2',
    dst_ip: '10.0.0.3',
    src_port: null,
    dst_port: null,
    protocol: 'ICMP',
    direction: 'internal',
    duration: null,
    packet_count: 4,
    byte_count: 336,
    tcp_flags: null,
    dns: null,
    tls: null,
    quic: null,
  },
  // 9. Unknown direction with null metadata fields
  {
    flow_id: 'flow-unk-001',
    timestamp: '2026-09-08T10:10:00Z',
    src_ip: '203.0.113.50',
    dst_ip: '10.0.0.100',
    src_port: 1234,
    dst_port: 80,
    protocol: 'TCP',
    direction: 'unknown',
    duration: 1.5,
    packet_count: 10,
    byte_count: 800,
    tcp_flags: 'ACK',
    dns: null,
    tls: null,
    quic: null,
  },
  // 10. Medium-severity Reconnaissance companion flow
  {
    flow_id: 'flow-scan-002',
    timestamp: '2026-09-08T10:11:15Z',
    src_ip: '198.51.100.99',
    dst_ip: '10.0.0.14',
    src_port: 33111,
    dst_port: 3389,
    protocol: 'TCP',
    direction: 'inbound',
    duration: 0.08,
    packet_count: 2,
    byte_count: 120,
    tcp_flags: 'SYN',
    dns: null,
    tls: null,
    quic: null,
  },
  // 11. Secondary alert companion flow for flow-vol-001 (testing multiple alerts per flow)
  {
    flow_id: 'flow-shared-001',
    timestamp: '2026-09-08T10:12:00Z',
    src_ip: '172.16.10.5',
    dst_ip: '10.0.0.50',
    src_port: 44332,
    dst_port: 53,
    protocol: 'UDP',
    direction: 'inbound',
    duration: 5.0,
    packet_count: 50000,
    byte_count: 32000000,
    tcp_flags: null,
    dns: null,
    tls: null,
    quic: null,
  },
  // 12. Minimal flow testing omitted/null optional fields
  {
    flow_id: 'flow-null-001',
    timestamp: '2026-09-08T10:13:00Z',
    src_ip: '10.0.1.1',
    dst_ip: '10.0.1.2',
    src_port: null,
    dst_port: null,
    protocol: 'UDP',
    direction: null,
    duration: null,
    packet_count: null,
    byte_count: null,
    tcp_flags: null,
    dns: null,
    tls: null,
    quic: null,
  },
];

/**
 * Deterministic Threat Alerts covering all 6 SIH threat classes and 4 severities.
 * Includes compliant evidence signals adhering to contracts/evidence-schema.json.
 * Multiple alerts map to shared flow_ids (e.g. flow-vol-001, flow-shared-001) to reflect cardinality.
 */
export const MOCK_ALERTS: ThreatAlert[] = [
  // Class 1: Volumetric / Protocol DDoS (CRITICAL)
  {
    timestamp: '2026-09-08T10:00:05Z',
    flow_id: 'flow-vol-001',
    threat_class: 'Volumetric / Protocol DDoS',
    confidence: 0.96,
    severity: 'CRITICAL',
    evidence: [
      {
        signal_name: 'packet_rate_surge',
        value: 11693.5,
        direction: 'supporting',
        reliability: 0.98,
        supporting_features: ['packet_count', 'duration'],
        threat_class: 'Volumetric / Protocol DDoS',
      },
      {
        signal_name: 'syn_ratio_extreme',
        value: 0.99,
        direction: 'supporting',
        reliability: 0.94,
        supporting_features: ['tcp_flags'],
        threat_class: 'Volumetric / Protocol DDoS',
      },
    ],
    source_ip: '192.168.1.105',
    destination_ip: '10.0.0.50',
    protocol: 'TCP',
    model_version: 'mock-ml-v1',
    explanation: 'High packet volume rate surge detected matching volumetric flood baseline',
  },

  // Second alert referencing flow-vol-001 (demonstrating multiple alerts for one flow_id)
  {
    timestamp: '2026-09-08T10:00:10Z',
    flow_id: 'flow-vol-001',
    threat_class: 'Volumetric / Protocol DDoS',
    confidence: 0.89,
    severity: 'HIGH',
    evidence: [
      {
        signal_name: 'byte_rate_threshold_exceeded',
        value: 7483870.9,
        direction: 'supporting',
        reliability: 0.91,
        supporting_features: ['byte_count', 'duration'],
        threat_class: 'Volumetric / Protocol DDoS',
      },
    ],
    source_ip: '192.168.1.105',
    destination_ip: '10.0.0.50',
    protocol: 'TCP',
    model_version: 'mock-ml-v2',
    explanation: 'Secondary byte rate threshold alert triggered for active flood session',
  },

  // Class 1 (alt): Volumetric UDP DDoS (HIGH)
  {
    timestamp: '2026-09-08T10:12:05Z',
    flow_id: 'flow-shared-001',
    threat_class: 'Volumetric / Protocol DDoS',
    confidence: 0.88,
    severity: 'HIGH',
    evidence: [
      {
        signal_name: 'udp_flood_rate',
        value: 10000.0,
        direction: 'supporting',
        reliability: 0.92,
        supporting_features: ['packet_count'],
        threat_class: 'Volumetric / Protocol DDoS',
      },
    ],
    source_ip: '172.16.10.5',
    destination_ip: '10.0.0.50',
    protocol: 'UDP',
    model_version: 'mock-ml-v1',
    explanation: 'UDP traffic burst exceeding statistical baseline',
  },

  // Class 2: Botnet C2 Beaconing (HIGH)
  {
    timestamp: '2026-09-08T10:02:20Z',
    flow_id: 'flow-bot-001',
    threat_class: 'Botnet C2 Beaconing',
    confidence: 0.87,
    severity: 'HIGH',
    evidence: [
      {
        signal_name: 'beaconing_periodicity_regularity',
        value: 0.94,
        direction: 'supporting',
        reliability: 0.90,
        supporting_features: ['inter_arrival_time_stddev'],
        threat_class: 'Botnet C2 Beaconing',
      },
      {
        signal_name: 'payload_length_constancy',
        value: 0.88,
        direction: 'supporting',
        reliability: 0.85,
        supporting_features: ['byte_count'],
        threat_class: 'Botnet C2 Beaconing',
      },
    ],
    source_ip: '172.16.4.12',
    destination_ip: '198.51.100.44',
    protocol: 'TCP',
    model_version: 'mock-ml-v1',
    explanation: 'Low-variance periodic outbound traffic pattern characteristic of C2 beaconing',
  },

  // Class 3: DGA / DNS Tunneling (HIGH)
  {
    timestamp: '2026-09-08T10:03:05Z',
    flow_id: 'flow-dga-001',
    threat_class: 'DGA / DNS Tunneling',
    confidence: 0.91,
    severity: 'HIGH',
    evidence: [
      {
        signal_name: 'dns_subdomain_entropy',
        value: 4.82,
        direction: 'supporting',
        reliability: 0.93,
        supporting_features: ['dns_query_entropy'],
        threat_class: 'DGA / DNS Tunneling',
      },
      {
        signal_name: 'txt_record_volume',
        value: 8.0,
        direction: 'supporting',
        reliability: 0.86,
        supporting_features: ['packet_count'],
        threat_class: 'DGA / DNS Tunneling',
      },
    ],
    source_ip: '172.16.4.88',
    destination_ip: '1.1.1.1',
    protocol: 'UDP',
    model_version: 'mock-ml-v2',
    explanation: 'High character entropy in DNS queries indicating domain generation or tunneling',
  },

  // Class 4: Malware Inside Encrypted Sessions (CRITICAL)
  {
    timestamp: '2026-09-08T10:04:35Z',
    flow_id: 'flow-enc-001',
    threat_class: 'Malware Inside Encrypted Sessions',
    confidence: 0.94,
    severity: 'CRITICAL',
    evidence: [
      {
        signal_name: 'tls_ja3_fingerprint_anomaly',
        value: 0.96,
        direction: 'supporting',
        reliability: 0.95,
        supporting_features: ['tls_ja3'],
        threat_class: 'Malware Inside Encrypted Sessions',
      },
      {
        signal_name: 'sni_reputation_flag',
        value: 0.89,
        direction: 'supporting',
        reliability: 0.88,
        supporting_features: ['tls_sni'],
        threat_class: 'Malware Inside Encrypted Sessions',
      },
    ],
    source_ip: '10.10.2.14',
    destination_ip: '203.0.113.195',
    protocol: 'TLS',
    model_version: 'mock-ml-v1',
    explanation: 'Unusual TLS client fingerprint and SNI structure observed in passive metadata',
  },

  // Class 5: Reconnaissance / Port Scanning (MEDIUM)
  {
    timestamp: '2026-09-08T10:06:05Z',
    flow_id: 'flow-scan-001',
    threat_class: 'Reconnaissance / Port Scanning',
    confidence: 0.78,
    severity: 'MEDIUM',
    evidence: [
      {
        signal_name: 'single_syn_no_ack',
        value: 1.0,
        direction: 'supporting',
        reliability: 0.82,
        supporting_features: ['tcp_flags', 'packet_count'],
        threat_class: 'Reconnaissance / Port Scanning',
      },
    ],
    source_ip: '198.51.100.99',
    destination_ip: '10.0.0.12',
    protocol: 'TCP',
    model_version: 'mock-ml-v2',
    explanation: 'Single packet TCP SYN without completion indicating probe activity',
  },

  // Class 5 (alt): Reconnaissance / Port Scanning (LOW)
  {
    timestamp: '2026-09-08T10:11:20Z',
    flow_id: 'flow-scan-002',
    threat_class: 'Reconnaissance / Port Scanning',
    confidence: 0.65,
    severity: 'LOW',
    evidence: [
      {
        signal_name: 'sequential_port_probe',
        value: 2.0,
        direction: 'supporting',
        reliability: 0.70,
        supporting_features: ['dst_port'],
        threat_class: 'Reconnaissance / Port Scanning',
      },
    ],
    source_ip: '198.51.100.99',
    destination_ip: '10.0.0.14',
    protocol: 'TCP',
    model_version: 'mock-ml-v2',
    explanation: 'Low-rate destination port probe observed',
  },

  // Class 6: Data Exfiltration (CRITICAL)
  {
    timestamp: '2026-09-08T10:08:20Z',
    flow_id: 'flow-exfil-001',
    threat_class: 'Data Exfiltration',
    confidence: 0.95,
    severity: 'CRITICAL',
    evidence: [
      {
        signal_name: 'asymmetric_outbound_ratio',
        value: 1470.5,
        direction: 'supporting',
        reliability: 0.97,
        supporting_features: ['byte_count', 'duration'],
        threat_class: 'Data Exfiltration',
      },
      {
        signal_name: 'quic_session_transfer_volume',
        value: 125000000.0,
        direction: 'supporting',
        reliability: 0.94,
        supporting_features: ['byte_count'],
        threat_class: 'Data Exfiltration',
      },
    ],
    source_ip: '10.0.4.15',
    destination_ip: '198.51.100.200',
    protocol: 'QUIC',
    model_version: 'mock-ml-v1',
    explanation: 'Sustained large-volume outbound encrypted session transfer',
  },

  // Alert testing null optional fields
  {
    timestamp: '2026-09-08T10:09:50Z',
    flow_id: 'flow-low-001',
    threat_class: 'Reconnaissance / Port Scanning',
    confidence: 0.42,
    severity: 'LOW',
    evidence: [
      {
        signal_name: 'icmp_ping_burst',
        value: 4.0,
        direction: 'neutral',
        reliability: 0.50,
        supporting_features: ['packet_count'],
        threat_class: null,
      },
    ],
    source_ip: null,
    destination_ip: null,
    protocol: null,
    model_version: null,
    explanation: null,
  },
];

/**
 * Deterministic Network Feature Records reflecting cardinality (multiple records per flow).
 * Contains primitive values (number | string | boolean | null) in features map.
 */
export const MOCK_FEATURES: NetworkFeatureRecord[] = [
  // flow-vol-001 Window 1
  {
    flow_id: 'flow-vol-001',
    timestamp: '2026-09-08T10:00:00Z',
    entity_id: 'host-10.0.0.50',
    window_id: 'win-10s-001',
    features: {
      pkt_rate: 11693.5,
      byte_rate: 7483870.9,
      syn_ratio: 0.99,
      mean_pkt_size: 64.0,
      is_known_service: true,
    },
  },
  // flow-vol-001 Window 2
  {
    flow_id: 'flow-vol-001',
    timestamp: '2026-09-08T10:00:10Z',
    entity_id: 'host-10.0.0.50',
    window_id: 'win-10s-002',
    features: {
      pkt_rate: 12100.0,
      byte_rate: 7744000.0,
      syn_ratio: 1.0,
      mean_pkt_size: 64.0,
      is_known_service: true,
    },
  },

  // flow-bot-001 Record 1
  {
    flow_id: 'flow-bot-001',
    timestamp: '2026-09-08T10:02:15Z',
    entity_id: 'host-172.16.4.12',
    window_id: 'win-60s-001',
    features: {
      interval_regularity_score: 0.94,
      packet_size_entropy: 0.12,
      outbound_connection_count: 1,
      dns_resolved: false,
    },
  },
  // flow-bot-001 Record 2
  {
    flow_id: 'flow-bot-001',
    timestamp: '2026-09-08T10:03:15Z',
    entity_id: 'host-172.16.4.12',
    window_id: 'win-60s-002',
    features: {
      interval_regularity_score: 0.96,
      packet_size_entropy: 0.09,
      outbound_connection_count: 1,
      dns_resolved: false,
    },
  },

  // flow-dga-001 Record 1
  {
    flow_id: 'flow-dga-001',
    timestamp: '2026-09-08T10:03:00Z',
    entity_id: 'host-172.16.4.88',
    window_id: 'win-30s-001',
    features: {
      query_length: 38,
      entropy_shannon: 4.82,
      consonant_ratio: 0.72,
      is_valid_tld: true,
      nxdomain_count: 14,
    },
  },

  // flow-enc-001 Record 1
  {
    flow_id: 'flow-enc-001',
    timestamp: '2026-09-08T10:04:30Z',
    entity_id: 'host-10.10.2.14',
    window_id: 'win-60s-001',
    features: {
      tls_version_code: '0x0304',
      sni_length: 36,
      cipher_count: 18,
      cert_is_self_signed: null,
      flow_bytes_ratio: 0.05,
    },
  },

  // flow-exfil-001 Record 1
  {
    flow_id: 'flow-exfil-001',
    timestamp: '2026-09-08T10:08:12Z',
    entity_id: 'host-10.0.4.15',
    window_id: 'win-300s-001',
    features: {
      total_bytes_sent: 125000000,
      total_bytes_received: 85000,
      asymmetry_ratio: 1470.5,
      is_business_hours: true,
      protocol_tunneling_risk: 0.89,
    },
  },
];

/**
 * Deterministic ML Prediction records using neutral simulated model versions (mock-ml-v1, mock-ml-v2).
 * Demonstrates cardinality (multiple model outputs per flow).
 */
export const MOCK_ML_PREDICTIONS: MlPrediction[] = [
  // flow-vol-001 Model 1
  {
    flow_id: 'flow-vol-001',
    threat_class: 'Volumetric / Protocol DDoS',
    score: 0.96,
    model_version: 'mock-ml-v1',
    calibrated: true,
  },
  // flow-vol-001 Model 2
  {
    flow_id: 'flow-vol-001',
    threat_class: 'Volumetric / Protocol DDoS',
    score: 0.89,
    model_version: 'mock-ml-v2',
    calibrated: false,
  },

  // flow-bot-001 Model 1
  {
    flow_id: 'flow-bot-001',
    threat_class: 'Botnet C2 Beaconing',
    score: 0.87,
    model_version: 'mock-ml-v1',
    calibrated: true,
  },
  // flow-bot-001 Model 2
  {
    flow_id: 'flow-bot-001',
    threat_class: 'Botnet C2 Beaconing',
    score: 0.82,
    model_version: 'mock-ml-v2',
    calibrated: true,
  },

  // flow-dga-001 Model 1
  {
    flow_id: 'flow-dga-001',
    threat_class: 'DGA / DNS Tunneling',
    score: 0.91,
    model_version: 'mock-ml-v2',
    calibrated: true,
  },

  // flow-enc-001 Model 1
  {
    flow_id: 'flow-enc-001',
    threat_class: 'Malware Inside Encrypted Sessions',
    score: 0.94,
    model_version: 'mock-ml-v1',
    calibrated: true,
  },
  // flow-enc-001 Model 2
  {
    flow_id: 'flow-enc-001',
    threat_class: 'Malware Inside Encrypted Sessions',
    score: 0.91,
    model_version: 'mock-ml-v2',
    calibrated: false,
  },

  // flow-scan-001 Model 1
  {
    flow_id: 'flow-scan-001',
    threat_class: 'Reconnaissance / Port Scanning',
    score: 0.78,
    model_version: 'mock-ml-v2',
    calibrated: true,
  },

  // flow-exfil-001 Model 1
  {
    flow_id: 'flow-exfil-001',
    threat_class: 'Data Exfiltration',
    score: 0.95,
    model_version: 'mock-ml-v1',
    calibrated: true,
  },
];

/**
 * Baseline Mock Overview Metrics conforming to OverviewMetrics API model.
 */
export const MOCK_OVERVIEW_METRICS: OverviewMetrics = {
  total_flows: 12,
  flows_per_second: 24.5,
  total_alerts: 10,
  critical_alerts: 3,
  high_alerts: 4,
  medium_alerts: 1,
  low_alerts: 2,
  active_source_ips: 7,
  active_destination_ips: 8,
  threat_counts_by_class: {
    'Volumetric / Protocol DDoS': 3,
    'Botnet C2 Beaconing': 1,
    'DGA / DNS Tunneling': 1,
    'Malware Inside Encrypted Sessions': 1,
    'Reconnaissance / Port Scanning': 3,
    'Data Exfiltration': 1,
  },
  ingest_status: 'HEALTHY',
};

/**
 * Baseline Mock Pipeline Health Status conforming to PipelineHealthStatus API model.
 */
export const MOCK_PIPELINE_HEALTH: PipelineHealthStatus = {
  ingest_mode: 'REPLAY',
  pipeline_status: 'HEALTHY',
  flows_per_second: 24.5,
  buffer_usage_percentage: 18.4,
  packets_dropped: 0,
  last_updated: '2026-09-08T10:13:00Z',
};
