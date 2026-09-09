import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import { beforeAll, describe, expect, it } from 'vitest';
import type { ThreatAlert } from '../types/alert';
import type { ThreatEvidenceSignal } from '../types/evidence';
import type { NetworkFeatureRecord } from '../types/feature';
import type { PassiveFlow } from '../types/flow';
import type { MlPrediction } from '../types/ml';

const contractsDir = path.resolve(import.meta.dirname, '../../../contracts');

function loadSchema(filename: string) {
  const filepath = path.join(contractsDir, filename);
  const content = fs.readFileSync(filepath, 'utf-8');
  return JSON.parse(content);
}

describe('Authoritative Contract AJV Validation Suite', () => {
  let ajv: Ajv2020;
  let alertSchema: object;
  let evidenceSchema: object;
  let flowSchema: object;
  let featureSchema: object;
  let mlPredictionSchema: object;

  beforeAll(() => {
    ajv = new Ajv2020({ strict: false, allErrors: true });

    evidenceSchema = loadSchema('evidence-schema.json');
    alertSchema = loadSchema('alert-schema.json');
    flowSchema = loadSchema('flow-schema.json');
    featureSchema = loadSchema('feature-schema.json');
    mlPredictionSchema = loadSchema('ml-prediction-schema.json');

    // Register evidence schema so alert schema can resolve $ref "evidence-schema.json"
    ajv.addSchema(evidenceSchema, 'evidence-schema.json');
  });

  describe('contracts/evidence-schema.json', () => {
    it('validates a compliant ThreatEvidenceSignal', () => {
      const validate = ajv.compile(evidenceSchema);
      const validEvidence: ThreatEvidenceSignal = {
        signal_name: 'syn_to_ack_ratio',
        value: 45.2,
        direction: 'supporting',
        reliability: 0.95,
        supporting_features: ['syn_count', 'ack_count'],
        threat_class: 'DDoS',
      };

      const isCompliant = validate(validEvidence);
      expect(validate.errors).toBeNull();
      expect(isCompliant).toBe(true);
    });

    it('rejects evidence with invalid direction enum', () => {
      const validate = ajv.compile(evidenceSchema);
      const invalidEvidence = {
        signal_name: 'syn_ratio',
        value: 12.0,
        direction: 'MALICIOUS_ENUM_VALUE', // Invalid enum
        reliability: 0.8,
        supporting_features: [],
      };

      const isCompliant = validate(invalidEvidence);
      expect(isCompliant).toBe(false);
      expect(validate.errors?.some((e) => e.instancePath.includes('/direction'))).toBe(true);
    });
  });

  describe('contracts/alert-schema.json', () => {
    it('validates a compliant ThreatAlert with $ref evidence schema', () => {
      const validate = ajv.compile(alertSchema);
      const validAlert: ThreatAlert = {
        timestamp: '2026-09-08T10:00:00Z',
        flow_id: 'flow-101',
        threat_class: 'DDoS',
        confidence: 0.92,
        severity: 'CRITICAL',
        evidence: [
          {
            signal_name: 'packet_rate_spike',
            value: 15000,
            direction: 'supporting',
            reliability: 0.98,
            supporting_features: ['packets_per_sec'],
          },
        ],
        source_ip: '192.168.1.100',
        destination_ip: '10.0.0.1',
        protocol: 'TCP',
        model_version: 'v1.4.2',
        explanation: 'Volumetric TCP SYN flood pattern detected by statistical baseline',
      };

      const isCompliant = validate(validAlert);
      expect(validate.errors).toBeNull();
      expect(isCompliant).toBe(true);
    });

    it('rejects an alert violating additionalProperties: false', () => {
      const validate = ajv.compile(alertSchema);
      const alertWithInventedField = {
        timestamp: '2026-09-08T10:00:00Z',
        flow_id: 'flow-101',
        threat_class: 'DDoS',
        confidence: 0.92,
        severity: 'CRITICAL',
        evidence: [],
        invented_ai_mitigation_score: 99.9, // Violates additionalProperties: false
      };

      const isCompliant = validate(alertWithInventedField);
      expect(isCompliant).toBe(false);
      expect(validate.errors?.some((e) => e.keyword === 'additionalProperties')).toBe(true);
    });
  });

  describe('contracts/flow-schema.json', () => {
    it('validates a compliant PassiveFlow event with optional TLS metadata', () => {
      const validate = ajv.compile(flowSchema);
      const validFlow: PassiveFlow = {
        flow_id: 'flow-889',
        timestamp: '2026-09-08T10:05:00Z',
        src_ip: '10.0.1.4',
        dst_ip: '185.220.101.5',
        src_port: 54321,
        dst_port: 443,
        protocol: 'TCP',
        direction: 'outbound',
        duration: 14.5,
        packet_count: 120,
        byte_count: 45000,
        tcp_flags: 'SYN,ACK',
        tls: {
          sni: 'suspicious-c2.domain',
          ja3: '771,49195-49199,0-23,0-1',
        },
      };

      const isCompliant = validate(validFlow);
      expect(validate.errors).toBeNull();
      expect(isCompliant).toBe(true);
    });

    it('rejects a flow with negative duration', () => {
      const validate = ajv.compile(flowSchema);
      const invalidFlow = {
        flow_id: 'flow-889',
        timestamp: '2026-09-08T10:05:00Z',
        src_ip: '10.0.1.4',
        dst_ip: '185.220.101.5',
        protocol: 'TCP',
        duration: -5, // Violates minimum: 0 constraint
      };

      const isCompliant = validate(invalidFlow);
      expect(isCompliant).toBe(false);
      expect(validate.errors?.some((e) => e.instancePath.includes('/duration'))).toBe(true);
    });
  });

  describe('contracts/feature-schema.json', () => {
    it('validates a compliant NetworkFeatureRecord', () => {
      const validate = ajv.compile(featureSchema);
      const validFeature: NetworkFeatureRecord = {
        flow_id: 'flow-889',
        timestamp: '2026-09-08T10:05:00Z',
        entity_id: 'host-14',
        window_id: 'win-60s-001',
        features: {
          pkt_count_60s: 120,
          payload_entropy: 7.82,
          is_known_port: false,
          sni_reputation: null,
        },
      };

      const isCompliant = validate(validFeature);
      expect(validate.errors).toBeNull();
      expect(isCompliant).toBe(true);
    });

    it('rejects a feature record missing required features map', () => {
      const validate = ajv.compile(featureSchema);
      const invalidFeature = {
        flow_id: 'flow-889',
        timestamp: '2026-09-08T10:05:00Z',
      };

      const isCompliant = validate(invalidFeature);
      expect(isCompliant).toBe(false);
      expect(validate.errors?.some((e) => e.keyword === 'required')).toBe(true);
    });
  });

  describe('contracts/ml-prediction-schema.json', () => {
    it('validates a compliant MlPrediction record', () => {
      const validate = ajv.compile(mlPredictionSchema);
      const validMlPrediction: MlPrediction = {
        flow_id: 'flow-889',
        threat_class: 'Botnet C2 Beaconing',
        score: 0.88,
        model_version: 'rf-beaconing-v2.1',
        calibrated: true,
      };

      const isCompliant = validate(validMlPrediction);
      expect(validate.errors).toBeNull();
      expect(isCompliant).toBe(true);
    });

    it('rejects an ML prediction with score exceeding 1', () => {
      const validate = ajv.compile(mlPredictionSchema);
      const invalidMlPrediction = {
        flow_id: 'flow-889',
        threat_class: 'Botnet C2 Beaconing',
        score: 1.5, // Exceeds maximum: 1 constraint
        model_version: 'rf-v2',
      };

      const isCompliant = validate(invalidMlPrediction);
      expect(isCompliant).toBe(false);
      expect(validate.errors?.some((e) => e.instancePath.includes('/score'))).toBe(true);
    });
  });
});
