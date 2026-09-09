import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import { beforeAll, describe, expect, it } from 'vitest';
import { MockDataService } from '../services/MockDataService';
import type { DataService } from '../services/DataService';
import {
  MOCK_ALERTS,
  MOCK_FLOWS,
  MOCK_FEATURES,
  MOCK_ML_PREDICTIONS,
  MOCK_DATA_ENVIRONMENT_BANNER,
} from '../services/mockData';
import type { PassiveFlow } from '../types/flow';
import type { ThreatAlert, SeverityLevel } from '../types/alert';
import type { ThreatEvidenceSignal } from '../types/evidence';
import type { NetworkFeatureRecord } from '../types/feature';
import type { MlPrediction } from '../types/ml';

const contractsDir = path.resolve(import.meta.dirname, '../../../contracts');

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function loadSchema(filename: string): any {
  const filepath = path.join(contractsDir, filename);
  const content = fs.readFileSync(filepath, 'utf-8');
  return JSON.parse(content);
}

describe('MockDataService & Dataset Contract Validation Suite', () => {
  let ajv: Ajv2020;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let alertSchema: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let evidenceSchema: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let flowSchema: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let featureSchema: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mlPredictionSchema: any;

  beforeAll(() => {
    ajv = new Ajv2020({ strict: false, allErrors: true });

    evidenceSchema = loadSchema('evidence-schema.json');
    alertSchema = loadSchema('alert-schema.json');
    flowSchema = loadSchema('flow-schema.json');
    featureSchema = loadSchema('feature-schema.json');
    mlPredictionSchema = loadSchema('ml-prediction-schema.json');

    ajv.addSchema(evidenceSchema, 'evidence-schema.json');
  });

  describe('Authoritative Contract Schema Compliance for Mock Datasets', () => {
    it('validates EVERY item in MOCK_FLOWS against contracts/flow-schema.json', () => {
      const validate = ajv.compile(flowSchema);
      expect(MOCK_FLOWS.length).toBeGreaterThanOrEqual(10);

      MOCK_FLOWS.forEach((flow: PassiveFlow) => {
        const isCompliant = validate(flow);
        if (!isCompliant) {
          console.error(`Flow validation failed for ${(flow as PassiveFlow).flow_id}:`, validate.errors);
        }
        expect(isCompliant).toBe(true);
        expect(validate.errors).toBeNull();
      });
    });

    it('validates EVERY item in MOCK_ALERTS against contracts/alert-schema.json', () => {
      const validate = ajv.compile(alertSchema);
      expect(MOCK_ALERTS.length).toBeGreaterThanOrEqual(10);

      MOCK_ALERTS.forEach((alert: ThreatAlert, idx: number) => {
        const isCompliant = validate(alert);
        if (!isCompliant) {
          console.error(`Alert validation failed at index ${idx} (flow ${(alert as ThreatAlert).flow_id}):`, validate.errors);
        }
        expect(isCompliant).toBe(true);
        expect(validate.errors).toBeNull();
      });
    });

    it('validates EVERY ThreatEvidenceSignal within alerts against contracts/evidence-schema.json', () => {
      const validate = ajv.compile(evidenceSchema);

      MOCK_ALERTS.flatMap((a) => a.evidence).forEach((evidence: ThreatEvidenceSignal) => {
        const isCompliant = validate(evidence);
        if (!isCompliant) {
          console.error(`Evidence signal validation failed for ${(evidence as ThreatEvidenceSignal).signal_name}:`, validate.errors);
        }
        expect(isCompliant).toBe(true);
        expect(validate.errors).toBeNull();
      });
    });

    it('validates EVERY item in MOCK_FEATURES against contracts/feature-schema.json', () => {
      const validate = ajv.compile(featureSchema);
      expect(MOCK_FEATURES.length).toBeGreaterThanOrEqual(5);

      MOCK_FEATURES.forEach((featureRecord: NetworkFeatureRecord) => {
        const isCompliant = validate(featureRecord);
        if (!isCompliant) {
          console.error(`Feature record validation failed for ${(featureRecord as NetworkFeatureRecord).flow_id}:`, validate.errors);
        }
        expect(isCompliant).toBe(true);
        expect(validate.errors).toBeNull();
      });
    });

    it('validates EVERY item in MOCK_ML_PREDICTIONS against contracts/ml-prediction-schema.json', () => {
      const validate = ajv.compile(mlPredictionSchema);
      expect(MOCK_ML_PREDICTIONS.length).toBeGreaterThanOrEqual(5);

      MOCK_ML_PREDICTIONS.forEach((prediction: MlPrediction) => {
        const isCompliant = validate(prediction);
        if (!isCompliant) {
          console.error(`ML Prediction validation failed for ${(prediction as MlPrediction).flow_id}:`, validate.errors);
        }
        expect(isCompliant).toBe(true);
        expect(validate.errors).toBeNull();
      });
    });
  });

  describe('UI State Coverage Requirements', () => {
    it('covers all six SIH required threat classes', () => {
      const requiredThreatClasses = [
        'Volumetric / Protocol DDoS',
        'Botnet C2 Beaconing',
        'DGA / DNS Tunneling',
        'Malware Inside Encrypted Sessions',
        'Reconnaissance / Port Scanning',
        'Data Exfiltration',
      ];

      const presentClasses = new Set(MOCK_ALERTS.map((a) => a.threat_class));
      requiredThreatClasses.forEach((threatClass) => {
        expect(presentClasses.has(threatClass)).toBe(true);
      });
    });

    it('covers all four severity levels', () => {
      const requiredSeverities: SeverityLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const presentSeverities = new Set(MOCK_ALERTS.map((a) => a.severity));

      requiredSeverities.forEach((severity) => {
        expect(presentSeverities.has(severity)).toBe(true);
      });
    });

    it('ensures protocol is ALWAYS a non-null, non-empty string across all flows', () => {
      MOCK_FLOWS.forEach((flow) => {
        expect(flow.protocol).toBeDefined();
        expect(flow.protocol).not.toBeNull();
        expect(typeof flow.protocol).toBe('string');
        expect(flow.protocol.length).toBeGreaterThan(0);
      });
    });

    it('includes valid nullable/optional field variations for schema testing', () => {
      const hasNullPort = MOCK_FLOWS.some((f) => f.src_port === null || f.dst_port === null);
      const hasNullDirection = MOCK_FLOWS.some((f) => f.direction === null);
      const hasNullDuration = MOCK_FLOWS.some((f) => f.duration === null);
      const hasNullAlertFields = MOCK_ALERTS.some(
        (a) => a.source_ip === null && a.destination_ip === null && a.explanation === null
      );

      expect(hasNullPort).toBe(true);
      expect(hasNullDirection).toBe(true);
      expect(hasNullDuration).toBe(true);
      expect(hasNullAlertFields).toBe(true);
    });

    it('demonstrates cardinality: multiple features, predictions, and alerts per flow', () => {
      // Multiple alerts for same flow_id
      const alertsForVol001 = MOCK_ALERTS.filter((a) => a.flow_id === 'flow-vol-001');
      expect(alertsForVol001.length).toBeGreaterThanOrEqual(2);

      // Multiple features for same flow_id
      const featuresForVol001 = MOCK_FEATURES.filter((f) => f.flow_id === 'flow-vol-001');
      expect(featuresForVol001.length).toBeGreaterThanOrEqual(2);

      // Multiple predictions for same flow_id
      const predictionsForVol001 = MOCK_ML_PREDICTIONS.filter((p) => p.flow_id === 'flow-vol-001');
      expect(predictionsForVol001.length).toBeGreaterThanOrEqual(2);
    });

    it('uses neutral ML model versions (no hardcoded RF/XGBoost)', () => {
      MOCK_ML_PREDICTIONS.forEach((pred) => {
        expect(pred.model_version).toMatch(/^mock-ml-/);
      });
    });
  });

  describe('MockDataService API & Deterministic Behavior', () => {
    let service: MockDataService;

    beforeAll(() => {
      service = new MockDataService();
    });

    it('satisfies the DataService interface contract', () => {
      const genericService: DataService = service;
      expect(typeof genericService.getAlerts).toBe('function');
      expect(typeof genericService.getFlows).toBe('function');
      expect(typeof genericService.getFlowById).toBe('function');
      expect(typeof genericService.getFeaturesByFlowId).toBe('function');
      expect(typeof genericService.getMlPredictionsByFlowId).toBe('function');
      expect(typeof genericService.getOverviewMetrics).toBe('function');
      expect(typeof genericService.getPipelineHealth).toBe('function');
    });

    it('returns environment status indicating DEMO / REPLAY environment', () => {
      const env = service.getEnvironmentStatus();
      expect(env.isMock).toBe(true);
      expect(env.label).toBe(MOCK_DATA_ENVIRONMENT_BANNER);
    });

    it('retrieves paginated alerts with default parameters', async () => {
      const result = await service.getAlerts();
      expect(result.data.length).toBeLessThanOrEqual(10);
      expect(result.total).toBe(MOCK_ALERTS.length);
      expect(result.page).toBe(1);
      expect(result.limit).toBe(10);
    });

    it('filters alerts by severity deterministically', async () => {
      const result = await service.getAlerts({ severity: 'CRITICAL' });
      expect(result.data.length).toBeGreaterThan(0);
      result.data.forEach((alert) => {
        expect(alert.severity).toBe('CRITICAL');
      });
    });

    it('filters alerts by threat class deterministically', async () => {
      const result = await service.getAlerts({ threat_class: 'Botnet C2 Beaconing' });
      expect(result.data.length).toBe(1);
      expect(result.data[0].threat_class).toBe('Botnet C2 Beaconing');
    });

    it('filters alerts by flow_id allowing multiple alerts for a single flow', async () => {
      const result = await service.getAlerts({ flow_id: 'flow-vol-001' });
      expect(result.data.length).toBe(2);
      expect(result.data.every((a) => a.flow_id === 'flow-vol-001')).toBe(true);
    });

    it('filters alerts by IP search string', async () => {
      const result = await service.getAlerts({ search_ip: '192.168.1.105' });
      expect(result.data.length).toBeGreaterThan(0);
      result.data.forEach((alert) => {
        expect(
          alert.source_ip?.includes('192.168.1.105') || alert.destination_ip?.includes('192.168.1.105')
        ).toBe(true);
      });
    });

    it('retrieves paginated flows with protocol filtering', async () => {
      const result = await service.getFlows({ protocol: 'TCP' });
      expect(result.data.length).toBeGreaterThan(0);
      result.data.forEach((flow) => {
        expect(flow.protocol.toUpperCase()).toBe('TCP');
      });
    });

    it('looks up a flow by flow_id', async () => {
      const flow = await service.getFlowById('flow-bot-001');
      expect(flow).not.toBeNull();
      expect(flow?.flow_id).toBe('flow-bot-001');

      const nonExistent = await service.getFlowById('non-existent-id');
      expect(nonExistent).toBeNull();
    });

    it('fetches features by flow_id', async () => {
      const features = await service.getFeaturesByFlowId('flow-vol-001');
      expect(features.length).toBe(2);
      expect(features[0].flow_id).toBe('flow-vol-001');
    });

    it('fetches ML predictions by flow_id', async () => {
      const predictions = await service.getMlPredictionsByFlowId('flow-vol-001');
      expect(predictions.length).toBe(2);
      expect(predictions[0].flow_id).toBe('flow-vol-001');
    });

    it('returns overview metrics and pipeline health status', async () => {
      const overview = await service.getOverviewMetrics();
      expect(overview.total_flows).toBe(12);
      expect(overview.total_alerts).toBe(10);
      expect(overview.ingest_status).toBe('HEALTHY');

      const health = await service.getPipelineHealth();
      expect(health.ingest_mode).toBe('REPLAY');
      expect(health.pipeline_status).toBe('HEALTHY');
    });
  });
});
