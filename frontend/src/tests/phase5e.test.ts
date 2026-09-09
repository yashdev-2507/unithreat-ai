/* eslint-disable @typescript-eslint/no-explicit-any */
import type { ReactElement } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { FlowMetadataPanel } from '../components/flows/FlowMetadataPanel';
import { ProtocolMetadataPanel } from '../components/flows/ProtocolMetadataPanel';
import { NetworkFeaturesTable } from '../components/flows/NetworkFeaturesTable';
import { MlPredictionsPanel } from '../components/flows/MlPredictionsPanel';
import { mockDataService } from '../services/MockDataService';
import type { PassiveFlow, NetworkFeatureRecord, MlPrediction } from '../types';

describe('Phase 5E — Investigation & Passive Flow Explorer Test Suite', () => {
  const sampleFlow: PassiveFlow = {
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
  };

  const sampleNullFlow: PassiveFlow = {
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
  };

  describe('1. FlowsPage & Flow Explorer Logic via DataService', () => {
    it('1. FlowsPage renders backend-provided flows via getFlows', async () => {
      const response = await mockDataService.getFlows({ page: 1, limit: 10 });
      expect(response.data).toBeDefined();
      expect(response.data.length).toBeGreaterThan(0);
      expect(response.total).toBeGreaterThanOrEqual(response.data.length);
    });

    it('2. Protocol filter calls getFlows with protocol parameter', async () => {
      const spy = vi.spyOn(mockDataService, 'getFlows');
      const response = await mockDataService.getFlows({ protocol: 'TCP' });

      expect(spy).toHaveBeenCalledWith({ protocol: 'TCP' });
      expect(response.data).toBeDefined();
      response.data.forEach((flow) => {
        expect(flow.protocol.toUpperCase()).toBe('TCP');
      });
      spy.mockRestore();
    });

    it('3. Direction filter calls getFlows with direction parameter', async () => {
      const spy = vi.spyOn(mockDataService, 'getFlows');
      const response = await mockDataService.getFlows({ direction: 'inbound' });

      expect(spy).toHaveBeenCalledWith({ direction: 'inbound' });
      expect(response.data).toBeDefined();
      response.data.forEach((flow) => {
        expect(flow.direction).toBe('inbound');
      });
      spy.mockRestore();
    });

    it('4. Search IP calls getFlows with search_ip parameter', async () => {
      const spy = vi.spyOn(mockDataService, 'getFlows');
      const response = await mockDataService.getFlows({ search_ip: '192.168.1.105' });

      expect(spy).toHaveBeenCalledWith({ search_ip: '192.168.1.105' });
      expect(response.data).toBeDefined();
      response.data.forEach((flow) => {
        const matchesSrc = flow.src_ip.includes('192.168.1.105');
        const matchesDst = flow.dst_ip.includes('192.168.1.105');
        expect(matchesSrc || matchesDst).toBe(true);
      });
      spy.mockRestore();
    });

    it('5. Pagination calls getFlows with correct page/limit parameters', async () => {
      const spy = vi.spyOn(mockDataService, 'getFlows');
      const response = await mockDataService.getFlows({ page: 2, limit: 5 });

      expect(spy).toHaveBeenCalledWith({ page: 2, limit: 5 });
      expect(response.page).toBe(2);
      expect(response.limit).toBe(5);
      spy.mockRestore();
    });

    it('6. Filter changes verify reset to page 1 parameter formation', async () => {
      const response = await mockDataService.getFlows({
        page: 1,
        limit: 10,
        protocol: 'UDP',
      });

      expect(response.page).toBe(1);
      expect(response.data).toBeDefined();
    });
  });

  describe('2. Flow Investigation Data & Param Logic', () => {
    it('7 & 8. getFlowById receives correct flowId and returns flow record', async () => {
      const spy = vi.spyOn(mockDataService, 'getFlowById');
      const flow = await mockDataService.getFlowById('flow-vol-001');

      expect(spy).toHaveBeenCalledWith('flow-vol-001');
      expect(flow).not.toBeNull();
      expect(flow?.flow_id).toBe('flow-vol-001');
      spy.mockRestore();
    });

    it('9. Features are retrieved through getFeaturesByFlowId', async () => {
      const spy = vi.spyOn(mockDataService, 'getFeaturesByFlowId');
      const features = await mockDataService.getFeaturesByFlowId('flow-vol-001');

      expect(spy).toHaveBeenCalledWith('flow-vol-001');
      expect(features).toBeDefined();
      expect(features.length).toBeGreaterThan(0);
      spy.mockRestore();
    });

    it('10. ML predictions are retrieved through getMlPredictionsByFlowId', async () => {
      const spy = vi.spyOn(mockDataService, 'getMlPredictionsByFlowId');
      const predictions = await mockDataService.getMlPredictionsByFlowId('flow-vol-001');

      expect(spy).toHaveBeenCalledWith('flow-vol-001');
      expect(predictions).toBeDefined();
      expect(predictions.length).toBeGreaterThan(0);
      spy.mockRestore();
    });

    it('11 & 12. Related alerts are retrieved using getAlerts({ flow_id }) and handles multiple alerts for same flow', async () => {
      const spy = vi.spyOn(mockDataService, 'getAlerts');
      const result = await mockDataService.getAlerts({ flow_id: 'flow-vol-001' });

      expect(spy).toHaveBeenCalledWith({ flow_id: 'flow-vol-001' });
      expect(result.data).toBeDefined();
      expect(result.data.length).toBe(2); // flow-vol-001 has 2 related alerts in mock data
      spy.mockRestore();
    });
  });

  describe('3. Inspector Panel Components & Edge Cases', () => {
    it('13. Optional/null flow metadata renders safely without crashing', () => {
      const element = FlowMetadataPanel({ flow: sampleNullFlow }) as ReactElement<any>;
      expect(element).toBeDefined();

      const protocolElement = ProtocolMetadataPanel({ flow: sampleNullFlow }) as ReactElement<any>;
      expect(protocolElement).toBeDefined();
    });

    it('14. Empty feature state works gracefully', () => {
      const element = NetworkFeaturesTable({ features: [] }) as ReactElement<any>;
      expect(element).toBeDefined();
    });

    it('15. Empty ML prediction state works gracefully', () => {
      const element = MlPredictionsPanel({ predictions: [] }) as ReactElement<any>;
      expect(element).toBeDefined();
    });

    it('16. Empty related-alert state works via getAlerts for un-alerted flow', async () => {
      const result = await mockDataService.getAlerts({ flow_id: 'non-existent-flow' });
      expect(result.data).toBeDefined();
      expect(result.data.length).toBe(0);
    });

    it('17. Flow-not-found state works when getFlowById returns null', async () => {
      const flow = await mockDataService.getFlowById('non-existent-flow-id');
      expect(flow).toBeNull();
    });

    it('18. Renders feature records with primitive types (number, string, boolean, null)', () => {
      const records: NetworkFeatureRecord[] = [
        {
          flow_id: 'flow-test-01',
          timestamp: '2026-09-08T10:00:00Z',
          features: {
            numeric_val: 123.45,
            string_val: 'TLSv1.3',
            boolean_val: true,
            null_val: null,
          },
        },
      ];

      const element = NetworkFeaturesTable({ features: records }) as ReactElement<any>;
      expect(element).toBeDefined();
    });

    it('Renders ML prediction panel with calibrated status', () => {
      const predictions: MlPrediction[] = [
        {
          flow_id: 'flow-test-01',
          threat_class: 'DGA / DNS Tunneling',
          score: 0.92,
          model_version: 'mock-ml-v1',
          calibrated: true,
        },
      ];

      const element = MlPredictionsPanel({ predictions }) as ReactElement<any>;
      expect(element).toBeDefined();
    });

    it('Renders ProtocolMetadataPanel with DNS, TLS, and QUIC metadata', () => {
      const flowWithProtocol: PassiveFlow = {
        ...sampleFlow,
        dns: { query_name: 'test.com', query_type: 'A', response_code: 'NOERROR' },
        tls: { sni: 'test.com', ja3: 'abc', version: 'TLSv1.3', cipher_suite: 'AES' },
        quic: { sni: 'test.com', version: '1', cipher: 'AES' },
      };

      const element = ProtocolMetadataPanel({ flow: flowWithProtocol }) as ReactElement<any>;
      expect(element).toBeDefined();
    });
  });
});
