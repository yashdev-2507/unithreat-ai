import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpDataService } from '../services/HttpDataService';
import type { ThreatAlert } from '../types/alert';
import type { PassiveFlow } from '../types/flow';

describe('HttpDataService Unit Tests', () => {
  const mockBaseUrl = 'http://test-soc-backend:8000';
  let service: HttpDataService;

  beforeEach(() => {
    service = new HttpDataService(mockBaseUrl);
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('getEnvironmentStatus', () => {
    it('reports live backend environment rather than mock data', () => {
      const status = service.getEnvironmentStatus();
      expect(status.isMock).toBe(false);
      expect(status.label).toContain('LIVE BACKEND');
    });
  });

  describe('getOverviewMetrics', () => {
    it('aggregates stats and health into OverviewMetrics correctly', async () => {
      const mockStats = {
        total_flows_processed: 1250,
        total_alerts_stored: 45,
        by_threat_class: {
          DDOS: 20,
          C2_BEACONING: 15,
          RECONNAISSANCE: 10,
        },
        by_severity: {
          LOW: 5,
          MEDIUM: 10,
          HIGH: 15,
          CRITICAL: 15,
        },
      };

      const mockHealth = {
        status: 'ok',
        version: '0.1.0',
        ml_active: true,
        total_flows_processed: 1250,
        total_alerts_stored: 45,
        active_stream_subscribers: 1,
      };

      const mockRecentFlows: Partial<PassiveFlow>[] = [
        { flow_id: 'f1', src_ip: '192.168.1.10', dst_ip: '10.0.0.1' },
        { flow_id: 'f2', src_ip: '192.168.1.20', dst_ip: '10.0.0.1' },
        { flow_id: 'f3', src_ip: '192.168.1.10', dst_ip: '10.0.0.2' },
      ];

      vi.mocked(fetch).mockImplementation(async (input) => {
        const url = String(input);
        if (url.includes('/stats')) {
          return new Response(JSON.stringify(mockStats), { status: 200 });
        }
        if (url.includes('/health')) {
          return new Response(JSON.stringify(mockHealth), { status: 200 });
        }
        if (url.includes('/flows')) {
          return new Response(JSON.stringify(mockRecentFlows), { status: 200 });
        }
        return new Response('Not found', { status: 404 });
      });

      const metrics = await service.getOverviewMetrics();

      expect(metrics.total_flows).toBe(1250);
      expect(metrics.total_alerts).toBe(45);
      expect(metrics.critical_alerts).toBe(15);
      expect(metrics.high_alerts).toBe(15);
      expect(metrics.medium_alerts).toBe(10);
      expect(metrics.low_alerts).toBe(5);
      expect(metrics.active_source_ips).toBe(2); // 192.168.1.10, 192.168.1.20
      expect(metrics.active_destination_ips).toBe(2); // 10.0.0.1, 10.0.0.2
      expect(metrics.threat_counts_by_class).toEqual(mockStats.by_threat_class);
      expect(metrics.ingest_status).toBe('HEALTHY');
    });

    it('throws when backend is unavailable (no silent fallback to mock)', async () => {
      vi.mocked(fetch).mockRejectedValue(new Error('Network connection refused'));

      await expect(service.getOverviewMetrics()).rejects.toThrow('Network connection refused');
    });
  });

  describe('getPipelineHealth', () => {
    it('maps GET /health to PipelineHealthStatus with buffer usage calculation', async () => {
      const mockHealth = {
        status: 'ok',
        version: '0.1.0',
        ml_active: true,
        total_flows_processed: 500,
        total_alerts_stored: 250,
      };

      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(mockHealth), { status: 200 })
      );

      const health = await service.getPipelineHealth();
      expect(health.pipeline_status).toBe('HEALTHY');
      expect(health.ingest_mode).toBe('LIVE');
      expect(health.buffer_usage_percentage).toBe(25); // 250 / 1000 = 25%
    });

    it('throws when health endpoint fails with 500', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response('Internal Server Error', { status: 500, statusText: 'Server Error' })
      );

      await expect(service.getPipelineHealth()).rejects.toThrow('Failed to fetch pipeline health: 500');
    });
  });

  describe('getAlerts', () => {
    const mockAlerts: ThreatAlert[] = [
      {
        flow_id: 'a1',
        threat_class: 'DDOS',
        severity: 'CRITICAL',
        confidence: 0.95,
        timestamp: '2026-09-08T12:00:00Z',
        evidence: [],
        source_ip: '192.168.1.100',
        destination_ip: '10.0.0.1',
      },
      {
        flow_id: 'a2',
        threat_class: 'C2_BEACONING',
        severity: 'HIGH',
        confidence: 0.82,
        timestamp: '2026-09-08T12:01:00Z',
        evidence: [],
        source_ip: '192.168.1.200',
        destination_ip: '10.0.0.2',
      },
      {
        flow_id: 'a3',
        threat_class: 'RECONNAISSANCE',
        severity: 'MEDIUM',
        confidence: 0.65,
        timestamp: '2026-09-08T12:02:00Z',
        evidence: [],
        source_ip: '192.168.1.100',
        destination_ip: '10.0.0.3',
      },
    ];

    it('returns paginated response from GET /alerts', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(mockAlerts), { status: 200 })
      );

      const res = await service.getAlerts({ page: 1, limit: 2 });
      expect(res.total).toBe(3);
      expect(res.data.length).toBe(2);
      expect(res.has_more).toBe(true);
      expect(res.page).toBe(1);
      expect(res.limit).toBe(2);
    });

    it('passes threat_class, severity, and min_confidence to backend query string', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify([mockAlerts[0]]), { status: 200 })
      );

      await service.getAlerts({
        threat_class: 'DDOS',
        severity: 'CRITICAL',
        min_confidence: 0.9,
      });

      const callUrl = vi.mocked(fetch).mock.calls[0][0] as string;
      expect(callUrl).toContain('threat_class=DDOS');
      expect(callUrl).toContain('severity=CRITICAL');
      expect(callUrl).toContain('min_confidence=0.9');
    });

    it('performs single flow_id lookup via GET /alerts/{flow_id}', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(mockAlerts[0]), { status: 200 })
      );

      const res = await service.getAlerts({ flow_id: 'a1' });
      expect(res.data.length).toBe(1);
      expect(res.data[0].flow_id).toBe('a1');
      expect(res.total).toBe(1);

      const callUrl = vi.mocked(fetch).mock.calls[0][0] as string;
      expect(callUrl).toBe('http://test-soc-backend:8000/alerts/a1');
    });

    it('returns empty array when single flow_id lookup returns 404', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response('Not Found', { status: 404 })
      );

      const res = await service.getAlerts({ flow_id: 'missing-flow' });
      expect(res.data).toEqual([]);
      expect(res.total).toBe(0);
    });
  });

  describe('getFlows and getFlowById', () => {
    const mockFlows: PassiveFlow[] = [
      {
        flow_id: 'fl-1',
        timestamp: '2026-09-08T12:00:00Z',
        src_ip: '192.168.1.1',
        dst_ip: '10.0.0.1',
        protocol: 'TCP',
        direction: 'outbound',
      },
      {
        flow_id: 'fl-2',
        timestamp: '2026-09-08T12:01:00Z',
        src_ip: '192.168.1.2',
        dst_ip: '10.0.0.2',
        protocol: 'UDP',
        direction: 'inbound',
      },
    ];

    it('retrieves flows with pagination', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(mockFlows), { status: 200 })
      );

      const res = await service.getFlows({ page: 1, limit: 10 });
      expect(res.total).toBe(2);
      expect(res.data.length).toBe(2);
      expect(res.data[0].flow_id).toBe('fl-1');
    });

    it('retrieves single flow by id', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(mockFlows[0]), { status: 200 })
      );

      const flow = await service.getFlowById('fl-1');
      expect(flow).not.toBeNull();
      expect(flow?.flow_id).toBe('fl-1');
    });

    it('returns null when flow is not found (404)', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response('Not Found', { status: 404 })
      );

      const flow = await service.getFlowById('nonexistent');
      expect(flow).toBeNull();
    });
  });

  describe('getFeaturesByFlowId', () => {
    it('returns feature array from GET /features/{flow_id}', async () => {
      const mockRecord = {
        flow_id: 'fl-1',
        timestamp: '2026-09-08T12:00:00Z',
        features: { pkt_rate: 150.0 },
      };

      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(mockRecord), { status: 200 })
      );

      const features = await service.getFeaturesByFlowId('fl-1');
      expect(features.length).toBe(1);
      expect(features[0].flow_id).toBe('fl-1');
      expect(features[0].features.pkt_rate).toBe(150.0);
    });

    it('returns empty array when feature record is not found (404)', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response('Not Found', { status: 404 })
      );

      const features = await service.getFeaturesByFlowId('missing');
      expect(features).toEqual([]);
    });
  });

  describe('getMlPredictionsByFlowId', () => {
    it('returns prediction array from GET /predictions/{flow_id}', async () => {
      const mockPrediction = {
        flow_id: 'fl-1',
        threat_class: 'DDOS',
        score: 0.9234,
        model_version: 'rf-baseline-v1',
        calibrated: false,
      };

      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify(mockPrediction), { status: 200 })
      );

      const predictions = await service.getMlPredictionsByFlowId('fl-1');
      expect(predictions.length).toBe(1);
      expect(predictions[0].threat_class).toBe('DDOS');
      expect(predictions[0].score).toBe(0.9234);
      expect(predictions[0].calibrated).toBe(false);
      expect((predictions[0] as unknown as Record<string, unknown>).ml_score).toBeUndefined();
    });

    it('returns empty array when ML prediction is not found (404)', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response('Not Found', { status: 404 })
      );

      const predictions = await service.getMlPredictionsByFlowId('missing');
      expect(predictions).toEqual([]);
    });
  });
});
