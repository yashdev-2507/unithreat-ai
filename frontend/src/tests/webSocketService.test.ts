import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WebSocketService } from '../services/WebSocketService';
import { createDataService, HttpDataService, MockDataService } from '../services';
import type { ThreatAlert } from '../types/alert';

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  url: string;
  readyState: number = 0; // CONNECTING
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((err: unknown) => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    // Auto-open on next tick
    setTimeout(() => {
      this.readyState = 1; // OPEN
      if (this.onopen) this.onopen();
    }, 10);
  }

  send = vi.fn();
  close = vi.fn(() => {
    this.readyState = 3; // CLOSED
    if (this.onclose) this.onclose();
  });
}

describe('WebSocketService Unit Tests', () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.stubGlobal('WebSocket', MockWebSocket);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('manages connection status and transitions to CONNECTED on open', async () => {
    const ws = new WebSocketService({ url: 'ws://localhost:8000/ws/alerts' });
    const statuses: string[] = [];

    ws.onStatusChange((status) => {
      statuses.push(status);
    });

    expect(statuses).toContain('DISCONNECTED');
    ws.connect();
    expect(ws.getStatus()).toBe('CONNECTING');

    // Wait for mock connection open
    await new Promise((r) => setTimeout(r, 25));

    expect(ws.getStatus()).toBe('CONNECTED');
    expect(statuses).toContain('CONNECTED');

    ws.disconnect();
    expect(ws.getStatus()).toBe('CLOSED');
  });

  it('parses valid threat alerts and notifies subscribers', async () => {
    const ws = new WebSocketService({ url: 'ws://localhost:8000/ws/alerts' });
    ws.connect();

    await new Promise((r) => setTimeout(r, 25));

    const receivedAlerts: ThreatAlert[] = [];
    const unsubscribe = ws.subscribe((alert) => {
      receivedAlerts.push(alert);
    });

    const mockAlertPayload: ThreatAlert = {
      flow_id: 'ws-flow-001',
      threat_class: 'DDOS',
      severity: 'CRITICAL',
      confidence: 0.96,
      timestamp: '2026-09-08T12:00:00.000000Z',
      evidence: [],
      source_ip: '192.168.1.50',
      destination_ip: '10.0.0.1',
    };

    const mockInstance = MockWebSocket.instances[0];
    mockInstance.onmessage!({ data: JSON.stringify(mockAlertPayload) });

    expect(receivedAlerts.length).toBe(1);
    expect(receivedAlerts[0].flow_id).toBe('ws-flow-001');
    expect(receivedAlerts[0].threat_class).toBe('DDOS');
    expect(receivedAlerts[0].confidence).toBe(0.96);

    // Verify recent alert storage
    const recent = ws.getRecentAlerts();
    expect(recent.length).toBe(1);
    expect(recent[0].flow_id).toBe('ws-flow-001');

    // Test unsubscribe
    unsubscribe();
    mockInstance.onmessage!({
      data: JSON.stringify({ ...mockAlertPayload, flow_id: 'ws-flow-002' }),
    });
    expect(receivedAlerts.length).toBe(1); // Subscriber was not called after unsubscribe

    ws.disconnect();
  });

  it('suppresses duplicate alerts with identical key', async () => {
    const ws = new WebSocketService({ url: 'ws://localhost:8000/ws/alerts' });
    ws.connect();
    await new Promise((r) => setTimeout(r, 25));

    let callCount = 0;
    ws.subscribe(() => {
      callCount++;
    });

    const mockAlert = {
      flow_id: 'dup-001',
      threat_class: 'C2_BEACONING',
      severity: 'HIGH',
      confidence: 0.85,
      timestamp: '2026-09-08T12:00:00Z',
      evidence: [],
    };

    const mockInstance = MockWebSocket.instances[0];
    // Send same alert twice
    mockInstance.onmessage!({ data: JSON.stringify(mockAlert) });
    mockInstance.onmessage!({ data: JSON.stringify(mockAlert) });

    expect(callCount).toBe(1);
    expect(ws.getRecentAlerts().length).toBe(1);

    ws.disconnect();
  });

  it('discards malformed JSON without crashing', async () => {
    const ws = new WebSocketService({ url: 'ws://localhost:8000/ws/alerts' });
    ws.connect();
    await new Promise((r) => setTimeout(r, 25));

    let called = false;
    ws.subscribe(() => {
      called = true;
    });

    const mockInstance = MockWebSocket.instances[0];
    mockInstance.onmessage!({ data: 'not-valid-json' });
    mockInstance.onmessage!({ data: JSON.stringify({ incomplete: true }) });

    expect(called).toBe(false);
    expect(ws.getRecentAlerts().length).toBe(0);

    ws.disconnect();
  });

  it('respects maxStoredAlerts ring-buffer capacity', async () => {
    const ws = new WebSocketService({
      url: 'ws://localhost:8000/ws/alerts',
      maxStoredAlerts: 3,
    });
    ws.connect();
    await new Promise((r) => setTimeout(r, 25));

    const mockInstance = MockWebSocket.instances[0];
    for (let i = 1; i <= 5; i++) {
      mockInstance.onmessage!({
        data: JSON.stringify({
          flow_id: `bounded-fl-${i}`,
          threat_class: 'DDOS',
          severity: 'HIGH',
          confidence: 0.8,
          timestamp: `2026-09-08T12:0${i}:00Z`,
          evidence: [],
        }),
      });
    }

    const recent = ws.getRecentAlerts();
    expect(recent.length).toBe(3);
    // Newest first
    expect(recent[0].flow_id).toBe('bounded-fl-5');
    expect(recent[2].flow_id).toBe('bounded-fl-3');

    ws.disconnect();
  });
});

describe('Service Selection Mechanism', () => {
  it('instantiates HttpDataService by default in integration mode', () => {
    const service = createDataService();
    expect(service).toBeInstanceOf(HttpDataService);
    const env = (service as HttpDataService).getEnvironmentStatus();
    expect(env.isMock).toBe(false);
  });

  it('instantiates MockDataService when VITE_USE_MOCK is true', () => {
    const origEnv = import.meta.env.VITE_USE_MOCK;
    try {
      import.meta.env.VITE_USE_MOCK = 'true';
      const service = createDataService();
      expect(service).toBeInstanceOf(MockDataService);
      const env = (service as MockDataService).getEnvironmentStatus();
      expect(env.isMock).toBe(true);
    } finally {
      import.meta.env.VITE_USE_MOCK = origEnv;
    }
  });
});
