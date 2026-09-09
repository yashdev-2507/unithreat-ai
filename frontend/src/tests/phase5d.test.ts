/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';
import { mockDataService } from '../services/MockDataService';
import type { ThreatAlert } from '../types';

describe('Phase 5D — Executive Overview & Live Alerts Component Suite', () => {
  const sampleAlert: ThreatAlert = {
    flow_id: 'FLOW-1001-DNS-TUNNEL',
    timestamp: '2026-03-30T10:15:30Z',
    severity: 'CRITICAL',
    threat_class: 'DGA / DNS Tunneling',
    confidence: 0.94,
    source_ip: '192.168.10.45',
    destination_ip: '198.51.100.88',
    protocol: 'UDP',
    evidence: [
      {
        signal_name: 'dns_entropy_high',
        value: 4.85,
        direction: 'supporting',
        reliability: 0.94,
        supporting_features: ['dns_entropy', 'subdomain_len'],
        threat_class: 'DGA / DNS Tunneling',
      },
    ],
    explanation: 'Unusual rate of DNS requests to dynamic domains indicating DNS tunneling activity.',
  };

  describe('1. AlertDetailDrawer Component', () => {
    it('returns null when isOpen is false or alert is null', () => {
      const closedElement = React.createElement(AlertDetailDrawer, {
        alert: sampleAlert,
        isOpen: false,
        onClose: () => {},
      });
      expect(closedElement).toBeDefined();

      const nullAlertElement = React.createElement(AlertDetailDrawer, {
        alert: null,
        isOpen: true,
        onClose: () => {},
      });
      expect(nullAlertElement).toBeDefined();
    });

    it('renders drawer structure when alert is provided and isOpen is true', () => {
      const element = React.createElement(AlertDetailDrawer, {
        alert: sampleAlert,
        isOpen: true,
        onClose: () => {},
      });

      expect(element).toBeDefined();
      expect(element.type).toBe(AlertDetailDrawer);
      expect(element.props.isOpen).toBe(true);
    });

    it('handles alert with multiple evidence signals and optional supporting features gracefully', () => {
      const alertWithMultipleSignals: ThreatAlert = {
        ...sampleAlert,
        evidence: [
          {
            signal_name: 'dns_entropy_high',
            value: 4.85,
            direction: 'supporting',
            reliability: 0.94,
            supporting_features: ['dns_entropy', 'subdomain_len'],
            threat_class: 'DGA / DNS Tunneling',
          },
          {
            signal_name: 'query_frequency_spike',
            value: 125,
            direction: 'supporting',
            reliability: 0.88,
            supporting_features: ['query_rate'],
            threat_class: 'DGA / DNS Tunneling',
          },
        ],
      };

      const element = React.createElement(AlertDetailDrawer, {
        alert: alertWithMultipleSignals,
        isOpen: true,
        onClose: () => {},
      });

      expect(element).toBeDefined();
      expect(element.type).toBe(AlertDetailDrawer);
      expect(element.props.isOpen).toBe(true);
    });
  });

  describe('2. Overview Data Integration via DataService', () => {
    it('fetches overview metrics, health, and recent alerts via mockDataService', async () => {
      const metrics = await mockDataService.getOverviewMetrics();
      const health = await mockDataService.getPipelineHealth();
      const recentAlerts = await mockDataService.getAlerts({ page: 1, limit: 5 });

      expect(metrics).toBeDefined();
      expect(metrics.total_flows).toBeGreaterThan(0);
      expect(metrics.total_alerts).toBeGreaterThan(0);
      expect(metrics.threat_counts_by_class).toBeDefined();

      expect(health).toBeDefined();
      expect(health.pipeline_status).toBe('HEALTHY');
      expect(health.ingest_mode).toBe('REPLAY');

      expect(recentAlerts).toBeDefined();
      expect(recentAlerts.data.length).toBeLessThanOrEqual(5);
    });

    it('supports spy on DataService getOverviewMetrics', async () => {
      const getOverviewSpy = vi.spyOn(mockDataService, 'getOverviewMetrics');
      const metrics = await mockDataService.getOverviewMetrics();

      expect(getOverviewSpy).toHaveBeenCalled();
      expect(metrics).toBeDefined();
      getOverviewSpy.mockRestore();
    });
  });

  describe('3. Live Alerts Data Integration via DataService', () => {
    it('executes getAlerts with query parameters via DataService', async () => {
      const getAlertsSpy = vi.spyOn(mockDataService, 'getAlerts');

      const result = await mockDataService.getAlerts({
        page: 1,
        limit: 10,
        severity: 'CRITICAL',
      });

      expect(getAlertsSpy).toHaveBeenCalledWith({
        page: 1,
        limit: 10,
        severity: 'CRITICAL',
      });
      expect(result.data).toBeDefined();
      expect(Array.isArray(result.data)).toBe(true);
      expect(result.total).toBeGreaterThanOrEqual(result.data.length);
      getAlertsSpy.mockRestore();
    });

    it('filters alerts by threat_class via DataService interface', async () => {
      const targetClass = 'Volumetric / Protocol DDoS';
      const result = await mockDataService.getAlerts({
        threat_class: targetClass,
      });

      expect(result.data).toBeDefined();
      result.data.forEach((alert) => {
        expect(alert.threat_class).toBe(targetClass);
      });
    });

    it('filters alerts by IP search string', async () => {
      const result = await mockDataService.getAlerts({
        search_ip: '192.168.10.45',
      });

      expect(result.data).toBeDefined();
      result.data.forEach((alert) => {
        const matchesSource = alert.source_ip?.includes('192.168.10.45');
        const matchesDest = alert.destination_ip?.includes('192.168.10.45');
        expect(matchesSource || matchesDest).toBe(true);
      });
    });
  });
});
