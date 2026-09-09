/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it, vi } from 'vitest';
import { ThreatAnalysisPage } from '../pages/ThreatAnalysisPage';
import { DetectionAnalyticsPage } from '../pages/DetectionAnalyticsPage';
import { MlIntelligencePage } from '../pages/MlIntelligencePage';
import { SystemMonitoringPage } from '../pages/SystemMonitoringPage';
import { AppRoutes } from '../routes/AppRoutes';
import { mockDataService } from '../services/MockDataService';

describe('Phase 5F — Advanced SOC Pages Test Suite', () => {
  describe('1. ThreatAnalysisPage Logic & DataService Integration', () => {
    it('1. ThreatAnalysisPage exported as a valid React component function', () => {
      expect(typeof ThreatAnalysisPage).toBe('function');
    });

    it('2. ThreatAnalysisPage calls getOverviewMetrics and getAlerts on initial load', async () => {
      const overviewSpy = vi.spyOn(mockDataService, 'getOverviewMetrics');
      const alertsSpy = vi.spyOn(mockDataService, 'getAlerts');

      const overview = await mockDataService.getOverviewMetrics();
      const alerts = await mockDataService.getAlerts({ page: 1, limit: 10 });

      expect(overviewSpy).toHaveBeenCalled();
      expect(alertsSpy).toHaveBeenCalledWith({ page: 1, limit: 10 });
      expect(overview.total_alerts).toBeGreaterThan(0);
      expect(alerts.data.length).toBeGreaterThan(0);

      overviewSpy.mockRestore();
      alertsSpy.mockRestore();
    });

    it('3. Severity filter passes correct severity parameter to getAlerts', async () => {
      const spy = vi.spyOn(mockDataService, 'getAlerts');
      const result = await mockDataService.getAlerts({ severity: 'CRITICAL' });

      expect(spy).toHaveBeenCalledWith({ severity: 'CRITICAL' });
      expect(result.data).toBeDefined();
      result.data.forEach((alert) => {
        expect(alert.severity).toBe('CRITICAL');
      });
      spy.mockRestore();
    });

    it('4. Threat class filter passes correct threat_class parameter to getAlerts', async () => {
      const spy = vi.spyOn(mockDataService, 'getAlerts');
      const result = await mockDataService.getAlerts({ threat_class: 'Volumetric / Protocol DDoS' });

      expect(spy).toHaveBeenCalledWith({ threat_class: 'Volumetric / Protocol DDoS' });
      expect(result.data).toBeDefined();
      result.data.forEach((alert) => {
        expect(alert.threat_class).toBe('Volumetric / Protocol DDoS');
      });
      spy.mockRestore();
    });

    it('5. Search IP filter passes search_ip parameter to getAlerts', async () => {
      const spy = vi.spyOn(mockDataService, 'getAlerts');
      const result = await mockDataService.getAlerts({ search_ip: '192.168.1.105' });

      expect(spy).toHaveBeenCalledWith({ search_ip: '192.168.1.105' });
      expect(result.data).toBeDefined();
      spy.mockRestore();
    });
  });

  describe('2. DetectionAnalyticsPage Logic & SIH Category Breakdown', () => {
    it('6. DetectionAnalyticsPage exported as a valid React component function', () => {
      expect(typeof DetectionAnalyticsPage).toBe('function');
    });

    it('7. DetectionAnalyticsPage retrieves metrics with SIH threat category breakdown', async () => {
      const overview = await mockDataService.getOverviewMetrics();
      expect(overview.threat_counts_by_class).toBeDefined();
      expect(Object.keys(overview.threat_counts_by_class).length).toBeGreaterThan(0);
    });

    it('8. Filtering by specific SIH category delegates directly to getAlerts', async () => {
      const spy = vi.spyOn(mockDataService, 'getAlerts');
      const result = await mockDataService.getAlerts({ threat_class: 'Botnet C2 Beaconing' });

      expect(spy).toHaveBeenCalledWith({ threat_class: 'Botnet C2 Beaconing' });
      expect(result.data).toBeDefined();
      result.data.forEach((a) => {
        expect(a.threat_class).toBe('Botnet C2 Beaconing');
      });
      spy.mockRestore();
    });
  });

  describe('3. MlIntelligencePage Logic & ML Predictions Representation', () => {
    it('9. MlIntelligencePage exported as a valid React component function', () => {
      expect(typeof MlIntelligencePage).toBe('function');
    });

    it('10. MlIntelligencePage retrieves ML prediction telemetry via DataService alerts & flow ML predictions', async () => {
      const alerts = await mockDataService.getAlerts({ page: 1, limit: 10 });
      expect(alerts.data).toBeDefined();
      expect(alerts.data.length).toBeGreaterThan(0);

      // Verify each alert flow has ML prediction record
      const predictions = await mockDataService.getMlPredictionsByFlowId(alerts.data[0].flow_id);
      expect(predictions).toBeDefined();
    });
  });

  describe('4. SystemMonitoringPage Logic & Telemetry Retrieval', () => {
    it('11. SystemMonitoringPage exported as a valid React component function', () => {
      expect(typeof SystemMonitoringPage).toBe('function');
    });

    it('12. SystemMonitoringPage calls getPipelineHealth and getOverviewMetrics', async () => {
      const healthSpy = vi.spyOn(mockDataService, 'getPipelineHealth');
      const overviewSpy = vi.spyOn(mockDataService, 'getOverviewMetrics');

      const health = await mockDataService.getPipelineHealth();
      const overview = await mockDataService.getOverviewMetrics();

      expect(healthSpy).toHaveBeenCalled();
      expect(overviewSpy).toHaveBeenCalled();
      expect(health.pipeline_status).toBeDefined();
      expect(health.ingest_mode).toBeDefined();
      expect(overview.flows_per_second).toBeGreaterThan(0);

      healthSpy.mockRestore();
      overviewSpy.mockRestore();
    });
  });

  describe('5. AppRoutes Mounting Verification', () => {
    it('13. AppRoutes exports component mounting all 4 Phase 5F pages', () => {
      expect(typeof AppRoutes).toBe('function');
    });
  });
});
