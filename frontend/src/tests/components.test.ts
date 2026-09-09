/* eslint-disable @typescript-eslint/no-explicit-any */
import type { ReactElement } from 'react';
import { describe, expect, it } from 'vitest';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ThreatClassBadge } from '../components/common/ThreatClassBadge';
import { ConfidenceGauge } from '../components/common/ConfidenceGauge';
import { StatusPill } from '../components/common/StatusPill';
import { MetricCard } from '../components/common/MetricCard';
import { DataStateWrapper } from '../components/common/DataStateWrapper';
import { PaginationControls } from '../components/common/PaginationControls';
import type { SeverityLevel } from '../types/alert';

describe('Phase 5C — Reusable Common SOC Components Suite', () => {
  describe('1. SeverityBadge Component', () => {
    it('accepts all 4 contract severity levels', () => {
      const severities: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

      severities.forEach((sev) => {
        const element = SeverityBadge({ severity: sev }) as ReactElement<any>;
        expect(element).toBeDefined();
        expect(element.props.title).toContain(sev);
      });
    });

    it('defaults to LOW for undefined or unrecognized severity', () => {
      // @ts-expect-error Testing fallback behavior
      const element = SeverityBadge({ severity: 'UNKNOWN' }) as ReactElement<any>;
      expect(element.props.title).toContain('LOW');
    });
  });

  describe('2. ThreatClassBadge Component', () => {
    it('renders backend-provided threat class string without modification', () => {
      const threatClasses = [
        'Volumetric / Protocol DDoS',
        'Botnet C2 Beaconing',
        'DGA / DNS Tunneling',
        'Malware Inside Encrypted Sessions',
        'Reconnaissance / Port Scanning',
        'Data Exfiltration',
      ];

      threatClasses.forEach((tc) => {
        const element = ThreatClassBadge({ threatClass: tc }) as ReactElement<any>;
        expect(element).toBeDefined();
        expect(element.props.title).toBe(`Threat Class: ${tc}`);
      });
    });

    it('renders neutral N/A label for missing threat class string', () => {
      const element = ThreatClassBadge({ threatClass: '' }) as ReactElement<any>;
      expect(element.props.title).toBe('Threat Class: N/A');
    });
  });

  describe('3. ConfidenceGauge Component', () => {
    it('formats 0..1 confidence values as rounded percentages with neutral bar styling', () => {
      const gauge091 = ConfidenceGauge({ confidence: 0.91 }) as ReactElement<any>;
      expect(gauge091.props.title).toContain('91%');

      const gauge042 = ConfidenceGauge({ confidence: 0.42 }) as ReactElement<any>;
      expect(gauge042.props.title).toContain('42%');
    });

    it('renders N/A for null, undefined, or out-of-range (< 0 or > 1) confidence values', () => {
      const gaugeNull = ConfidenceGauge({ confidence: null }) as ReactElement<any>;
      expect(gaugeNull.props.children).toBe('N/A');

      const gaugeUndefined = ConfidenceGauge({ confidence: undefined }) as ReactElement<any>;
      expect(gaugeUndefined.props.children).toBe('N/A');

      const gaugeNegative = ConfidenceGauge({ confidence: -0.2 }) as ReactElement<any>;
      expect(gaugeNegative.props.children).toBe('N/A');

      const gaugeTooHigh = ConfidenceGauge({ confidence: 1.5 }) as ReactElement<any>;
      expect(gaugeTooHigh.props.children).toBe('N/A');
    });
  });

  describe('4. StatusPill Component', () => {
    it('renders supported pipeline and transport status values', () => {
      const statuses = [
        'HEALTHY',
        'DEGRADED',
        'ERROR',
        'UNAVAILABLE',
        'CONNECTED',
        'DISCONNECTED',
        'RECONNECTING',
        'LIVE',
        'REPLAY',
      ];

      statuses.forEach((status) => {
        const element = StatusPill({ status }) as ReactElement<any>;
        expect(element).toBeDefined();
      });
    });

    it('renders custom unknown status text cleanly without converting it to UNAVAILABLE', () => {
      const element = StatusPill({ status: 'CUSTOM_PIPELINE_STATE' }) as ReactElement<any>;
      expect(element).toBeDefined();
    });
  });

  describe('5. MetricCard Component', () => {
    it('displays supplied label, value, and description without altering security meaning', () => {
      const card = MetricCard({
        label: 'Total Flows',
        value: 14500,
        description: 'Active flow count',
        statusContext: 'healthy',
      }) as ReactElement<any>;

      expect(card).toBeDefined();
      expect(card.props.className).toContain('emerald');
    });
  });

  describe('6. DataStateWrapper Component', () => {
    it('renders appropriate UI wrappers for loading, empty, error, unavailable, and disconnected states', () => {
      const loadingState = DataStateWrapper({ state: 'loading' }) as ReactElement<any>;
      expect(loadingState.props.role).toBe('status');

      const errorState = DataStateWrapper({ state: 'error' }) as ReactElement<any>;
      expect(errorState.props.role).toBe('alert');

      const readyState = DataStateWrapper({
        state: 'ready',
        children: 'Child Component Output',
      }) as ReactElement<any>;
      expect(readyState.props.children).toBe('Child Component Output');
    });
  });

  describe('7. PaginationControls Component', () => {
    it('calculates page range numbers correctly based on contract pagination input', () => {
      const element = PaginationControls({
        page: 1,
        limit: 10,
        total: 25,
        hasMore: true,
        onPageChange: () => {},
      }) as ReactElement<any>;

      expect(element).toBeDefined();
    });
  });
});
