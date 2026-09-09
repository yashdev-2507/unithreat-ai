"""
tests/alerts/test_dedup.py
==========================

Tests for AlertDeduplicator:
  - Temporal suppression of identical alerts
  - Differentiation by threat class, source, and destination
  - Suppression window expiration
  - Bounded LRU capacity enforcement
"""

from __future__ import annotations

import pytest

from unithreat.alerts.dedup import AlertDeduplicator
from unithreat.alerts.models import ThreatAlert
from unithreat.detection.result import EvidenceSignal


def _make_alert(
    flow_id: str,
    threat_class: str,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.50",
    timestamp: str = "2026-09-08T08:00:00.000000Z",
) -> ThreatAlert:
    return ThreatAlert(
        timestamp=timestamp,
        flow_id=flow_id,
        threat_class=threat_class,
        confidence=0.85,
        severity="HIGH",
        evidence=[
            EvidenceSignal(
                signal_name="test_signal",
                value=1.0,
                direction="supporting",
                reliability=0.9,
                supporting_features=["feat"],
            )
        ],
        source_ip=src_ip,
        destination_ip=dst_ip,
    )


class TestAlertDeduplicator:
    def test_duplicate_alert_suppressed_within_window(self):
        dedup = AlertDeduplicator(suppression_window_seconds=60.0)
        a1 = _make_alert("flow-001", "DDOS")
        a2 = _make_alert("flow-002", "DDOS")  # Same src, dst, threat_class

        # First alert is accepted (not suppressed)
        assert dedup.should_suppress(a1, current_time=100.0) is False

        # Second alert 10 seconds later is suppressed
        assert dedup.should_suppress(a2, current_time=110.0) is True

    def test_alert_allowed_after_window_expires(self):
        dedup = AlertDeduplicator(suppression_window_seconds=60.0)
        a1 = _make_alert("flow-001", "DDOS")
        a2 = _make_alert("flow-002", "DDOS")

        assert dedup.should_suppress(a1, current_time=100.0) is False
        # After 65 seconds (> 60s), allowed through
        assert dedup.should_suppress(a2, current_time=165.0) is False

    def test_different_threat_class_not_suppressed(self):
        dedup = AlertDeduplicator(suppression_window_seconds=60.0)
        a1 = _make_alert("flow-001", "DDOS")
        a2 = _make_alert("flow-002", "RECONNAISSANCE")

        assert dedup.should_suppress(a1, current_time=100.0) is False
        assert dedup.should_suppress(a2, current_time=105.0) is False

    def test_different_ip_pairs_not_suppressed(self):
        dedup = AlertDeduplicator(suppression_window_seconds=60.0)
        a1 = _make_alert("flow-001", "DDOS", src_ip="192.168.1.10")
        a2 = _make_alert("flow-002", "DDOS", src_ip="192.168.1.20")

        assert dedup.should_suppress(a1, current_time=100.0) is False
        assert dedup.should_suppress(a2, current_time=105.0) is False

    def test_batch_filtering(self):
        dedup = AlertDeduplicator(suppression_window_seconds=60.0)
        alerts = [
            _make_alert("f1", "DDOS"),
            _make_alert("f2", "DDOS"),  # duplicate
            _make_alert("f3", "C2_BEACONING"),
            _make_alert("f4", "DDOS"),  # duplicate
        ]
        filtered = dedup.filter(alerts)
        assert len(filtered) == 2
        assert [a.flow_id for a in filtered] == ["f1", "f3"]

    def test_bounded_capacity_evicts_lru(self):
        # Deduplicator with tiny capacity of 2
        dedup = AlertDeduplicator(suppression_window_seconds=60.0, max_tracked_keys=2)
        a1 = _make_alert("f1", "DDOS", src_ip="10.0.0.1")
        a2 = _make_alert("f2", "DDOS", src_ip="10.0.0.2")
        a3 = _make_alert("f3", "DDOS", src_ip="10.0.0.3")

        assert dedup.should_suppress(a1, current_time=10.0) is False
        assert dedup.should_suppress(a2, current_time=11.0) is False
        # Adding 3rd key should evict 1st key (10.0.0.1)
        assert dedup.should_suppress(a3, current_time=12.0) is False

        # Now a1 is forgotten due to LRU eviction; re-testing a1 is accepted as novel
        assert dedup.should_suppress(a1, current_time=13.0) is False
