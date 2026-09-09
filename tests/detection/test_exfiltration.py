"""
tests/detection/test_exfiltration.py
====================================

Unit tests for ExfiltrationDetector.
"""

from __future__ import annotations

import pytest

from unithreat.detection.exfiltration import ExfiltrationDetector
from unithreat.features.models import FeatureRecord


def _make_exfil_record(
    byte_count: int,
    duration: float,
    direction: str = "outbound",
    bytes_per_sec: float | None = None,
) -> FeatureRecord:
    bps = bytes_per_sec if bytes_per_sec is not None else (byte_count / max(duration, 0.001))
    return FeatureRecord(
        flow_id="exfil-001",
        timestamp="2026-09-06T12:00:00Z",
        entity_id="192.168.1.77",
        features={
            "src_ip": "192.168.1.77",
            "dst_ip": "203.0.113.88",
            "protocol": "TCP",
            "dst_port": 443,
            "direction": direction,
            "byte_count": byte_count,
            "duration": duration,
            "bytes_per_sec": bps,
        },
    )


class TestExfiltrationDetector:
    def test_normal_traffic_not_detected(self):
        detector = ExfiltrationDetector()
        # Normal web flow: 45 KB over 2 seconds
        rec = _make_exfil_record(byte_count=45_000, duration=2.0)
        res = detector.detect(rec)
        assert res is None

    def test_inbound_download_not_classified_as_exfiltration(self):
        detector = ExfiltrationDetector()
        # Large incoming download: 50 MB inbound
        rec = _make_exfil_record(byte_count=50_000_000, duration=30.0, direction="inbound")
        res = detector.detect(rec)
        assert res is None

    def test_large_outbound_exfiltration_detected(self):
        detector = ExfiltrationDetector()
        # Large outbound transfer: 4.5 MB over 25 seconds
        rec = _make_exfil_record(byte_count=4_500_000, duration=25.0, direction="outbound")
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "DATA_EXFILTRATION"
        assert res.confidence >= 0.75
        assert any(e.signal_name == "large_outbound_volume" for e in res.evidence)
        assert any(e.signal_name == "sustained_transfer" for e in res.evidence)

    def test_normal_bidirectional_traffic_not_detected(self):
        detector = ExfiltrationDetector()
        # 2 MB outbound, but balanced bidirectional traffic with low outbound/inbound ratio (0.8)
        rec = FeatureRecord(
            flow_id="bidi-001",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.77",
                "dst_ip": "203.0.113.88",
                "direction": "outbound",
                "byte_count": 2_000_000,
                "duration": 15.0,
                "bytes_per_sec": 133_333.0,
                "outbound_inbound_byte_ratio": 0.80,
            },
        )
        res = detector.detect(rec)
        assert res is None

    def test_high_outbound_low_inbound_ratio_detected(self):
        detector = ExfiltrationDetector()
        # High outbound/inbound ratio anomaly (3 MB outbound with ratio 150)
        rec = FeatureRecord(
            flow_id="ratio-exfil-001",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.77",
                "dst_ip": "203.0.113.88",
                "direction": "outbound",
                "byte_count": 3_000_000,
                "duration": 20.0,
                "bytes_per_sec": 150_000.0,
                "outbound_inbound_byte_ratio": 150.0,
            },
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "DATA_EXFILTRATION"
        assert any(e.signal_name == "outbound_inbound_ratio" for e in res.evidence)
        ratio_sig = next(e for e in res.evidence if e.signal_name == "outbound_inbound_ratio")
        assert ratio_sig.value == 150.0

    def test_missing_directional_data_handled_cleanly(self):
        detector = ExfiltrationDetector()
        # Missing direction and ratio: should still detect on large volume/sustained transfer without crashing
        # and must NOT invent a fake ratio evidence signal
        rec = FeatureRecord(
            flow_id="nodir-exfil-001",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.77",
                "dst_ip": "203.0.113.88",
                "byte_count": 3_500_000,
                "duration": 25.0,
                "bytes_per_sec": 140_000.0,
            },
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "DATA_EXFILTRATION"
        assert any(e.signal_name == "large_outbound_volume" for e in res.evidence)
        # Ratio signal must NOT be invented
        assert not any(e.signal_name == "outbound_inbound_ratio" for e in res.evidence)
