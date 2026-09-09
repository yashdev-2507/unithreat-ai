"""
tests/detection/test_ddos.py
============================

Unit tests for DDoSDetector.
"""

from __future__ import annotations

import pytest

from unithreat.detection.config import DDoSConfig
from unithreat.detection.ddos import DDoSDetector
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


def _make_record(
    idx: int,
    ts: str,
    src_ip: str,
    dst_ip: str = "10.0.0.50",
    is_syn: bool = True,
    is_udp: bool = False,
    packet_count: int = 2,
    byte_count: int = 120,
    duration: float = 0.001,
) -> FeatureRecord:
    return FeatureRecord(
        flow_id=f"ddos-{idx:04d}",
        timestamp=ts,
        entity_id=src_ip,
        features={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "UDP" if is_udp else "TCP",
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "is_syn": is_syn,
            "is_udp": is_udp,
            "direction": "inbound",
        },
    )


class TestDDoSDetector:
    def test_empty_window_no_detection(self):
        detector = DDoSDetector()
        wm = BoundedWindowManager()
        rec = _make_record(1, "2026-09-06T12:00:00.000000Z", "192.168.1.10")
        res = detector.detect(rec, window_manager=wm)
        assert res is None

    def test_normal_traffic_not_detected(self):
        detector = DDoSDetector()
        wm = BoundedWindowManager()

        # 5 benign flows over 10 seconds to same target
        records = [
            _make_record(i, f"2026-09-06T12:00:0{i * 2}.000000Z", "192.168.1.10", is_syn=False)
            for i in range(5)
        ]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is None

    def test_strong_ddos_detected(self):
        detector = DDoSDetector()
        wm = BoundedWindowManager()

        # 30 flows arriving in 0.2 seconds from 30 distinct sources with SYN flags
        records = [
            _make_record(
                i,
                f"2026-09-06T12:00:00.{i * 6000:06d}Z",
                f"198.51.100.{i}",
                is_syn=True,
            )
            for i in range(1, 31)
        ]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is not None
        assert res.threat_class == "DDOS"
        assert res.confidence >= 0.70
        assert res.severity in ("HIGH", "CRITICAL")
        assert any(e.signal_name == "high_flow_rate" for e in res.evidence)
        assert any(e.signal_name == "source_ip_diversity" for e in res.evidence)

    def test_confidence_increases_with_stronger_evidence(self):
        detector = DDoSDetector()

        # Moderate attack: 15 flows in 0.3s
        wm_mod = BoundedWindowManager()
        recs_mod = [
            _make_record(i, f"2026-09-06T12:00:00.{i * 15000:06d}Z", f"198.51.100.{i}", is_syn=True)
            for i in range(1, 16)
        ]
        for r in recs_mod:
            wm_mod.update(r)
        res_mod = detector.detect(recs_mod[-1], window_manager=wm_mod)

        # Massive attack: 50 flows in 0.1s from 50 sources
        wm_mas = BoundedWindowManager()
        recs_mas = [
            _make_record(i, f"2026-09-06T12:00:00.{i * 2000:06d}Z", f"198.51.100.{i}", is_syn=True)
            for i in range(1, 51)
        ]
        for r in recs_mas:
            wm_mas.update(r)
        res_mas = detector.detect(recs_mas[-1], window_manager=wm_mas)

        assert res_mod is not None
        assert res_mas is not None
        assert res_mas.confidence >= res_mod.confidence

    def test_zero_duration_flows_handled(self):
        detector = DDoSDetector()
        wm = BoundedWindowManager()
        records = [
            _make_record(i, f"2026-09-06T12:00:00.{i * 5000:06d}Z", f"198.51.100.{i}", duration=0.0)
            for i in range(1, 25)
        ]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is not None

    def test_missing_optional_features_no_crash(self):
        detector = DDoSDetector()
        wm = BoundedWindowManager()
        rec = FeatureRecord(
            flow_id="f-bare",
            timestamp="2026-09-06T12:00:00Z",
            features={"dst_ip": "10.0.0.50"},
        )
        wm.update(rec)
        res = detector.detect(rec, window_manager=wm)
        assert res is None

    def test_ddos_source_diversity_evidence_and_explanation(self):
        detector = DDoSDetector()
        wm = BoundedWindowManager()
        # High entropy distributed flood from 25 distinct sources
        records = [
            _make_record(i, f"2026-09-06T12:00:00.{i * 8000:06d}Z", f"198.51.100.{i}", is_syn=True)
            for i in range(1, 26)
        ]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is not None
        ev_names = {e.signal_name for e in res.evidence}
        assert "destination_concentration" in ev_names
        assert "distributed_source_diversity" in ev_names
        # Explanation must describe passive distributed/spoofing-like diversity, not confirmed spoofing
        assert "distributed/spoofing-like source diversity" in res.explanation
        assert "not confirmed spoofing" in res.explanation
