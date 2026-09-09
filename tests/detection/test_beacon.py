"""
tests/detection/test_beacon.py
==============================

Unit tests for C2BeaconDetector.
"""

from __future__ import annotations

import pytest

from unithreat.detection.beacon import C2BeaconDetector
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


def _make_beacon_flow(
    idx: int,
    ts: str,
    src_ip: str = "192.168.1.42",
    dst_ip: str = "198.51.100.25",
    byte_count: int = 512,
) -> FeatureRecord:
    return FeatureRecord(
        flow_id=f"beacon-{idx:04d}",
        timestamp=ts,
        entity_id=src_ip,
        features={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": 443,
            "protocol": "TCP",
            "duration": 0.25,
            "byte_count": byte_count,
            "direction": "outbound",
        },
    )


class TestC2BeaconDetector:
    def test_irregular_traffic_not_detected(self):
        detector = C2BeaconDetector()
        wm = BoundedWindowManager()

        # Highly irregular intervals: 2s, 35s, 110s, 5s, 80s
        timestamps = [
            "2026-09-06T12:00:00.000000Z",
            "2026-09-06T12:00:02.000000Z",
            "2026-09-06T12:00:37.000000Z",
            "2026-09-06T12:02:27.000000Z",
            "2026-09-06T12:02:32.000000Z",
            "2026-09-06T12:03:52.000000Z",
        ]
        records = [_make_beacon_flow(i, ts) for i, ts in enumerate(timestamps, 1)]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is None

    def test_periodic_traffic_detected(self):
        detector = C2BeaconDetector()
        wm = BoundedWindowManager()

        # Regular 30s interval with slight 0.2s jitter
        timestamps = [
            "2026-09-06T12:00:00.000000Z",
            "2026-09-06T12:00:30.100000Z",
            "2026-09-06T12:01:00.050000Z",
            "2026-09-06T12:01:29.950000Z",
            "2026-09-06T12:02:00.120000Z",
            "2026-09-06T12:02:30.080000Z",
        ]
        records = [_make_beacon_flow(i, ts, byte_count=528) for i, ts in enumerate(timestamps, 1)]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is not None
        assert res.threat_class == "C2_BEACONING"
        assert res.confidence >= 0.80

        # Verify evidence signals
        ev_map = {e.signal_name: e for e in res.evidence}
        assert "temporal_periodicity" in ev_map
        assert ev_map["temporal_periodicity"].value >= 0.90
        assert "connection_repetition" in ev_map
        assert ev_map["connection_repetition"].value == 6.0

    def test_subsecond_burst_not_detected_as_c2(self):
        detector = C2BeaconDetector()
        wm = BoundedWindowManager()

        # Sub-second bursts (e.g. parallel image download chunks 0.05s apart)
        timestamps = [
            f"2026-09-06T12:00:00.{i * 50000:06d}Z"
            for i in range(1, 8)
        ]
        records = [_make_beacon_flow(i, ts) for i, ts in enumerate(timestamps, 1)]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is None
