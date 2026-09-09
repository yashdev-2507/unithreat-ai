"""
tests/detection/test_port_scan.py
=================================

Unit tests for PortScanDetector.
"""

from __future__ import annotations

import pytest

from unithreat.detection.config import PortScanConfig, WindowConfig
from unithreat.detection.port_scan import PortScanDetector
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


def _make_scan_probe(
    idx: int,
    ts: str,
    src_ip: str = "192.168.1.105",
    dst_ip: str = "192.168.1.50",
    dst_port: int = 80,
    duration: float = 0.001,
    byte_count: int = 44,
) -> FeatureRecord:
    return FeatureRecord(
        flow_id=f"scan-{idx:04d}",
        timestamp=ts,
        entity_id=src_ip,
        features={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "TCP",
            "duration": duration,
            "byte_count": byte_count,
            "is_syn": True,
            "tcp_flags": "SYN",
        },
    )


class TestPortScanDetector:
    def test_normal_traffic_not_detected(self):
        detector = PortScanDetector()
        wm = BoundedWindowManager()

        # Regular web client contacting port 443 only repeatedly
        records = [
            _make_scan_probe(i, f"2026-09-06T12:00:0{i}.000000Z", dst_port=443)
            for i in range(1, 10)
        ]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is None

    def test_high_port_fanout_detected(self):
        detector = PortScanDetector()
        wm = BoundedWindowManager()

        # Single scanner contacting 15 distinct ports in 1 second
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 1433, 3306, 8080]
        records = [
            _make_scan_probe(i, f"2026-09-06T12:00:00.{i * 50000:06d}Z", dst_port=p)
            for i, p in enumerate(ports, 1)
        ]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is not None
        assert res.threat_class == "RECONNAISSANCE"
        assert res.confidence >= 0.65
        assert any(e.signal_name == "port_fan_out" for e in res.evidence)
        assert any(e.signal_name == "syn_probe_pattern" for e in res.evidence)

    def test_horizontal_host_sweep_detected(self):
        detector = PortScanDetector()
        wm = BoundedWindowManager()

        # Scanner sweeps port 22 across 12 distinct hosts
        records = [
            _make_scan_probe(
                i,
                f"2026-09-06T12:00:00.{i * 50000:06d}Z",
                dst_ip=f"192.168.1.{i * 10}",
                dst_port=22,
            )
            for i in range(1, 13)
        ]
        for r in records:
            wm.update(r)

        res = detector.detect(records[-1], window_manager=wm)
        assert res is not None
        assert res.threat_class == "RECONNAISSANCE"
        assert any(e.signal_name == "host_sweep" for e in res.evidence)

    def test_bounded_window_expires_old_probes(self):
        # Window duration is 10 seconds
        config = WindowConfig(window_duration_seconds=10.0)
        wm = BoundedWindowManager(config=config)
        detector = PortScanDetector()

        # 5 probes at time 0s
        for i in range(1, 6):
            wm.update(_make_scan_probe(i, "2026-09-06T12:00:00.000000Z", dst_port=i * 10))

        # 5 probes at time 25s (old probes from time 0s should expire)
        last_rec = None
        for i in range(6, 11):
            last_rec = _make_scan_probe(i, "2026-09-06T12:00:25.000000Z", dst_port=i * 100)
            wm.update(last_rec)

        res = detector.detect(last_rec, window_manager=wm)
        # Only 5 probes in the active 10s window (below default min_probed_ports=8)
        assert res is None
