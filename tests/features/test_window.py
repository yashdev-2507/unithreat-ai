"""
tests/features/test_window.py
=============================

Unit tests for incremental streaming window feature aggregation:
  - source/destination fan-out
  - unique destination ports and hosts
  - flow frequency and rates
  - inter-arrival time, variance, and periodicity
  - protocol distribution (TCP/UDP ratios)
  - outbound/inbound byte ratios
  - incremental streaming behavior
  - bounded window expiration and capacity eviction
"""

from __future__ import annotations

import pytest

from unithreat.features.extractor import FeatureExtractor
from unithreat.features.window import FeatureWindowTracker
from unithreat.ingest.models import Flow


def _make_flow(
    idx: int,
    ts: str,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    dst_port: int = 80,
    protocol: str = "TCP",
    direction: str = "outbound",
    byte_count: int = 1000,
    packet_count: int = 10,
    duration: float = 1.0,
) -> Flow:
    return Flow.model_validate({
        "flow_id": f"f-{idx:04d}",
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "direction": direction,
        "duration": duration,
        "packet_count": packet_count,
        "byte_count": byte_count,
    })


class TestFeatureWindowTracker:
    def test_fan_out_and_unique_destinations(self):
        tracker = FeatureWindowTracker(window_duration_seconds=60.0)
        extractor = FeatureExtractor(window_tracker=tracker)

        # Single source contacting 5 different destination IPs on 3 different ports
        destinations = [
            ("10.0.0.1", 80),
            ("10.0.0.2", 443),
            ("10.0.0.3", 80),
            ("10.0.0.4", 8080),
            ("10.0.0.5", 443),
        ]

        records = []
        for i, (dst, port) in enumerate(destinations, 1):
            flow = _make_flow(i, f"2026-09-06T12:00:0{i}.000000Z", dst_ip=dst, dst_port=port)
            records.append(extractor.extract(flow))

        last = records[-1]
        assert last.features["src_fan_out"] == 5
        assert last.features["unique_dst_hosts"] == 5
        assert last.features["unique_dst_ports"] == 3
        assert last.features["window_flow_count"] == 5

    def test_flow_rate_and_frequency(self):
        tracker = FeatureWindowTracker(window_duration_seconds=60.0)
        extractor = FeatureExtractor(window_tracker=tracker)

        # 10 flows over 2 seconds (starts at 0.0s, ends at 2.0s) -> ~4.5-5.0 flows/sec
        records = [
            extractor.extract(_make_flow(i, f"2026-09-06T12:00:0{i * 0.2:.1f}Z"))
            for i in range(1, 11)
        ]

        last = records[-1]
        assert last.features["window_flow_count"] == 10
        assert last.features["flow_rate"] > 0.0
        assert last.features["window_bytes_per_sec"] > 0.0
        assert last.features["window_packets_per_sec"] > 0.0

    def test_inter_arrival_timing_and_periodicity(self):
        tracker = FeatureWindowTracker(window_duration_seconds=300.0)
        extractor = FeatureExtractor(window_tracker=tracker)

        # 5 periodic flows exactly 10.0 seconds apart between same host pair
        flows = [
            _make_flow(i, f"2026-09-06T12:0{i}:00.000000Z")
            for i in range(1, 6)
        ]

        records = [extractor.extract(f) for f in flows]
        last = records[-1]

        # 60s gap between minutes: inter_arrival_time = 60.0
        assert last.features["inter_arrival_time"] == 60.0
        assert last.features["mean_inter_arrival_time"] == 60.0
        assert last.features["inter_arrival_std"] == 0.0
        assert last.features["inter_arrival_cv"] == 0.0
        assert last.features["periodicity_score"] == 1.0  # Perfectly periodic

    def test_protocol_distribution(self):
        tracker = FeatureWindowTracker(window_duration_seconds=60.0)
        extractor = FeatureExtractor(window_tracker=tracker)

        # 3 TCP flows and 1 UDP flow
        f1 = _make_flow(1, "2026-09-06T12:00:01.000000Z", protocol="TCP")
        f2 = _make_flow(2, "2026-09-06T12:00:02.000000Z", protocol="TCP")
        f3 = _make_flow(3, "2026-09-06T12:00:03.000000Z", protocol="TCP")
        f4 = _make_flow(4, "2026-09-06T12:00:04.000000Z", protocol="UDP")

        for f in (f1, f2, f3):
            extractor.extract(f)
        r4 = extractor.extract(f4)

        assert r4.features["protocol_tcp_ratio"] == 0.75
        assert r4.features["protocol_udp_ratio"] == 0.25

    def test_outbound_inbound_byte_ratio(self):
        tracker = FeatureWindowTracker(window_duration_seconds=60.0)
        extractor = FeatureExtractor(window_tracker=tracker)

        # 8,000 bytes outbound, 2,000 bytes inbound
        f_out = _make_flow(1, "2026-09-06T12:00:01.000000Z", direction="outbound", byte_count=8000)
        f_in = _make_flow(2, "2026-09-06T12:00:02.000000Z", direction="inbound", byte_count=2000)

        extractor.extract(f_out)
        r_in = extractor.extract(f_in)

        assert r_in.features["outbound_bytes_window"] == 8000
        assert r_in.features["inbound_bytes_window"] == 2000
        assert r_in.features["outbound_inbound_byte_ratio"] == 4.0

    def test_bounded_window_expiration(self):
        """Events older than window_duration_seconds must be pruned."""
        tracker = FeatureWindowTracker(window_duration_seconds=10.0)
        extractor = FeatureExtractor(window_tracker=tracker)

        # Flow at t = 0s
        f0 = _make_flow(1, "2026-09-06T12:00:00.000000Z", dst_ip="10.0.0.1")
        extractor.extract(f0)

        # Flow at t = 25s (15 seconds past the 10s window cutoff)
        f1 = _make_flow(2, "2026-09-06T12:00:25.000000Z", dst_ip="10.0.0.2")
        r1 = extractor.extract(f1)

        # f0 should have expired; window only contains f1
        assert r1.features["window_flow_count"] == 1
        assert r1.features["unique_dst_hosts"] == 1
