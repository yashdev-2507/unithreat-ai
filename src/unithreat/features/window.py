"""
unithreat.features.window
=========================

Incremental streaming window tracking for behavioral feature aggregation.

Provides bounded in-memory sliding window state for:
  - Source fan-out and unique destination tracking
  - Destination fan-in tracking
  - Flow frequency and rates
  - Inter-arrival timing, variance, and periodicity
  - Directional outbound/inbound byte ratios
  - Protocol distributions

Bounded memory:
  - Strict TTL window pruning based on event timestamps
  - Bounded history per entity (deque maxlen)
  - LRU eviction of oldest entities when capacity is reached
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime
import math
from typing import Any


def _parse_epoch_seconds(ts: Any) -> float:
    """Safely convert datetime or ISO string to epoch seconds float."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    if isinstance(ts, str):
        clean = ts.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(clean).timestamp()
        except ValueError:
            return 0.0
    return 0.0


@dataclass(frozen=True)
class FlowSnapshot:
    """Lightweight immutable snapshot of an observed flow for feature aggregation."""
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    direction: str | None
    duration: float
    packet_count: int
    byte_count: int


class FeatureWindowTracker:
    """
    Stateful, bounded window tracker computing rolling behavioral features.
    """

    def __init__(
        self,
        window_duration_seconds: float = 60.0,
        max_events_per_entity: int = 200,
        max_tracked_entities: int = 10_000,
    ) -> None:
        self.window_duration_seconds = window_duration_seconds
        self.max_events_per_entity = max_events_per_entity
        self.max_tracked_entities = max_tracked_entities

        self._src_windows: OrderedDict[str, deque[FlowSnapshot]] = OrderedDict()
        self._dst_windows: OrderedDict[str, deque[FlowSnapshot]] = OrderedDict()
        self._pair_windows: OrderedDict[tuple[str, str], deque[FlowSnapshot]] = OrderedDict()

    def _get_or_create_deque(
        self,
        cache: OrderedDict[Any, deque[FlowSnapshot]],
        key: Any,
    ) -> deque[FlowSnapshot]:
        if key in cache:
            cache.move_to_end(key)
            return cache[key]

        if len(cache) >= self.max_tracked_entities:
            cache.popitem(last=False)

        dq: deque[FlowSnapshot] = deque(maxlen=self.max_events_per_entity)
        cache[key] = dq
        return dq

    def _prune_deque(self, dq: deque[FlowSnapshot], current_ts: float, max_duration: float) -> None:
        cutoff = current_ts - max_duration
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()

    def update_and_compute(
        self,
        flow_timestamp: Any,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        protocol: str,
        direction: str | None,
        duration: float,
        packet_count: int,
        byte_count: int,
    ) -> dict[str, float | int | str | bool | None]:
        """
        Record a flow and compute rolling window features incrementally.
        """
        ts = _parse_epoch_seconds(flow_timestamp)
        proto = protocol.upper()

        snapshot = FlowSnapshot(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto,
            direction=direction,
            duration=duration,
            packet_count=packet_count,
            byte_count=byte_count,
        )

        # 1. Update source tracking window
        src_dq = self._get_or_create_deque(self._src_windows, src_ip)
        src_dq.append(snapshot)
        self._prune_deque(src_dq, ts, self.window_duration_seconds)

        # 2. Update destination tracking window
        dst_dq = self._get_or_create_deque(self._dst_windows, dst_ip)
        dst_dq.append(snapshot)
        self._prune_deque(dst_dq, ts, self.window_duration_seconds)

        # 3. Update conversation pair tracking window (longer window for beaconing)
        pair_key = (src_ip, dst_ip)
        pair_dq = self._get_or_create_deque(self._pair_windows, pair_key)
        pair_dq.append(snapshot)
        self._prune_deque(pair_dq, ts, self.window_duration_seconds * 10)

        # Compute source fan-out and destination metrics
        unique_dst_hosts = len({e.dst_ip for e in src_dq if e.dst_ip})
        unique_dst_ports = len({e.dst_port for e in src_dq if e.dst_port is not None})
        dst_fan_in = len({e.src_ip for e in dst_dq if e.src_ip})

        # Flow counts and window duration
        window_flow_count = len(src_dq)
        if len(src_dq) > 1:
            span = max(src_dq[-1].timestamp - src_dq[0].timestamp, 0.001)
            flow_rate = round(len(src_dq) / span, 4)
            window_bytes_sum = sum(e.byte_count for e in src_dq)
            window_packets_sum = sum(e.packet_count for e in src_dq)
            window_bytes_per_sec = round(window_bytes_sum / span, 4)
            window_packets_per_sec = round(window_packets_sum / span, 4)
        else:
            span = 0.0
            flow_rate = 0.0
            window_bytes_per_sec = 0.0
            window_packets_per_sec = 0.0

        # Protocol distribution
        tcp_count = sum(1 for e in src_dq if e.protocol == "TCP")
        udp_count = sum(1 for e in src_dq if e.protocol == "UDP")
        protocol_tcp_ratio = round(tcp_count / window_flow_count, 4)
        protocol_udp_ratio = round(udp_count / window_flow_count, 4)

        # Outbound / Inbound byte ratios
        outbound_bytes_window = sum(e.byte_count for e in src_dq if e.direction == "outbound")
        inbound_bytes_window = sum(e.byte_count for e in src_dq if e.direction == "inbound")
        outbound_inbound_byte_ratio = round(
            outbound_bytes_window / max(float(inbound_bytes_window), 1.0), 4
        )

        # Inter-arrival timing and regularity across pair
        if len(pair_dq) >= 2:
            pair_timestamps = [e.timestamp for e in pair_dq]
            intervals = [t2 - t1 for t1, t2 in zip(pair_timestamps[:-1], pair_timestamps[1:], strict=True)]
            inter_arrival_time = round(intervals[-1], 4)
            mean_iat = sum(intervals) / len(intervals)
            variance = sum((x - mean_iat) ** 2 for x in intervals) / len(intervals)
            std_iat = math.sqrt(variance)
            cv_iat = round(std_iat / mean_iat, 4) if mean_iat > 0 else 0.0
            periodicity_score = round(max(0.0, 1.0 - cv_iat), 4)
            mean_inter_arrival_time = round(mean_iat, 4)
            inter_arrival_std = round(std_iat, 4)
        else:
            inter_arrival_time = 0.0
            mean_inter_arrival_time = 0.0
            inter_arrival_std = 0.0
            cv_iat = 0.0
            periodicity_score = 0.0

        return {
            # Fan-out & host diversity
            "src_fan_out": unique_dst_hosts,
            "unique_dst_hosts": unique_dst_hosts,
            "unique_dst_ports": unique_dst_ports,
            "dst_fan_in": dst_fan_in,
            # Flow frequency & rates
            "window_flow_count": window_flow_count,
            "flow_rate": flow_rate,
            "window_bytes_per_sec": window_bytes_per_sec,
            "window_packets_per_sec": window_packets_per_sec,
            # Inter-arrival timing & regularity
            "inter_arrival_time": inter_arrival_time,
            "mean_inter_arrival_time": mean_inter_arrival_time,
            "inter_arrival_std": inter_arrival_std,
            "inter_arrival_cv": cv_iat,
            "periodicity_score": periodicity_score,
            # Protocol distribution
            "protocol_tcp_ratio": protocol_tcp_ratio,
            "protocol_udp_ratio": protocol_udp_ratio,
            # Directional byte volume
            "outbound_bytes_window": outbound_bytes_window,
            "inbound_bytes_window": inbound_bytes_window,
            "outbound_inbound_byte_ratio": outbound_inbound_byte_ratio,
        }
