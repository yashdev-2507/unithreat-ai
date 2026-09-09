"""
unithreat.detection.window
==========================

Bounded streaming state and window aggregation for behavioral detection.

Ensures:
  - Bounded in-memory retention (strictly no unbounded memory growth)
  - Automatic time-based expiration of stale historical events
  - LRU-style entity eviction when entity capacity is reached
  - Incremental aggregation of temporal and behavioral metrics
"""

from __future__ import annotations

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime
import math
from typing import Any

from unithreat.detection.config import WindowConfig
from unithreat.features.models import FeatureRecord


def _parse_ts(ts_str: str) -> float:
    """Parse ISO 8601 timestamp string into unix epoch timestamp (float)."""
    # Handles both '...Z' and standard ISO formats
    clean = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean).timestamp()


@dataclass(frozen=True)
class TrackedEvent:
    """Lightweight immutable snapshot of an observed flow event."""
    timestamp: float
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    direction: str | None
    duration: float
    packet_count: int
    byte_count: int
    is_syn: bool
    is_udp: bool


class BoundedEntityTracker:
    """
    Tracks historical events for an entity within a bounded time window.
    """

    def __init__(self, maxlen: int, max_duration: float) -> None:
        self.maxlen = maxlen
        self.max_duration = max_duration
        self.events: deque[TrackedEvent] = deque(maxlen=maxlen)

    def add(self, event: TrackedEvent) -> None:
        self.events.append(event)
        self.prune(event.timestamp)

    def prune(self, current_ts: float) -> None:
        cutoff = current_ts - self.max_duration
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def get_events(self) -> list[TrackedEvent]:
        return list(self.events)


class BoundedWindowManager:
    """
    Manages bounded sliding windows across network entities with bounded memory.
    """

    def __init__(self, config: WindowConfig | None = None) -> None:
        self.config = config or WindowConfig()
        self._dst_trackers: OrderedDict[str, BoundedEntityTracker] = OrderedDict()
        self._src_trackers: OrderedDict[str, BoundedEntityTracker] = OrderedDict()
        self._pair_trackers: OrderedDict[tuple[str, str], BoundedEntityTracker] = OrderedDict()

    def _get_or_create(
        self,
        cache: OrderedDict[Any, BoundedEntityTracker],
        key: Any,
        custom_duration: float | None = None,
    ) -> BoundedEntityTracker:
        if key in cache:
            cache.move_to_end(key)
            return cache[key]

        if len(cache) >= self.config.max_tracked_entities:
            cache.popitem(last=False)  # Evict oldest entity (LRU)

        duration = custom_duration or self.config.window_duration_seconds
        tracker = BoundedEntityTracker(maxlen=self.config.max_events_per_entity, max_duration=duration)
        cache[key] = tracker
        return tracker

    def update(self, record: FeatureRecord) -> TrackedEvent:
        """
        Record a feature event into destination, source, and pair tracking windows.
        """
        feat = record.features
        ts = _parse_ts(record.timestamp)

        src_ip = str(feat.get("src_ip") or "")
        dst_ip = str(feat.get("dst_ip") or "")
        protocol = str(feat.get("protocol") or "").upper()
        direction = feat.get("direction")
        direction_str = str(direction) if direction is not None else None

        duration = float(feat.get("duration") or 0.0)
        packet_count = int(feat.get("packet_count") or 0)
        byte_count = int(feat.get("byte_count") or 0)
        is_syn = bool(feat.get("is_syn"))
        is_udp = bool(feat.get("is_udp"))

        src_port = int(feat["src_port"]) if feat.get("src_port") is not None else None
        dst_port = int(feat["dst_port"]) if feat.get("dst_port") is not None else None

        event = TrackedEvent(
            timestamp=ts,
            flow_id=record.flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            direction=direction_str,
            duration=duration,
            packet_count=packet_count,
            byte_count=byte_count,
            is_syn=is_syn,
            is_udp=is_udp,
        )

        if dst_ip:
            dst_tracker = self._get_or_create(self._dst_trackers, dst_ip)
            dst_tracker.add(event)

        if src_ip:
            src_tracker = self._get_or_create(self._src_trackers, src_ip)
            src_tracker.add(event)

        if src_ip and dst_ip:
            # Pair tracking uses longer window (e.g. 10x) for beacon detection
            pair_tracker = self._get_or_create(
                self._pair_trackers,
                (src_ip, dst_ip),
                custom_duration=self.config.window_duration_seconds * 10,
            )
            pair_tracker.add(event)

        return event

    def get_destination_history(self, dst_ip: str) -> list[TrackedEvent]:
        tracker = self._dst_trackers.get(dst_ip)
        return tracker.get_events() if tracker else []

    def get_source_history(self, src_ip: str) -> list[TrackedEvent]:
        tracker = self._src_trackers.get(src_ip)
        return tracker.get_events() if tracker else []

    def get_pair_history(self, src_ip: str, dst_ip: str) -> list[TrackedEvent]:
        tracker = self._pair_trackers.get((src_ip, dst_ip))
        return tracker.get_events() if tracker else []
