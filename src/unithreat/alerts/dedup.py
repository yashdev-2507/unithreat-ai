"""
unithreat.alerts.dedup
======================

Bounded alert deduplication engine.

Suppresses duplicate alerts for identical (source_ip, destination_ip, threat_class)
within a configurable temporal window (default: 60 seconds).
Guarantees bounded memory through LRU eviction and timestamp pruning.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from typing import Any

from unithreat.alerts.models import ThreatAlert


def _parse_timestamp(ts: Any) -> float:
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


class AlertDeduplicator:
    """
    Stateful bounded deduplicator for standardized threat alerts.
    """

    def __init__(
        self,
        suppression_window_seconds: float = 60.0,
        max_tracked_keys: int = 10_000,
    ) -> None:
        self.suppression_window_seconds = suppression_window_seconds
        self.max_tracked_keys = max_tracked_keys
        self._seen_keys: OrderedDict[tuple[str | None, str | None, str], float] = OrderedDict()

    def _make_key(
        self,
        alert: ThreatAlert | dict[str, Any],
    ) -> tuple[str | None, str | None, str]:
        if isinstance(alert, ThreatAlert):
            return (alert.source_ip, alert.destination_ip, alert.threat_class)
        if isinstance(alert, dict):
            return (alert.get("source_ip"), alert.get("destination_ip"), alert["threat_class"])
        raise TypeError(f"Expected ThreatAlert or dict, got {type(alert).__name__!r}")

    def should_suppress(
        self,
        alert: ThreatAlert | dict[str, Any],
        current_time: float | None = None,
    ) -> bool:
        """
        Check if an alert should be suppressed as a duplicate.

        Returns True if the alert should be suppressed (is a duplicate within window).
        Returns False if the alert is accepted as novel.
        """
        if current_time is None:
            ts_val = alert.timestamp if isinstance(alert, ThreatAlert) else alert.get("timestamp")
            current_time = _parse_timestamp(ts_val)

        key = self._make_key(alert)

        # Check existing key
        if key in self._seen_keys:
            last_time = self._seen_keys[key]
            if current_time - last_time < self.suppression_window_seconds:
                # Update LRU order and suppress
                self._seen_keys.move_to_end(key)
                return True

        # Novel alert or expired suppression
        if len(self._seen_keys) >= self.max_tracked_keys:
            self._seen_keys.popitem(last=False)

        self._seen_keys[key] = current_time
        return False

    def filter(
        self,
        alerts: list[ThreatAlert],
    ) -> list[ThreatAlert]:
        """
        Filter a batch of alerts, returning only non-duplicate alerts.
        """
        accepted: list[ThreatAlert] = []
        for alert in alerts:
            if not self.should_suppress(alert):
                accepted.append(alert)
        return accepted

    def clear(self) -> None:
        """Clear all deduplication state."""
        self._seen_keys.clear()
