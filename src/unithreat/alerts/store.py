"""
unithreat.alerts.store
======================

Bounded, thread-safe in-memory storage for standardized threat alerts and recent flows.
"""

from __future__ import annotations

from collections import deque
import threading
from typing import Any

from unithreat.alerts.models import ThreatAlert


class BoundedAlertStore:
    """
    Thread-safe, bounded in-memory alert ring-buffer.
    Guarantees oldest alerts are automatically evicted when capacity is reached.
    """

    def __init__(self, max_alerts: int = 1000) -> None:
        self.max_alerts = max_alerts
        self._alerts: deque[dict[str, Any]] = deque(maxlen=max_alerts)
        self._by_flow_id: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def add(self, alert: ThreatAlert | dict[str, Any]) -> dict[str, Any]:
        """
        Add an alert to the store. Evicts oldest alert when max capacity is reached.
        """
        alert_dict = alert.to_contract_dict() if isinstance(alert, ThreatAlert) else dict(alert)

        with self._lock:
            # If deque is full, prune the oldest alert from the index
            if len(self._alerts) == self.max_alerts:
                oldest = self._alerts[0]
                old_flow_id = oldest.get("flow_id")
                if old_flow_id and old_flow_id in self._by_flow_id:
                    del self._by_flow_id[old_flow_id]

            self._alerts.append(alert_dict)
            flow_id = alert_dict.get("flow_id")
            if flow_id:
                self._by_flow_id[flow_id] = alert_dict

        return alert_dict

    def add_many(self, alerts: list[ThreatAlert | dict[str, Any]]) -> list[dict[str, Any]]:
        """Add multiple alerts atomically."""
        return [self.add(a) for a in alerts]

    def get_all(
        self,
        threat_class: str | None = None,
        severity: str | None = None,
        min_confidence: float | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Query alerts with optional filtering. Returns newest alerts first.
        """
        with self._lock:
            # Iterate in reverse order (newest first)
            results: list[dict[str, Any]] = []
            for alert in reversed(self._alerts):
                if threat_class and alert.get("threat_class") != threat_class:
                    continue
                if severity and alert.get("severity") != severity:
                    continue
                if min_confidence is not None and alert.get("confidence", 0.0) < min_confidence:
                    continue

                results.append(dict(alert))
                if limit and len(results) >= limit:
                    break

            return results

    def get_by_flow_id(self, flow_id: str) -> dict[str, Any] | None:
        """Lookup alert by flow_id."""
        with self._lock:
            val = self._by_flow_id.get(flow_id)
            return dict(val) if val is not None else None

    def count(self) -> int:
        """Total number of stored alerts."""
        with self._lock:
            return len(self._alerts)

    def stats(self) -> dict[str, Any]:
        """Compute aggregated statistics over stored alerts."""
        with self._lock:
            total = len(self._alerts)
            by_threat_class: dict[str, int] = {}
            by_severity: dict[str, int] = {
                "LOW": 0,
                "MEDIUM": 0,
                "HIGH": 0,
                "CRITICAL": 0,
            }

            for alert in self._alerts:
                tc = alert.get("threat_class", "UNKNOWN")
                by_threat_class[tc] = by_threat_class.get(tc, 0) + 1

                sev = alert.get("severity", "LOW")
                if sev in by_severity:
                    by_severity[sev] += 1

            return {
                "total_alerts": total,
                "by_threat_class": by_threat_class,
                "by_severity": by_severity,
            }

    def clear(self) -> None:
        """Clear all stored alerts."""
        with self._lock:
            self._alerts.clear()
            self._by_flow_id.clear()


class BoundedFlowStore:
    """
    Thread-safe, bounded in-memory store for recent raw flow records.
    Supports GET /flows/{flow_id}.
    """

    def __init__(self, max_flows: int = 2000) -> None:
        self.max_flows = max_flows
        self._flows: deque[dict[str, Any]] = deque(maxlen=max_flows)
        self._by_flow_id: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def add(self, flow: dict[str, Any]) -> None:
        flow_dict = dict(flow)
        with self._lock:
            if len(self._flows) == self.max_flows:
                oldest = self._flows[0]
                old_id = oldest.get("flow_id")
                if old_id and old_id in self._by_flow_id:
                    del self._by_flow_id[old_id]

            self._flows.append(flow_dict)
            flow_id = flow_dict.get("flow_id")
            if flow_id:
                self._by_flow_id[flow_id] = flow_dict

    def get(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock:
            val = self._by_flow_id.get(flow_id)
            return dict(val) if val is not None else None

    def count(self) -> int:
        with self._lock:
            return len(self._flows)

    def clear(self) -> None:
        with self._lock:
            self._flows.clear()
            self._by_flow_id.clear()
