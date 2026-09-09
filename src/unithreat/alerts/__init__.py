"""
unithreat.alerts
================

Alert fusion, deduplication, bounded storage, and pipeline orchestration.
"""

from unithreat.alerts.dedup import AlertDeduplicator
from unithreat.alerts.fusion import AlertFusionEngine, compute_severity
from unithreat.alerts.models import ThreatAlert
from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.alerts.store import BoundedAlertStore, BoundedFlowStore

__all__ = [
    "AlertDeduplicator",
    "AlertFusionEngine",
    "BoundedAlertStore",
    "BoundedFlowStore",
    "IntegratedPipeline",
    "ThreatAlert",
    "compute_severity",
]
