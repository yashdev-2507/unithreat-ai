"""
unithreat.alerts
================

Alert fusion, deduplication, bounded storage, and pipeline orchestration.
"""

from unithreat.alerts.dedup import AlertDeduplicator
from unithreat.alerts.fusion import AlertFusionEngine, compute_severity
from unithreat.alerts.models import ThreatAlert
from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.alerts.store import (
    BoundedAlertStore,
    BoundedFeatureStore,
    BoundedFlowStore,
    BoundedPredictionStore,
)

__all__ = [
    "AlertDeduplicator",
    "AlertFusionEngine",
    "BoundedAlertStore",
    "BoundedFeatureStore",
    "BoundedFlowStore",
    "BoundedPredictionStore",
    "IntegratedPipeline",
    "ThreatAlert",
    "compute_severity",
]
