"""
unithreat.alerts.pipeline
=========================

Integrated pipeline coordinating:
Flow -> Feature Extraction -> Statistical Detection -> ML Inference -> Alert Fusion -> Deduplication -> Storage & Streaming.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol

from unithreat.alerts.dedup import AlertDeduplicator
from unithreat.alerts.fusion import AlertFusionEngine
from unithreat.alerts.models import ThreatAlert
from unithreat.alerts.store import BoundedAlertStore, BoundedFlowStore
from unithreat.detection.engine import DetectionEngine
from unithreat.features.extractor import FeatureExtractor
from unithreat.features.models import FeatureRecord
from unithreat.ingest.models import Flow
from unithreat.ingest.parser import parse_flow
from unithreat.ml.inference import MLInferenceEngine

logger = logging.getLogger(__name__)


class AlertBroadcaster(Protocol):
    def broadcast(self, alert_dict: dict[str, Any]) -> int: ...


class IntegratedPipeline:
    """
    Complete threat intelligence pipeline combining passive flow extraction,
    statistical/behavioral detection, machine learning, fusion, and alerting.
    """

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        ml_engine: MLInferenceEngine | None = None,
        fusion_engine: AlertFusionEngine | None = None,
        deduplicator: AlertDeduplicator | None = None,
        alert_store: BoundedAlertStore | None = None,
        flow_store: BoundedFlowStore | None = None,
        stream_manager: AlertBroadcaster | Any | None = None,
        enable_windowing: bool = True,
    ) -> None:
        self.extractor = FeatureExtractor(enable_windowing=enable_windowing)
        self.detection_engine = detection_engine or DetectionEngine()
        self.ml_engine = ml_engine
        self.fusion_engine = fusion_engine or AlertFusionEngine()
        self.deduplicator = deduplicator or AlertDeduplicator()
        self.alert_store = alert_store or BoundedAlertStore()
        self.flow_store = flow_store or BoundedFlowStore()
        self.stream_manager = stream_manager

        self.total_flows_processed: int = 0

    @classmethod
    def with_default_models(
        cls,
        model_dir: Path | str | None = "artifacts/models/rf-baseline-v1",
        stream_manager: AlertBroadcaster | Any | None = None,
    ) -> IntegratedPipeline:
        """
        Factory to construct an IntegratedPipeline attempting to load the baseline ML model.
        """
        ml_engine: MLInferenceEngine | None = None
        if model_dir is not None:
            p = Path(model_dir)
            if (p / "model.joblib").exists():
                try:
                    ml_engine = MLInferenceEngine(model_dir=p)
                except Exception as exc:
                    logger.warning("Could not load ML model from %s: %s", p, exc)

        return cls(
            ml_engine=ml_engine,
            stream_manager=stream_manager,
        )

    def process_flow(self, flow_or_dict: Flow | dict[str, Any]) -> list[dict[str, Any]]:
        """
        Process an incoming flow through the complete intelligence pipeline.

        Returns
        -------
        list[dict[str, Any]]
            Newly generated non-duplicate alerts conforming to contracts/alert-schema.json.
        """
        # 1. Parse and store raw flow
        raw_dict = flow_or_dict if isinstance(flow_or_dict, dict) else flow_or_dict.model_dump()
        self.flow_store.add(raw_dict)
        self.total_flows_processed += 1

        try:
            flow_obj = parse_flow(raw_dict)
        except Exception as exc:
            logger.warning("Malformed flow rejected: %s", exc)
            return []

        # 2. Extract normalized features
        record = self.extractor.extract(flow_obj)

        # 3. Statistical threat detection
        det_results = self.detection_engine.process(record)

        # 4. ML inference (if available)
        ml_pred = None
        if self.ml_engine is not None:
            try:
                ml_pred = self.ml_engine.predict(record)
            except Exception as exc:
                logger.warning("ML inference failed on flow %s: %s", record.flow_id, exc)

        # 5. Alert Fusion
        fused_alerts = self.fusion_engine.fuse(
            detection_results=det_results,
            ml_prediction=ml_pred,
            flow_context=record,
        )

        # 6. Deduplication
        novel_alerts = self.deduplicator.filter(fused_alerts)

        # 7. Storage
        saved_alerts = self.alert_store.add_many(novel_alerts)

        # 8. Live Broadcast
        if self.stream_manager is not None:
            for alert in saved_alerts:
                self.stream_manager.broadcast(alert)

        return saved_alerts
