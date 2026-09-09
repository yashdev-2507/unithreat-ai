"""
unithreat.alerts.fusion
=======================

Alert Fusion Engine combining statistical detection results and ML predictions.

Strictly aligned with:
  - contracts/alert-schema.json
  - contracts/evidence-schema.json
  - contracts/ml-prediction-schema.json
"""

from __future__ import annotations

from typing import Any, Literal, Sequence
from datetime import datetime, timezone

from unithreat.alerts.models import ThreatAlert
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.features.models import FeatureRecord
from unithreat.ingest.models import Flow
from unithreat.ml.models import MLPrediction


def compute_severity(
    confidence: float,
    is_ml_only: bool = False,
) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    """
    Map confidence to severity rating consistently.

    When is_ml_only=True, severity is capped at HIGH because Random Forest
    scores are uncalibrated and lack deterministic statistical ground truth.
    """
    if is_ml_only:
        if confidence >= 0.65:
            return "HIGH"
        if confidence >= 0.50:
            return "MEDIUM"
        return "LOW"

    if confidence >= 0.90:
        return "CRITICAL"
    if confidence >= 0.75:
        return "HIGH"
    if confidence >= 0.50:
        return "MEDIUM"
    return "LOW"


def _extract_flow_metadata(
    flow_or_record: Flow | FeatureRecord | dict[str, Any] | None,
) -> dict[str, Any]:
    """Extract standard network coordinates from flow or record if available."""
    if flow_or_record is None:
        return {"timestamp": None, "source_ip": None, "destination_ip": None, "protocol": None}

    if isinstance(flow_or_record, Flow):
        ts = flow_or_record.timestamp
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if hasattr(ts, "strftime") else str(ts)
        return {
            "timestamp": ts_str,
            "source_ip": flow_or_record.src_ip,
            "destination_ip": flow_or_record.dst_ip,
            "protocol": flow_or_record.protocol,
        }

    if isinstance(flow_or_record, FeatureRecord):
        return {
            "timestamp": flow_or_record.timestamp,
            "source_ip": str(flow_or_record.features.get("src_ip")) if flow_or_record.features.get("src_ip") else flow_or_record.entity_id,
            "destination_ip": str(flow_or_record.features.get("dst_ip")) if flow_or_record.features.get("dst_ip") else None,
            "protocol": str(flow_or_record.features.get("protocol")) if flow_or_record.features.get("protocol") else None,
        }

    if isinstance(flow_or_record, dict):
        return {
            "timestamp": str(flow_or_record.get("timestamp")) if flow_or_record.get("timestamp") else None,
            "source_ip": str(flow_or_record.get("src_ip")) if flow_or_record.get("src_ip") else None,
            "destination_ip": str(flow_or_record.get("dst_ip")) if flow_or_record.get("dst_ip") else None,
            "protocol": str(flow_or_record.get("protocol")) if flow_or_record.get("protocol") else None,
        }

    return {"timestamp": None, "source_ip": None, "destination_ip": None, "protocol": None}


class AlertFusionEngine:
    """
    Deterministic alert fusion engine combining statistical and ML evidence.
    """

    def __init__(
        self,
        min_ml_standalone_score: float = 0.75,
    ) -> None:
        self.min_ml_standalone_score = min_ml_standalone_score

    def fuse(
        self,
        detection_results: Sequence[DetectionResult],
        ml_prediction: MLPrediction | None = None,
        flow_context: Flow | FeatureRecord | dict[str, Any] | None = None,
    ) -> list[ThreatAlert]:
        """
        Fuse statistical detection results and ML prediction into ThreatAlerts.

        Explicit Fusion Cases:
          1. Statistical + ML Agree: Preserves statistical threat class, modest confidence boost.
          2. Statistical + ML Disagree: Preserves statistical threat class, dampens confidence.
          3. Statistical Only: Preserves statistical detection result unchanged.
          4. ML Only: Fuses as an ML hypothesis with conservative severity (never CRITICAL).
        """
        fused_alerts: list[ThreatAlert] = []
        flow_meta = _extract_flow_metadata(flow_context)

        # Cases 1, 2, 3: Statistical detections present
        if detection_results:
            for det in detection_results:
                # Case 3: Statistical Only (No ML or ML prediction is None)
                if ml_prediction is None:
                    fused_alerts.append(
                        ThreatAlert(
                            timestamp=det.timestamp,
                            flow_id=det.flow_id,
                            threat_class=det.threat_class,
                            confidence=det.confidence,
                            severity=det.severity,
                            evidence=list(det.evidence),
                            source_ip=det.source_ip or flow_meta["source_ip"],
                            destination_ip=det.destination_ip or flow_meta["destination_ip"],
                            protocol=det.protocol or flow_meta["protocol"],
                            model_version=det.model_version,
                            explanation=det.explanation,
                        )
                    )
                    continue

                # Case 1: Statistical + ML Agree
                if ml_prediction.threat_class == det.threat_class:
                    boost = det.confidence + (1.0 - det.confidence) * 0.25 * ml_prediction.score
                    final_conf = min(1.0, max(0.0, round(boost, 4)))

                    ml_ev = EvidenceSignal(
                        signal_name="ml_classifier_support",
                        value=round(float(ml_prediction.score), 4),
                        direction="supporting",
                        reliability=0.85,
                        supporting_features=["rf_ensemble_trees"],
                        threat_class=ml_prediction.threat_class,
                    )
                    combined_evidence = list(det.evidence) + [ml_ev]
                    combined_model_version = f"{det.model_version or 'statistical'}+{ml_prediction.model_version}"
                    explanation_text = (
                        f"{det.explanation or ''} "
                        f"Supported by ML model {ml_prediction.model_version} "
                        f"(score={ml_prediction.score:.4f}, uncalibrated)."
                    ).strip()

                    fused_alerts.append(
                        ThreatAlert(
                            timestamp=det.timestamp,
                            flow_id=det.flow_id,
                            threat_class=det.threat_class,
                            confidence=final_conf,
                            severity=compute_severity(final_conf, is_ml_only=False),
                            evidence=combined_evidence,
                            source_ip=det.source_ip or flow_meta["source_ip"],
                            destination_ip=det.destination_ip or flow_meta["destination_ip"],
                            protocol=det.protocol or flow_meta["protocol"],
                            model_version=combined_model_version,
                            explanation=explanation_text,
                        )
                    )

                # Case 2: Statistical + ML Disagree (ML predicts BENIGN or another class)
                else:
                    final_conf = round(det.confidence * 0.85, 4)

                    ml_ev = EvidenceSignal(
                        signal_name="ml_classifier_divergence",
                        value=round(float(ml_prediction.score), 4),
                        direction="contradicting",
                        reliability=0.50,
                        supporting_features=["rf_ensemble_trees"],
                        threat_class=ml_prediction.threat_class,
                    )
                    combined_evidence = list(det.evidence) + [ml_ev]
                    combined_model_version = f"{det.model_version or 'statistical'}+{ml_prediction.model_version}"
                    explanation_text = (
                        f"{det.explanation or ''} "
                        f"ML model {ml_prediction.model_version} diverged with prediction "
                        f"{ml_prediction.threat_class} (score={ml_prediction.score:.4f}, uncalibrated)."
                    ).strip()

                    fused_alerts.append(
                        ThreatAlert(
                            timestamp=det.timestamp,
                            flow_id=det.flow_id,
                            threat_class=det.threat_class,
                            confidence=final_conf,
                            severity=compute_severity(final_conf, is_ml_only=False),
                            evidence=combined_evidence,
                            source_ip=det.source_ip or flow_meta["source_ip"],
                            destination_ip=det.destination_ip or flow_meta["destination_ip"],
                            protocol=det.protocol or flow_meta["protocol"],
                            model_version=combined_model_version,
                            explanation=explanation_text,
                        )
                    )

            return fused_alerts

        # Case 4: ML Only (No statistical detections triggered)
        if (
            ml_prediction is not None
            and ml_prediction.threat_class != "BENIGN"
            and ml_prediction.score >= self.min_ml_standalone_score
        ):
            final_conf = round(min(0.75, ml_prediction.score * 0.80), 4)
            severity = compute_severity(final_conf, is_ml_only=True)

            ml_ev = EvidenceSignal(
                signal_name="ml_hypothesis",
                value=round(float(ml_prediction.score), 4),
                direction="supporting",
                reliability=0.65,
                supporting_features=["rf_ensemble_trees"],
                threat_class=ml_prediction.threat_class,
            )

            ts_str = flow_meta["timestamp"] or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            explanation_text = (
                f"Threat hypothesis originated by ML model {ml_prediction.model_version} "
                f"(score={ml_prediction.score:.4f}, uncalibrated). No immediate statistical rule triggered."
            )

            fused_alerts.append(
                ThreatAlert(
                    timestamp=ts_str,
                    flow_id=ml_prediction.flow_id,
                    threat_class=ml_prediction.threat_class,
                    confidence=final_conf,
                    severity=severity,
                    evidence=[ml_ev],
                    source_ip=flow_meta["source_ip"],
                    destination_ip=flow_meta["destination_ip"],
                    protocol=flow_meta["protocol"],
                    model_version=ml_prediction.model_version,
                    explanation=explanation_text,
                )
            )

        return fused_alerts
