"""
tests/alerts/test_fusion.py
===========================

Comprehensive test suite for AlertFusionEngine:
  - Case 1: Statistical + ML Agree (modest confidence boost, supporting ML evidence)
  - Case 2: Statistical + ML Disagree (statistical threat preserved, confidence dampened, contradicting ML evidence)
  - Case 3: Statistical Only (preserves statistical result completely unchanged)
  - Case 4: ML Only (conservative severity, never CRITICAL, confidence capped)
  - Strict compliance with contracts/alert-schema.json and contracts/evidence-schema.json
"""

from __future__ import annotations

import json
from pathlib import Path
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import pytest

from unithreat.alerts.fusion import AlertFusionEngine, compute_severity
from unithreat.alerts.models import ThreatAlert
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.ml.models import MLPrediction

ROOT = Path(__file__).resolve().parents[2]
ALERT_SCHEMA_PATH = ROOT / "contracts" / "alert-schema.json"
EVIDENCE_SCHEMA_PATH = ROOT / "contracts" / "evidence-schema.json"


@pytest.fixture(scope="module")
def alert_validator() -> Draft202012Validator:
    with ALERT_SCHEMA_PATH.open(encoding="utf-8") as f:
        alert_schema = json.load(f)
    with EVIDENCE_SCHEMA_PATH.open(encoding="utf-8") as f:
        evidence_schema = json.load(f)

    registry = Registry().with_resources(
        [("evidence-schema.json", Resource.from_contents(evidence_schema))]
    )
    return Draft202012Validator(alert_schema, registry=registry)


@pytest.fixture
def fusion_engine() -> AlertFusionEngine:
    return AlertFusionEngine()


@pytest.fixture
def sample_detection_result() -> DetectionResult:
    ev = EvidenceSignal(
        signal_name="high_packet_rate",
        value=5000.0,
        direction="supporting",
        reliability=0.95,
        supporting_features=["packets_per_sec"],
        threat_class="DDOS",
    )
    return DetectionResult(
        timestamp="2026-09-08T08:00:00.000000Z",
        flow_id="flow-stat-ddos-001",
        threat_class="DDOS",
        confidence=0.85,
        severity="HIGH",
        evidence=[ev],
        source_ip="192.168.1.100",
        destination_ip="10.0.0.50",
        protocol="TCP",
        model_version="statistical-v1",
        explanation="High volumetric packet rate observed.",
    )


class TestAlertFusionEngine:
    def test_case_1_statistical_and_ml_agree(
        self,
        fusion_engine: AlertFusionEngine,
        sample_detection_result: DetectionResult,
        alert_validator: Draft202012Validator,
    ):
        ml_pred = MLPrediction(
            flow_id="flow-stat-ddos-001",
            threat_class="DDOS",
            score=0.92,
            model_version="rf-baseline-v1",
            calibrated=False,
        )

        alerts = fusion_engine.fuse(
            detection_results=[sample_detection_result],
            ml_prediction=ml_pred,
        )

        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, ThreatAlert)
        assert alert.threat_class == "DDOS"
        # Statistical confidence was 0.85; with ML agreement it receives a modest boost:
        # 0.85 + (1.0 - 0.85) * 0.25 * 0.92 = 0.85 + 0.0345 = 0.8845
        assert alert.confidence == pytest.approx(0.8845, abs=0.001)
        assert alert.confidence > sample_detection_result.confidence
        assert alert.severity in ("HIGH", "CRITICAL")
        assert "rf-baseline-v1" in (alert.model_version or "")
        assert "uncalibrated" in (alert.explanation or "")

        # Check evidence signals: original statistical + supporting ML signal
        assert len(alert.evidence) == 2
        signals = {e.signal_name: e for e in alert.evidence}
        assert "high_packet_rate" in signals
        assert "ml_classifier_support" in signals
        assert signals["ml_classifier_support"].direction == "supporting"
        assert signals["ml_classifier_support"].value == 0.92

        # Validate against contracts/alert-schema.json
        alert_validator.validate(alert.to_contract_dict())

    def test_case_2_statistical_and_ml_disagree(
        self,
        fusion_engine: AlertFusionEngine,
        sample_detection_result: DetectionResult,
        alert_validator: Draft202012Validator,
    ):
        ml_pred = MLPrediction(
            flow_id="flow-stat-ddos-001",
            threat_class="BENIGN",
            score=0.70,
            model_version="rf-baseline-v1",
            calibrated=False,
        )

        alerts = fusion_engine.fuse(
            detection_results=[sample_detection_result],
            ml_prediction=ml_pred,
        )

        assert len(alerts) == 1
        alert = alerts[0]
        # Statistical threat class is preserved
        assert alert.threat_class == "DDOS"
        # Confidence is dampened (0.85 * 0.85 = 0.7225)
        assert alert.confidence == pytest.approx(0.7225, abs=0.001)
        assert alert.confidence < sample_detection_result.confidence

        # Evidence includes contradicting ML signal
        signals = {e.signal_name: e for e in alert.evidence}
        assert "ml_classifier_divergence" in signals
        assert signals["ml_classifier_divergence"].direction == "contradicting"

        alert_validator.validate(alert.to_contract_dict())

    def test_case_3_statistical_only(
        self,
        fusion_engine: AlertFusionEngine,
        sample_detection_result: DetectionResult,
        alert_validator: Draft202012Validator,
    ):
        alerts = fusion_engine.fuse(
            detection_results=[sample_detection_result],
            ml_prediction=None,
        )

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.threat_class == sample_detection_result.threat_class
        assert alert.confidence == sample_detection_result.confidence
        assert alert.severity == sample_detection_result.severity
        assert alert.model_version == sample_detection_result.model_version
        assert alert.explanation == sample_detection_result.explanation
        assert len(alert.evidence) == 1

        alert_validator.validate(alert.to_contract_dict())

    def test_case_4_ml_only_conservative_severity(
        self,
        fusion_engine: AlertFusionEngine,
        alert_validator: Draft202012Validator,
    ):
        # High ML score (0.99) with no statistical detections
        ml_pred = MLPrediction(
            flow_id="flow-ml-c2-001",
            threat_class="C2_BEACONING",
            score=0.99,
            model_version="rf-baseline-v1",
            calibrated=False,
        )

        alerts = fusion_engine.fuse(
            detection_results=[],
            ml_prediction=ml_pred,
            flow_context={"src_ip": "192.168.1.42", "dst_ip": "198.51.100.25", "protocol": "TCP"},
        )

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.threat_class == "C2_BEACONING"
        # Confidence must be capped at 0.75 for ML-only hypotheses
        assert alert.confidence <= 0.75
        assert alert.confidence == pytest.approx(0.75, abs=0.01)
        # Severity must be conservative: NEVER CRITICAL from uncalibrated ML alone
        assert alert.severity != "CRITICAL"
        assert alert.severity == "HIGH"
        assert alert.source_ip == "192.168.1.42"
        assert alert.destination_ip == "198.51.100.25"
        assert "hypothesis" in (alert.explanation or "").lower()

        alert_validator.validate(alert.to_contract_dict())

    def test_case_4_ml_benign_produces_no_alerts(
        self,
        fusion_engine: AlertFusionEngine,
    ):
        ml_pred = MLPrediction(
            flow_id="flow-benign-001",
            threat_class="BENIGN",
            score=0.95,
            model_version="rf-baseline-v1",
            calibrated=False,
        )

        alerts = fusion_engine.fuse(
            detection_results=[],
            ml_prediction=ml_pred,
        )
        assert len(alerts) == 0

    def test_case_4_low_score_ml_produces_no_alerts(
        self,
        fusion_engine: AlertFusionEngine,
    ):
        ml_pred = MLPrediction(
            flow_id="flow-low-001",
            threat_class="DDOS",
            score=0.55,  # Below default min_ml_standalone_score of 0.75
            model_version="rf-baseline-v1",
            calibrated=False,
        )

        alerts = fusion_engine.fuse(
            detection_results=[],
            ml_prediction=ml_pred,
        )
        assert len(alerts) == 0
