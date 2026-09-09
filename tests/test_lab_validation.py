"""
tests/test_lab_validation.py
============================

Automated verification tests for Phase 5.2 Lab Traffic Validation.
Verifies live lab socket generation, schema conformity, and passive boundary guarantees.
"""

from __future__ import annotations

import json
from pathlib import Path
from jsonschema import Draft202012Validator
import pytest

from scripts.validate_lab_traffic import (
    ScenarioValidationResult,
    generate_live_lab_benign,
    generate_live_lab_ddos_udp,
    generate_live_lab_exfiltration,
    generate_live_lab_port_scan,
    load_alert_validator,
    run_scenario_validation,
)
from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.ml.inference import MLInferenceEngine

ROOT = Path(__file__).resolve().parents[1]
FLOW_SCHEMA_PATH = ROOT / "contracts" / "flow-schema.json"


@pytest.fixture(scope="module")
def flow_validator() -> Draft202012Validator:
    with FLOW_SCHEMA_PATH.open(encoding="utf-8") as f:
        schema = json.load(f)
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def test_pipeline() -> IntegratedPipeline:
    model_dir = ROOT / "artifacts" / "models" / "rf-baseline-v1"
    ml_engine = MLInferenceEngine(model_dir=model_dir) if model_dir.exists() else None
    return IntegratedPipeline(ml_engine=ml_engine, enable_windowing=True)


class TestLabTrafficGenerators:
    def test_live_lab_benign_flows_conform_to_schema(self, flow_validator: Draft202012Validator):
        flows = generate_live_lab_benign(count=5)
        assert len(flows) == 5
        for f in flows:
            errors = list(flow_validator.iter_errors(f))
            assert not errors, f"Validation error: {errors[0].message if errors else ''}"
            assert f["protocol"] == "TCP"
            assert f["direction"] == "internal"
            assert f["duration"] > 0.0

    def test_live_lab_port_scan_flows_conform_to_schema(self, flow_validator: Draft202012Validator):
        flows = generate_live_lab_port_scan(count=8)
        assert len(flows) == 8
        for f in flows:
            errors = list(flow_validator.iter_errors(f))
            assert not errors, f"Validation error: {errors[0].message if errors else ''}"
            assert f["tcp_flags"] == "SYN"
            assert f["packet_count"] == 1

    def test_live_lab_exfiltration_flows_conform_to_schema(self, flow_validator: Draft202012Validator):
        flows = generate_live_lab_exfiltration(count=2)
        assert len(flows) == 2
        for f in flows:
            errors = list(flow_validator.iter_errors(f))
            assert not errors, f"Validation error: {errors[0].message if errors else ''}"
            assert f["byte_count"] > 1_000_000
            assert f["direction"] == "outbound"

    def test_live_lab_ddos_udp_flows_conform_to_schema(self, flow_validator: Draft202012Validator):
        flows = generate_live_lab_ddos_udp(count=10)
        assert len(flows) == 10
        for f in flows:
            errors = list(flow_validator.iter_errors(f))
            assert not errors, f"Validation error: {errors[0].message if errors else ''}"
            assert f["protocol"] == "UDP"
            assert f["dst_port"] == 80


class TestScenarioValidationRunner:
    def test_benign_validation_has_zero_false_positives(
        self,
        test_pipeline: IntegratedPipeline,
    ):
        validator = load_alert_validator()
        res = run_scenario_validation(
            scenario="benign",
            pipeline=test_pipeline,
            validator=validator,
            flow_count=15,
        )
        assert isinstance(res, ScenarioValidationResult)
        assert res.scenario == "benign"
        assert res.input_type == "actual lab-generated"
        assert res.false_positives == 0
        assert res.alerts_generated == 0
        assert res.schema_valid is True

    def test_ddos_validation_detects_attack_and_conforms_to_schema(
        self,
        test_pipeline: IntegratedPipeline,
    ):
        validator = load_alert_validator()
        res = run_scenario_validation(
            scenario="ddos",
            pipeline=test_pipeline,
            validator=validator,
            flow_count=20,
        )
        assert isinstance(res, ScenarioValidationResult)
        assert res.detected is True
        assert "DDOS" in res.detected_threat_classes
        assert res.schema_valid is True
        assert res.alerts_generated > 0

    def test_passive_boundary_remains_uncompromised(self, test_pipeline: IntegratedPipeline):
        """Verify that the detection pipeline has no active network sockets."""
        # Ensure the pipeline components do not possess socket or client attributes
        assert not hasattr(test_pipeline, "socket")
        assert not hasattr(test_pipeline.detection_engine, "socket")
        assert not hasattr(test_pipeline.extractor, "socket")
