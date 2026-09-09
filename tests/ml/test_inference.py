"""
tests/ml/test_inference.py
==========================

Tests for ML inference, contract adherence, error handling, and explainability.
"""

from __future__ import annotations

import json
from pathlib import Path
from jsonschema import Draft202012Validator
import pytest

from unithreat.features.models import FeatureRecord
from unithreat.ml.dataset import ALL_CLASSES, generate_labelled_dataset
from unithreat.ml.inference import MLInferenceEngine
from unithreat.ml.models import MLPrediction
from unithreat.ml.train import train_model

ROOT = Path(__file__).resolve().parents[2]
ML_SCHEMA_PATH = ROOT / "contracts" / "ml-prediction-schema.json"


@pytest.fixture(scope="module")
def ml_validator() -> Draft202012Validator:
    with ML_SCHEMA_PATH.open(encoding="utf-8") as f:
        schema = json.load(f)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def trained_engine(tmp_path_factory) -> MLInferenceEngine:
    model_dir = tmp_path_factory.mktemp("ml_engine_dir")
    dataset = generate_labelled_dataset(runs_per_scenario=3, flows_per_run=12, seed_base=777)
    train_model(dataset=dataset, model_dir=model_dir, seed=42, n_estimators=20, max_depth=8)
    return MLInferenceEngine(model_dir=model_dir)


class TestInference:
    def test_prediction_strictly_conforms_to_contract(
        self,
        trained_engine: MLInferenceEngine,
        ml_validator: Draft202012Validator,
    ):
        record = FeatureRecord(
            flow_id="flow-test-ddos-001",
            timestamp="2026-09-06T12:00:00.000000Z",
            entity_id="192.168.1.100",
            features={
                "packets_per_sec": 5000.0,
                "bytes_per_sec": 300000.0,
                "is_syn": True,
                "is_tcp": True,
                "duration": 0.001,
                "dst_fan_in": 50,
            },
        )

        pred = trained_engine.predict(record)
        assert isinstance(pred, MLPrediction)
        assert pred.flow_id == "flow-test-ddos-001"
        assert pred.threat_class in ALL_CLASSES
        assert 0.0 <= pred.score <= 1.0
        assert pred.calibrated is False

        # Validate against contracts/ml-prediction-schema.json
        contract_dict = pred.to_contract_dict()
        ml_validator.validate(contract_dict)

    def test_missing_optional_features_handled_safely(
        self,
        trained_engine: MLInferenceEngine,
        ml_validator: Draft202012Validator,
    ):
        # Record with nearly empty features
        record = FeatureRecord(
            flow_id="minimal-flow-001",
            timestamp="2026-09-06T12:00:00.000000Z",
            features={},
        )
        pred = trained_engine.predict(record)
        assert isinstance(pred, MLPrediction)
        assert pred.flow_id == "minimal-flow-001"
        ml_validator.validate(pred.to_contract_dict())

    def test_dict_input_supported(
        self,
        trained_engine: MLInferenceEngine,
        ml_validator: Draft202012Validator,
    ):
        raw_dict = {
            "flow_id": "dict-flow-001",
            "features": {
                "byte_count": 5000000,
                "duration": 25.0,
                "outbound_inbound_byte_ratio": 500.0,
            },
        }
        pred = trained_engine.predict(raw_dict)
        assert pred.flow_id == "dict-flow-001"
        ml_validator.validate(pred.to_contract_dict())

    def test_invalid_input_rejected_cleanly(self, trained_engine: MLInferenceEngine):
        with pytest.raises(ValueError, match="Input feature record cannot be None"):
            trained_engine.predict(None)  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="must contain a non-empty 'flow_id'"):
            trained_engine.predict({"features": {}})

        with pytest.raises(TypeError, match="Expected FeatureRecord or dict"):
            trained_engine.predict(12345)  # type: ignore[arg-type]

    def test_explainability_predict_detailed(self, trained_engine: MLInferenceEngine):
        record = FeatureRecord(
            flow_id="explain-flow-001",
            timestamp="2026-09-06T12:00:00.000000Z",
            features={
                "dns_entropy": 4.2,
                "dns_ngram_score": 0.05,
                "dns_vowel_ratio": 0.10,
                "has_dns": True,
            },
        )
        details = trained_engine.predict_detailed(record, top_k_features=3)
        assert "prediction" in details
        assert "top_features" in details
        assert len(details["top_features"]) == 3
        for item in details["top_features"]:
            assert "feature_name" in item
            assert "importance" in item
            assert "observed_value" in item
