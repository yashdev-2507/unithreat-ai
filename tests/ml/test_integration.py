"""
tests/ml/test_integration.py
============================

End-to-end integration tests for ML pipeline:
Scenario generation -> Ingest validation -> Feature extraction -> ML inference -> Schema compliance.
"""

from __future__ import annotations

import json
from pathlib import Path
from jsonschema import Draft202012Validator
import pytest

from unithreat.features.extractor import FeatureExtractor
from unithreat.generator import VALID_SCENARIOS, generate_flows
from unithreat.ingest.parser import parse_flow
from unithreat.ml.dataset import ALL_CLASSES, SCENARIO_LABEL_MAP, generate_labelled_dataset
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
def shared_ml_engine(tmp_path_factory) -> MLInferenceEngine:
    model_dir = tmp_path_factory.mktemp("shared_ml_dir")
    dataset = generate_labelled_dataset(runs_per_scenario=3, flows_per_run=15, seed_base=555)
    train_model(dataset=dataset, model_dir=model_dir, seed=42, n_estimators=25, max_depth=10)
    return MLInferenceEngine(model_dir=model_dir)


class TestMLEndToEndIntegration:
    @pytest.mark.parametrize("scenario", VALID_SCENARIOS)
    def test_full_pipeline_from_generator_to_ml_prediction(
        self,
        scenario: str,
        shared_ml_engine: MLInferenceEngine,
        ml_validator: Draft202012Validator,
    ):
        # 1. Generate realistic flows for scenario
        raw_flows = list(generate_flows(scenario=scenario, count=10, seed=888))
        assert len(raw_flows) == 10

        extractor = FeatureExtractor(enable_windowing=True)

        for raw_flow in raw_flows:
            # 2. Ingest validation
            parsed_flow = parse_flow(raw_flow)
            assert parsed_flow.flow_id == raw_flow["flow_id"]

            # 3. Feature extraction
            record = extractor.extract(parsed_flow)
            assert record.flow_id == parsed_flow.flow_id

            # 4. ML inference on FeatureRecord
            prediction = shared_ml_engine.predict(record)
            assert isinstance(prediction, MLPrediction)
            assert prediction.flow_id == record.flow_id
            assert prediction.threat_class in ALL_CLASSES
            assert 0.0 <= prediction.score <= 1.0
            assert prediction.calibrated is False

            # 5. Schema compliance check
            ml_validator.validate(prediction.to_contract_dict())

    def test_inference_latency_is_lightweight(self, shared_ml_engine: MLInferenceEngine):
        import time

        extractor = FeatureExtractor(enable_windowing=True)
        flows = list(generate_flows(scenario="benign", count=100, seed=123))
        records = [extractor.extract(f) for f in flows]

        # Warm up
        shared_ml_engine.predict(records[0])

        start = time.perf_counter()
        for r in records:
            shared_ml_engine.predict(r)
        elapsed = time.perf_counter() - start

        avg_latency_ms = (elapsed / len(records)) * 1000.0
        # Average latency should be well under 5ms per flow on typical machines
        assert avg_latency_ms < 10.0
