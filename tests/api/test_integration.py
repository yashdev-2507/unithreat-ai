"""
tests/api/test_integration.py
=============================

End-to-end integration test exercising the complete UniThreat AI architecture:
Synthetic Traffic Generation -> Ingest -> Feature Extraction -> Statistical Detection
-> Machine Learning Inference -> Alert Fusion -> Deduplication -> Alert Storage -> REST API & WebSocket Stream.
"""

from __future__ import annotations

import json
from pathlib import Path
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import pytest

from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.api.app import create_app
from unithreat.api.stream import AlertStreamManager
from unithreat.detection.engine import DetectionEngine
from unithreat.generator import generate_flows
from unithreat.ml.dataset import generate_labelled_dataset
from unithreat.ml.inference import MLInferenceEngine
from unithreat.ml.train import train_model

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


@pytest.fixture(scope="module")
def full_pipeline(tmp_path_factory) -> IntegratedPipeline:
    # Train a real baseline ML model on a small synthetic dataset
    model_dir = tmp_path_factory.mktemp("full_integration_model")
    ds = generate_labelled_dataset(runs_per_scenario=2, flows_per_run=12, seed_base=42)
    train_model(dataset=ds, model_dir=model_dir, seed=42, n_estimators=20, max_depth=8)

    ml_engine = MLInferenceEngine(model_dir=model_dir)
    stream_mgr = AlertStreamManager()
    detection_engine = DetectionEngine()

    return IntegratedPipeline(
        detection_engine=detection_engine,
        ml_engine=ml_engine,
        stream_manager=stream_mgr,
        enable_windowing=True,
    )


class TestFullPipelineIntegration:
    def test_end_to_end_flow_to_api_and_stream(
        self,
        full_pipeline: IntegratedPipeline,
        alert_validator: Draft202012Validator,
    ):
        app = create_app(pipeline=full_pipeline, stream_manager=full_pipeline.stream_manager)
        client = TestClient(app)

        # 1. Connect WebSocket client
        with client.websocket_connect("/ws/alerts") as ws:
            # 2. Feed a high-confidence DDoS volumetric flood
            ddos_flows = list(generate_flows(scenario="ddos", count=60, seed=123))

            alerts_generated = []
            for flow in ddos_flows:
                created = full_pipeline.process_flow(flow)
                alerts_generated.extend(created)

            assert len(alerts_generated) >= 1
            first_alert = alerts_generated[0]

            # 3. Verify WebSocket received alert broadcast
            data = ws.receive_text()
            streamed_alert = json.loads(data)
            assert streamed_alert["flow_id"] == first_alert["flow_id"]
            assert streamed_alert["threat_class"] == "DDOS"

            # 4. Verify alert is queryable through REST API
            res = client.get(f"/alerts/{first_alert['flow_id']}")
            assert res.status_code == 200
            api_alert = res.json()
            assert api_alert["flow_id"] == first_alert["flow_id"]
            assert api_alert["threat_class"] == "DDOS"

            # 5. Verify contract compliance of all alerts
            alert_validator.validate(api_alert)
            alert_validator.validate(streamed_alert)

            # 6. Verify stats endpoint reflects detection
            stats_res = client.get("/stats")
            assert stats_res.status_code == 200
            stats_data = stats_res.json()
            assert stats_data["total_flows_processed"] >= 60
            assert stats_data["total_alerts_stored"] >= 1
            assert "DDOS" in stats_data["by_threat_class"]
