"""
tests/api/test_routes.py
========================

Tests for FastAPI REST API endpoints:
  - GET  /health
  - GET  /alerts
  - GET  /alerts/{flow_id}
  - GET  /flows/{flow_id}
  - GET  /stats
  - POST /ingest/flow
"""

from __future__ import annotations

import json
from pathlib import Path
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import pytest

from unithreat.alerts.models import ThreatAlert
from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.api.app import create_app
from unithreat.detection.result import EvidenceSignal
from unithreat.features.models import FeatureRecord
from unithreat.generator import generate_flows
from unithreat.ml.models import MLPrediction

ROOT = Path(__file__).resolve().parents[2]
ALERT_SCHEMA_PATH = ROOT / "contracts" / "alert-schema.json"
EVIDENCE_SCHEMA_PATH = ROOT / "contracts" / "evidence-schema.json"
FLOW_SCHEMA_PATH = ROOT / "contracts" / "flow-schema.json"
FEATURE_SCHEMA_PATH = ROOT / "contracts" / "feature-schema.json"
PREDICTION_SCHEMA_PATH = ROOT / "contracts" / "ml-prediction-schema.json"


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
def flow_validator() -> Draft202012Validator:
    with FLOW_SCHEMA_PATH.open(encoding="utf-8") as f:
        schema = json.load(f)
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def feature_validator() -> Draft202012Validator:
    with FEATURE_SCHEMA_PATH.open(encoding="utf-8") as f:
        schema = json.load(f)
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def prediction_validator() -> Draft202012Validator:
    with PREDICTION_SCHEMA_PATH.open(encoding="utf-8") as f:
        schema = json.load(f)
    return Draft202012Validator(schema)


@pytest.fixture
def client() -> TestClient:
    pipeline = IntegratedPipeline()
    app = create_app(pipeline=pipeline)
    return TestClient(app)


class TestAPIRoutes:
    def test_health_endpoint(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "ml_active" in data
        assert "total_flows_processed" in data
        assert "total_alerts_stored" in data

    def test_alerts_query_and_contract_validation(
        self,
        client: TestClient,
        alert_validator: Draft202012Validator,
    ):
        pipeline: IntegratedPipeline = client.app.state.pipeline  # type: ignore[attr-defined]

        # Seed the store with sample alerts
        ev = EvidenceSignal(
            signal_name="test_sig",
            value=1.0,
            direction="supporting",
            reliability=0.9,
            supporting_features=["feat"],
        )
        a1 = ThreatAlert(
            timestamp="2026-09-08T08:00:00.000000Z",
            flow_id="alert-001",
            threat_class="DDOS",
            confidence=0.92,
            severity="CRITICAL",
            evidence=[ev],
            source_ip="192.168.1.100",
            destination_ip="10.0.0.50",
        )
        a2 = ThreatAlert(
            timestamp="2026-09-08T08:01:00.000000Z",
            flow_id="alert-002",
            threat_class="C2_BEACONING",
            confidence=0.78,
            severity="HIGH",
            evidence=[ev],
            source_ip="192.168.1.42",
            destination_ip="198.51.100.25",
        )
        pipeline.alert_store.add(a1)
        pipeline.alert_store.add(a2)

        # GET /alerts
        res = client.get("/alerts")
        assert res.status_code == 200
        alerts = res.json()
        assert len(alerts) == 2
        # Newest first
        assert alerts[0]["flow_id"] == "alert-002"

        # Validate strictly against contracts/alert-schema.json
        for alert_dict in alerts:
            alert_validator.validate(alert_dict)

    def test_alerts_filtering(self, client: TestClient):
        pipeline: IntegratedPipeline = client.app.state.pipeline  # type: ignore[attr-defined]
        ev = EvidenceSignal(
            signal_name="s",
            value=1.0,
            direction="supporting",
            reliability=0.9,
            supporting_features=["f"],
        )
        pipeline.alert_store.add(
            ThreatAlert(
                timestamp="2026-09-08T08:00:00.000000Z",
                flow_id="f-ddos",
                threat_class="DDOS",
                confidence=0.95,
                severity="CRITICAL",
                evidence=[ev],
            )
        )
        pipeline.alert_store.add(
            ThreatAlert(
                timestamp="2026-09-08T08:01:00.000000Z",
                flow_id="f-c2",
                threat_class="C2_BEACONING",
                confidence=0.72,
                severity="MEDIUM",
                evidence=[ev],
            )
        )

        # Filter by class
        res = client.get("/alerts?threat_class=DDOS")
        assert res.status_code == 200
        assert len(res.json()) == 1
        assert res.json()[0]["flow_id"] == "f-ddos"

        # Filter by severity
        res = client.get("/alerts?severity=CRITICAL")
        assert res.status_code == 200
        assert len(res.json()) == 1

        # Filter by min_confidence
        res = client.get("/alerts?min_confidence=0.80")
        assert res.status_code == 200
        assert len(res.json()) == 1

    def test_alert_lookup_by_flow_id(self, client: TestClient):
        pipeline: IntegratedPipeline = client.app.state.pipeline  # type: ignore[attr-defined]
        ev = EvidenceSignal(
            signal_name="s",
            value=1.0,
            direction="supporting",
            reliability=0.9,
            supporting_features=["f"],
        )
        pipeline.alert_store.add(
            ThreatAlert(
                timestamp="2026-09-08T08:00:00.000000Z",
                flow_id="target-alert-123",
                threat_class="DNS_TUNNELING",
                confidence=0.88,
                severity="HIGH",
                evidence=[ev],
            )
        )

        res = client.get("/alerts/target-alert-123")
        assert res.status_code == 200
        assert res.json()["flow_id"] == "target-alert-123"

        res_404 = client.get("/alerts/nonexistent-id")
        assert res_404.status_code == 404

    def test_flow_lookup_by_id(self, client: TestClient):
        pipeline: IntegratedPipeline = client.app.state.pipeline  # type: ignore[attr-defined]
        pipeline.flow_store.add({"flow_id": "flow-xyz", "protocol": "TCP", "src_ip": "1.2.3.4"})

        res = client.get("/flows/flow-xyz")
        assert res.status_code == 200
        assert res.json()["flow_id"] == "flow-xyz"

        res_404 = client.get("/flows/unknown-flow")
        assert res_404.status_code == 404

    def test_stats_endpoint(self, client: TestClient):
        res = client.get("/stats")
        assert res.status_code == 200
        data = res.json()
        assert "total_flows_processed" in data
        assert "total_alerts_stored" in data
        assert "by_threat_class" in data
        assert "by_severity" in data

    def test_post_ingest_flow(self, client: TestClient):
        flow = next(generate_flows(scenario="benign", count=1, seed=42))
        res = client.post("/ingest/flow", json=flow)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "accepted"
        assert data["flow_id"] == flow["flow_id"]
        assert "alerts_generated" in data

    def test_get_flows_empty(self, client: TestClient):
        res = client.get("/flows")
        assert res.status_code == 200
        assert res.json() == []

    def test_get_flows_query_and_contract_validation(
        self, client: TestClient, flow_validator: Draft202012Validator
    ):
        flows = list(generate_flows(scenario="benign", count=3, seed=42))
        for f in flows:
            client.post("/ingest/flow", json=f)

        res = client.get("/flows")
        assert res.status_code == 200
        retrieved_flows = res.json()
        assert len(retrieved_flows) == 3

        # Newest first
        assert retrieved_flows[0]["flow_id"] == flows[2]["flow_id"]
        assert retrieved_flows[1]["flow_id"] == flows[1]["flow_id"]
        assert retrieved_flows[2]["flow_id"] == flows[0]["flow_id"]

        # Validate strictly against contracts/flow-schema.json
        for flow_item in retrieved_flows:
            flow_validator.validate(flow_item)

    def test_get_flows_filtering_and_pagination(self, client: TestClient):
        flows = list(generate_flows(scenario="benign", count=5, seed=99))
        for f in flows:
            client.post("/ingest/flow", json=f)

        # Test limit
        res_limit = client.get("/flows?limit=2")
        assert res_limit.status_code == 200
        assert len(res_limit.json()) == 2

        # Test protocol filter
        sample_proto = flows[0]["protocol"]
        res_proto = client.get(f"/flows?protocol={sample_proto}")
        assert res_proto.status_code == 200
        assert all(f["protocol"].upper() == sample_proto.upper() for f in res_proto.json())

        # Test src_ip filter
        sample_src = flows[0]["src_ip"]
        res_src = client.get(f"/flows?src_ip={sample_src}")
        assert res_src.status_code == 200
        assert all(f["src_ip"] == sample_src for f in res_src.json())

        # Test dst_ip filter
        sample_dst = flows[0]["dst_ip"]
        res_dst = client.get(f"/flows?dst_ip={sample_dst}")
        assert res_dst.status_code == 200
        assert all(f["dst_ip"] == sample_dst for f in res_dst.json())

    def test_get_features_by_flow_id_and_contract_validation(
        self, client: TestClient, feature_validator: Draft202012Validator
    ):
        flow = next(generate_flows(scenario="benign", count=1, seed=123))
        client.post("/ingest/flow", json=flow)

        res = client.get(f"/features/{flow['flow_id']}")
        assert res.status_code == 200
        feat_data = res.json()
        assert feat_data["flow_id"] == flow["flow_id"]
        assert "timestamp" in feat_data
        assert "features" in feat_data
        assert isinstance(feat_data["features"], dict)

        # Validate strictly against contracts/feature-schema.json
        feature_validator.validate(feat_data)

    def test_get_features_not_found(self, client: TestClient):
        res = client.get("/features/nonexistent-feature-flow")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()

    def test_get_predictions_by_flow_id_and_contract_validation(
        self, client: TestClient, prediction_validator: Draft202012Validator
    ):
        pipeline: IntegratedPipeline = client.app.state.pipeline  # type: ignore[attr-defined]
        pred = MLPrediction(
            flow_id="pred-flow-999",
            threat_class="C2_BEACONING",
            score=0.8765,
            model_version="rf-baseline-v1",
            calibrated=False,
        )
        pipeline.prediction_store.add(pred)

        res = client.get("/predictions/pred-flow-999")
        assert res.status_code == 200
        pred_data = res.json()
        assert pred_data["flow_id"] == "pred-flow-999"
        assert pred_data["threat_class"] == "C2_BEACONING"
        assert pred_data["score"] == 0.8765
        assert pred_data["model_version"] == "rf-baseline-v1"
        assert pred_data["calibrated"] is False
        assert "ml_score" not in pred_data

        # Validate strictly against contracts/ml-prediction-schema.json
        prediction_validator.validate(pred_data)

    def test_get_predictions_not_found(self, client: TestClient):
        res = client.get("/predictions/nonexistent-pred-flow")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()

    def test_flow_ingest_populates_feature_and_flow_stores(self, client: TestClient):
        flow = next(generate_flows(scenario="benign", count=1, seed=777))
        res_post = client.post("/ingest/flow", json=flow)
        assert res_post.status_code == 200

        # Flow store populated
        res_flow = client.get(f"/flows/{flow['flow_id']}")
        assert res_flow.status_code == 200
        assert res_flow.json()["flow_id"] == flow["flow_id"]

        # Feature store populated
        res_feat = client.get(f"/features/{flow['flow_id']}")
        assert res_feat.status_code == 200
        assert res_feat.json()["flow_id"] == flow["flow_id"]

