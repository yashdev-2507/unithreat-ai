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
from unithreat.generator import generate_flows

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
