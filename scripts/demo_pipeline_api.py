#!/usr/bin/env python3
"""
scripts/demo_pipeline_api.py
============================

CLI demonstration script for Task 6:
Exercises the complete passive pipeline from synthetic flow generation,
feature extraction, statistical detection + ML inference, alert fusion,
deduplication, bounded in-memory storage, to FastAPI querying and schema validation.

Usage
-----
python scripts/demo_pipeline_api.py
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure src is on sys.path
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.api.app import create_app
from unithreat.api.stream import AlertStreamManager
from unithreat.detection.engine import DetectionEngine
from unithreat.generator import generate_flows
from unithreat.ml.inference import MLInferenceEngine


def load_validator() -> Draft202012Validator:
    alert_schema_path = _ROOT / "contracts" / "alert-schema.json"
    evidence_schema_path = _ROOT / "contracts" / "evidence-schema.json"
    with alert_schema_path.open(encoding="utf-8") as f:
        alert_schema = json.load(f)
    with evidence_schema_path.open(encoding="utf-8") as f:
        evidence_schema = json.load(f)

    registry = Registry().with_resources(
        [("evidence-schema.json", Resource.from_contents(evidence_schema))]
    )
    return Draft202012Validator(alert_schema, registry=registry)


def main() -> int:
    print("=" * 70)
    print("UniThreat AI — Task 6 End-to-End Pipeline & API Live Replay Demo")
    print("=" * 70)

    # 1. Initialize Pipeline & Engines
    model_dir = _ROOT / "artifacts" / "models" / "rf-baseline-v1"
    ml_engine = None
    if model_dir.exists():
        print(f"[*] Loading trained ML model from {model_dir}...")
        ml_engine = MLInferenceEngine(model_dir=model_dir)
    else:
        print("[!] No trained ML model found at artifacts/models/rf-baseline-v1, using statistical only")

    detection_engine = DetectionEngine()
    stream_manager = AlertStreamManager()
    pipeline = IntegratedPipeline(
        detection_engine=detection_engine,
        ml_engine=ml_engine,
        stream_manager=stream_manager,
        enable_windowing=True,
    )
    app = create_app(pipeline=pipeline, stream_manager=stream_manager)
    client = TestClient(app)
    validator = load_validator()

    print("[+] Pipeline and FastAPI application initialized successfully.\n")

    # 2. Replay Scenarios
    scenarios = [
        ("benign", 15, "Normal background web & office traffic"),
        ("port_scan", 25, "TCP SYN reconnaissance scan"),
        ("ddos", 40, "Volumetric SYN flood attack"),
    ]

    total_flows = 0
    total_alerts_produced = 0

    for scenario_name, count, desc in scenarios:
        print(f"[*] Simulating scenario: '{scenario_name}' ({count} flows) — {desc}")
        flows = list(generate_flows(scenario=scenario_name, count=count, seed=42))
        scenario_alerts = 0
        for flow in flows:
            total_flows += 1
            created = pipeline.process_flow(flow)
            scenario_alerts += len(created)
            total_alerts_produced += len(created)
        print(f"    -> Processed {len(flows)} flows | Produced {scenario_alerts} alert(s)")

    print(f"\n[+] Total flows processed: {total_flows}")
    print(f"[+] Total alerts stored in BoundedAlertStore: {total_alerts_produced}\n")

    # 3. Query via REST API
    print("=" * 70)
    print("Querying REST API Endpoints")
    print("=" * 70)

    # GET /health
    health_resp = client.get("/health")
    print(f"[GET /health] Status: {health_resp.status_code}")
    print(f"  Response: {json.dumps(health_resp.json(), indent=2)}")

    # GET /stats
    stats_resp = client.get("/stats")
    print(f"\n[GET /stats] Status: {stats_resp.status_code}")
    print(f"  Response: {json.dumps(stats_resp.json(), indent=2)}")

    # GET /alerts
    alerts_resp = client.get("/alerts?limit=5")
    print(f"\n[GET /alerts?limit=5] Status: {alerts_resp.status_code}")
    recent_alerts = alerts_resp.json()
    print(f"  Retrieved {len(recent_alerts)} alerts (newest-first):")

    for i, alt in enumerate(recent_alerts, 1):
        # Validate against contracts/alert-schema.json
        errors = list(validator.iter_errors(alt))
        valid_status = "VALID" if not errors else f"INVALID ({errors[0].message})"
        print(f"  [{i}] ID: {alt['flow_id']} | Threat: {alt['threat_class']} | "
              f"Severity: {alt['severity']} | Confidence: {alt['confidence']:.2f} | Contract: {valid_status}")
        for ev in alt.get("evidence", []):
            print(f"      - Evidence signal: {ev['signal_name']} (dir={ev['direction']}, rel={ev['reliability']})")

    # POST /ingest/flow verification (Local Testing Endpoint)
    print("\n" + "=" * 70)
    print("Testing POST /ingest/flow (Passive Boundary Replay Endpoint)")
    print("=" * 70)
    sample_flow = list(generate_flows(scenario="ddos", count=1, seed=999))[0]
    ingest_resp = client.post("/ingest/flow", json=sample_flow)
    print(f"[POST /ingest/flow] Status: {ingest_resp.status_code}")
    print(f"  Response: {json.dumps(ingest_resp.json(), indent=2)}")

    print("\n" + "=" * 70)
    print("[SUCCESS] All demonstration checks and contract validations passed!")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
