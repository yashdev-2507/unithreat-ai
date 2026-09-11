#!/usr/bin/env python3
"""
scripts/verify_realtime_demo.py
===============================

Verification of real-time passive detection pipeline:
  Traffic Generator (/tmp/unithreat_realtime_ddos.jsonl)
          ↓
  POST http://127.0.0.1:8000/ingest/flow (One-by-one with delay)
          ↓
  Real FastAPI Backend
          ↓
  Feature Extraction + Detection / ML
          ↓
  Alert Fusion + Deduplication
          ↓
  WebSocket /ws/alerts
          ↓
  Client Reception (Simultaneous Realtime Verification)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from typing import Any

import httpx
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import websockets

_ROOT = Path(__file__).resolve().parents[1]
_CONTRACTS = _ROOT / "contracts"


def load_validators():
    with (_CONTRACTS / "alert-schema.json").open(encoding="utf-8") as f:
        alert_schema = json.load(f)
    with (_CONTRACTS / "evidence-schema.json").open(encoding="utf-8") as f:
        evidence_schema = json.load(f)
    with (_CONTRACTS / "flow-schema.json").open(encoding="utf-8") as f:
        flow_schema = json.load(f)
    with (_CONTRACTS / "feature-schema.json").open(encoding="utf-8") as f:
        feature_schema = json.load(f)
    with (_CONTRACTS / "ml-prediction-schema.json").open(encoding="utf-8") as f:
        ml_schema = json.load(f)

    registry = Registry().with_resources([
        ("evidence-schema.json", Resource.from_contents(evidence_schema)),
        ("flow-schema.json", Resource.from_contents(flow_schema)),
        ("feature-schema.json", Resource.from_contents(feature_schema)),
        ("ml-prediction-schema.json", Resource.from_contents(ml_schema)),
    ])

    return {
        "alert": Draft202012Validator(alert_schema, registry=registry),
        "flow": Draft202012Validator(flow_schema, registry=registry),
        "feature": Draft202012Validator(feature_schema, registry=registry),
        "ml": Draft202012Validator(ml_schema, registry=registry),
    }


async def main():
    print("=" * 70)
    print("UniThreat AI — Real-Time Detection Pipeline Verification")
    print("=" * 70)

    validators = load_validators()
    dataset_path = Path("/tmp/unithreat_realtime_ddos.jsonl")
    if not dataset_path.exists():
        print(f"ERROR: Dataset {dataset_path} does not exist!")
        sys.exit(1)

    with dataset_path.open("r", encoding="utf-8") as f:
        flows = [json.loads(line) for line in f if line.strip()]

    print(f"[*] Loaded {len(flows)} flows from {dataset_path}")

    base_url = "http://127.0.0.1:8000"
    ws_url = "ws://127.0.0.1:8000/ws/alerts"
    frontend_api_url = "http://localhost:5173/api"

    async with httpx.AsyncClient() as client:
        # Step 1: Health check
        print("\n--- 1. Backend Health Check ---")
        health_res = await client.get(f"{base_url}/health")
        assert health_res.status_code == 200, f"Health status: {health_res.status_code}"
        health_data = health_res.json()
        print(f"Health OK: {health_data}")
        initial_flows = health_data["total_flows_processed"]
        initial_alerts = health_data["total_alerts_stored"]

        # Step 2: Check Frontend Vite Proxy Health
        print("\n--- 2. Frontend Proxy Check (http://localhost:5173/api/health) ---")
        fe_health_res = await client.get(f"{frontend_api_url}/health")
        assert fe_health_res.status_code == 200, f"Frontend proxy status: {fe_health_res.status_code}"
        print(f"Frontend Proxy Health OK: {fe_health_res.json()['status']}")

        # Step 3: Connect WebSocket Listener
        print(f"\n--- 3. Connecting to WebSocket Stream ({ws_url}) ---")
        received_ws_alerts = []
        ws_connected_evt = asyncio.Event()

        async def listen_ws():
            async with websockets.connect(ws_url) as ws:
                print("  [WebSocket] Connected successfully to /ws/alerts")
                ws_connected_evt.set()
                try:
                    while True:
                        msg = await ws.recv()
                        data = json.loads(msg)
                        recv_time = time.time()
                        received_ws_alerts.append((data, recv_time))
                        print(f"  ⚡ [WebSocket Event Received]: flow_id={data.get('flow_id')} threat={data.get('threat_class')} conf={data.get('confidence')} sev={data.get('severity')}")
                except asyncio.CancelledError:
                    pass

        ws_task = asyncio.create_task(listen_ws())
        await ws_connected_evt.wait()

        # Step 4: Replay Flows One at a Time with Delay
        print(f"\n--- 4. Ingesting {len(flows)} Flows (One-by-One with 150ms streaming delay) ---")
        ingest_results = []
        start_ingest_time = time.time()

        for idx, flow in enumerate(flows, 1):
            flow_send_time = time.time()
            res = await client.post(f"{base_url}/ingest/flow", json=flow)
            assert res.status_code == 200, f"Ingest failed for flow {flow['flow_id']}: {res.status_code}"
            result = res.json()
            ingest_results.append((flow, result, flow_send_time))

            alerts_gen = result.get("alerts_generated", 0)
            status_symbol = "🚨 ALERT GENERATED" if alerts_gen > 0 else "✓ flow accepted"
            print(f"  [{idx:02d}/{len(flows)}] Flow {flow['flow_id']} -> {status_symbol} ({alerts_gen} alert(s))")

            # Observable streaming delay
            await asyncio.sleep(0.15)

        total_ingest_duration = time.time() - start_ingest_time
        print(f"[*] Ingestion completed in {total_ingest_duration:.2f}s")

        # Allow brief time for last websocket messages to be flushed
        await asyncio.sleep(0.5)
        ws_task.cancel()
        try:
            await ws_task
        except asyncio.CancelledError:
            pass

        # Step 5: Verification of WebSocket alerts received
        print(f"\n--- 5. WebSocket Verification Summary ---")
        print(f"Total alerts received over WebSocket: {len(received_ws_alerts)}")
        assert len(received_ws_alerts) > 0, "No alerts received over WebSocket!"

        print("\nValidating Alert Contracts against contracts/alert-schema.json:")
        for idx, (alert_data, recv_t) in enumerate(received_ws_alerts, 1):
            validators["alert"].validate(alert_data)
            # Check non-empty evidence
            assert len(alert_data["evidence"]) > 0, "Alert evidence must not be empty"
            assert "timestamp" in alert_data
            assert "flow_id" in alert_data
            assert "threat_class" in alert_data
            assert "confidence" in alert_data
            assert "severity" in alert_data
            print(f"  Alert {idx}: {alert_data['flow_id']} | {alert_data['threat_class']} | {alert_data['severity']} | Conf: {alert_data['confidence']} | Evidence items: {len(alert_data['evidence'])} -> VALID")

        # Step 6: Backend Post-Ingest State Verification
        print("\n--- 6. Backend REST API Verification ---")
        post_health = (await client.get(f"{base_url}/health")).json()
        print(f"Total flows processed: {post_health['total_flows_processed']} (was {initial_flows})")
        print(f"Total alerts stored: {post_health['total_alerts_stored']} (was {initial_alerts})")
        assert post_health["total_flows_processed"] >= initial_flows + len(flows)

        stats = (await client.get(f"{base_url}/stats")).json()
        print(f"Stats: {stats}")
        assert "DDOS" in stats["by_threat_class"]

        alerts_list = (await client.get(f"{base_url}/alerts?limit=50")).json()
        print(f"Recent alerts in store: {len(alerts_list)}")
        assert len(alerts_list) >= len(received_ws_alerts)

        # Flow store lookup
        sample_flow_id = flows[0]["flow_id"]
        flow_get = await client.get(f"{base_url}/flows/{sample_flow_id}")
        assert flow_get.status_code == 200, f"Flow get failed: {flow_get.status_code}"
        validators["flow"].validate(flow_get.json())
        print(f"Flow lookup for {sample_flow_id}: OK, Schema VALID")

        # Feature store lookup
        sample_alert_flow_id = received_ws_alerts[0][0]["flow_id"]
        feat_get = await client.get(f"{base_url}/features/{sample_alert_flow_id}")
        assert feat_get.status_code == 200, f"Feature get failed: {feat_get.status_code}"
        validators["feature"].validate(feat_get.json())
        print(f"Feature lookup for {sample_alert_flow_id}: OK, Schema VALID (features count: {len(feat_get.json()['features'])})")

        # Prediction store lookup
        pred_get = await client.get(f"{base_url}/predictions/{sample_alert_flow_id}")
        if pred_get.status_code == 200:
            validators["ml"].validate(pred_get.json())
            print(f"Prediction lookup for {sample_alert_flow_id}: OK, Schema VALID (score: {pred_get.json()['score']}, class: {pred_get.json()['threat_class']})")
        else:
            print(f"Prediction lookup returned: {pred_get.status_code}")

        # Step 7: Frontend Proxy Endpoints Verification
        print("\n--- 7. Frontend Proxy Verification (http://localhost:5173/api) ---")
        fe_stats = (await client.get(f"{frontend_api_url}/stats")).json()
        assert fe_stats["total_flows_processed"] == stats["total_flows_processed"]
        fe_alerts = (await client.get(f"{frontend_api_url}/alerts?limit=10")).json()
        assert len(fe_alerts) > 0
        print(f"Frontend Proxy delivered {len(fe_alerts)} alerts and identical stats matching backend.")

    print("\n" + "=" * 70)
    print("REAL-TIME DEMO VERIFICATION: ALL CHECKS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
