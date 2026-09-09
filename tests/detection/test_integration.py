"""
tests/detection/test_integration.py
===================================

End-to-end integration tests:
  Synthetic traffic generation
    ↓
  JSONL file storage
    ↓
  Replay ingest (passive streaming)
    ↓
  Feature extraction
    ↓
  Detection engine
    ↓
  Detection result & Alert contract validation
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from unithreat.detection.engine import DetectionEngine
from unithreat.detection.result import DetectionResult
from unithreat.features.extractor import extract_features
from unithreat.generator.traffic import generate_flows, write_flows_jsonl
from unithreat.ingest.adapters.jsonl import replay_jsonl
from unithreat.ingest.models import Flow
from unithreat.ingest.parser import parse_flow

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = ROOT / "contracts"


@pytest.fixture(scope="module")
def alert_validator() -> Draft202012Validator:
    with (CONTRACTS_DIR / "evidence-schema.json").open(encoding="utf-8") as f:
        ev_schema = json.load(f)
    with (CONTRACTS_DIR / "alert-schema.json").open(encoding="utf-8") as f:
        alert_schema = json.load(f)

    registry = Registry().with_resources([
        ("evidence-schema.json", Resource.from_contents(ev_schema)),
    ])
    return Draft202012Validator(alert_schema, registry=registry)


class TestEndToEndPipeline:
    def test_benign_traffic_emits_no_threat_alerts(self):
        """Benign background scenario should not trigger threat alerts."""
        engine = DetectionEngine()
        raw_flows = list(generate_flows(scenario="benign", count=30, seed=42))

        detected_threats: list[DetectionResult] = []
        for raw in raw_flows:
            flow = parse_flow(raw)
            features = extract_features(flow)
            results = engine.process(features)
            detected_threats.extend(results)

        assert len(detected_threats) == 0

    def test_ddos_scenario_detection_pipeline(self, alert_validator):
        """Generated DDoS flood scenario triggers DDOS detection results."""
        engine = DetectionEngine()
        raw_flows = list(generate_flows(scenario="ddos", count=40, seed=42))

        ddos_alerts: list[DetectionResult] = []
        for raw in raw_flows:
            flow = parse_flow(raw)
            features = extract_features(flow)
            results = engine.process(features)
            for res in results:
                if res.threat_class == "DDOS":
                    ddos_alerts.append(res)
                    alert_validator.validate(res.to_alert_dict())

        assert len(ddos_alerts) >= 1
        assert ddos_alerts[-1].confidence >= 0.70
        assert ddos_alerts[-1].destination_ip == "10.0.0.50"

    def test_port_scan_scenario_detection_pipeline(self, alert_validator):
        """Generated port scan scenario triggers RECONNAISSANCE detection."""
        engine = DetectionEngine()
        raw_flows = list(generate_flows(scenario="port_scan", count=35, seed=42))

        scan_alerts: list[DetectionResult] = []
        for raw in raw_flows:
            flow = parse_flow(raw)
            features = extract_features(flow)
            results = engine.process(features)
            for res in results:
                if res.threat_class == "RECONNAISSANCE":
                    scan_alerts.append(res)
                    alert_validator.validate(res.to_alert_dict())

        assert len(scan_alerts) >= 1
        assert scan_alerts[-1].source_ip == "192.168.1.105"

    def test_c2_beacon_scenario_detection_pipeline(self, alert_validator):
        """Generated C2 beacon scenario triggers C2_BEACONING detection."""
        engine = DetectionEngine()
        raw_flows = list(generate_flows(scenario="c2_beacon", count=12, seed=42))

        beacon_alerts: list[DetectionResult] = []
        for raw in raw_flows:
            flow = parse_flow(raw)
            features = extract_features(flow)
            results = engine.process(features)
            for res in results:
                if res.threat_class == "C2_BEACONING":
                    beacon_alerts.append(res)
                    alert_validator.validate(res.to_alert_dict())

        assert len(beacon_alerts) >= 1
        assert beacon_alerts[-1].confidence >= 0.80

    def test_dns_tunnel_scenario_detection_pipeline(self, alert_validator):
        """Generated DNS tunnel scenario triggers DNS_TUNNELING detection."""
        engine = DetectionEngine()
        raw_flows = list(generate_flows(scenario="dns_tunnel", count=20, seed=42))

        dns_alerts: list[DetectionResult] = []
        for raw in raw_flows:
            flow = parse_flow(raw)
            features = extract_features(flow)
            results = engine.process(features)
            for res in results:
                if res.threat_class == "DNS_TUNNELING":
                    dns_alerts.append(res)
                    alert_validator.validate(res.to_alert_dict())

        assert len(dns_alerts) >= 1
        assert dns_alerts[0].confidence >= 0.70

    def test_exfiltration_scenario_detection_pipeline(self, alert_validator):
        """Generated exfiltration scenario triggers DATA_EXFILTRATION detection."""
        engine = DetectionEngine()
        raw_flows = list(generate_flows(scenario="exfiltration", count=15, seed=42))

        exfil_alerts: list[DetectionResult] = []
        for raw in raw_flows:
            flow = parse_flow(raw)
            features = extract_features(flow)
            results = engine.process(features)
            for res in results:
                if res.threat_class == "DATA_EXFILTRATION":
                    exfil_alerts.append(res)
                    alert_validator.validate(res.to_alert_dict())

        assert len(exfil_alerts) >= 1
        assert exfil_alerts[0].confidence >= 0.75

    def test_encrypted_session_anomaly_pipeline(self, alert_validator):
        """Encrypted flows with anomalous TLS metadata trigger ENCRYPTED_ANOMALY detection."""
        engine = DetectionEngine()
        raw_flow = {
            "flow_id": "tls-anom-001",
            "timestamp": "2026-09-06T12:00:00Z",
            "src_ip": "192.168.1.55",
            "dst_ip": "198.51.100.25",
            "src_port": 49152,
            "dst_port": 443,
            "protocol": "TCP",
            "direction": "outbound",
            "duration": 0.5,
            "packet_count": 12,
            "byte_count": 1500,
            "tls": {
                "version": "SSL 3.0",
                "sni": "198.51.100.25",
            },
        }

        flow = parse_flow(raw_flow)
        features = extract_features(flow)
        results = engine.process(features)

        assert len(results) >= 1
        anom = [r for r in results if r.threat_class == "ENCRYPTED_ANOMALY"][0]
        assert anom.confidence >= 0.80
        alert_validator.validate(anom.to_alert_dict())

    def test_full_jsonl_file_streaming_pipeline(self, tmp_path: Path, alert_validator):
        """
        Validate complete pipeline from file on disk:
        Generator → JSONL file → replay_jsonl → Flow → extract_features → DetectionEngine → Alert
        """
        jsonl_path = tmp_path / "ddos_stream.jsonl"
        flows_gen = generate_flows(scenario="ddos", count=25, seed=42)
        write_flows_jsonl(flows_gen, output_path=jsonl_path)

        engine = DetectionEngine()
        detected_alerts: list[DetectionResult] = []

        # Read JSONL file incrementally through passive replay adapter
        for flow in replay_jsonl(jsonl_path, speed_factor=0.0):
            features = extract_features(flow)
            for alert in engine.process(features):
                detected_alerts.append(alert)
                alert_validator.validate(alert.to_alert_dict())

        assert len(detected_alerts) >= 1
        assert any(a.threat_class == "DDOS" for a in detected_alerts)
