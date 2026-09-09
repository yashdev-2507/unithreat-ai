"""
tests/detection/test_engine.py
==============================

Tests for DetectionEngine orchestration, error handling, contract compliance,
and window state management.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from unithreat.detection.base import BaseDetector
from unithreat.detection.config import DetectionConfig
from unithreat.detection.engine import DetectionEngine
from unithreat.detection.result import DetectionResult
from unithreat.features.models import FeatureRecord
from unithreat.ingest.models import Flow

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = ROOT / "contracts"


@pytest.fixture(scope="module")
def alert_schemas() -> tuple[Draft202012Validator, Draft202012Validator]:
    with (CONTRACTS_DIR / "evidence-schema.json").open(encoding="utf-8") as f:
        ev_schema = json.load(f)
    with (CONTRACTS_DIR / "alert-schema.json").open(encoding="utf-8") as f:
        alert_schema = json.load(f)

    registry = Registry().with_resources([
        ("evidence-schema.json", Resource.from_contents(ev_schema)),
    ])
    ev_val = Draft202012Validator(ev_schema)
    alert_val = Draft202012Validator(alert_schema, registry=registry)
    return ev_val, alert_val


class _CrashingDetector(BaseDetector):
    """Detector that deliberately raises an unhandled error to test engine resilience."""

    @property
    def threat_class(self) -> str:
        return "CRASHING"

    def detect(self, record: FeatureRecord, window_manager=None):
        raise RuntimeError("Intentional detector failure")


class TestDetectionEngine:
    def test_default_engine_initializes_all_detectors(self):
        engine = DetectionEngine()
        assert len(engine.detectors) == 6
        classes = {d.threat_class for d in engine.detectors}
        assert classes == {
            "DDOS",
            "RECONNAISSANCE",
            "C2_BEACONING",
            "DNS_TUNNELING",
            "DATA_EXFILTRATION",
            "ENCRYPTED_ANOMALY",
        }

    def test_detector_independence_on_failure(self):
        """A crashing detector must not prevent other detectors from executing."""
        engine = DetectionEngine()
        engine.register_detector(_CrashingDetector())

        # An exfiltration flow that should be detected by ExfiltrationDetector
        rec = FeatureRecord(
            flow_id="exfil-safe",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.77",
                "dst_ip": "203.0.113.88",
                "direction": "outbound",
                "byte_count": 3_000_000,
                "duration": 20.0,
                "bytes_per_sec": 150_000.0,
            },
        )

        results = engine.process(rec)
        assert len(results) >= 1
        assert any(r.threat_class == "DATA_EXFILTRATION" for r in results)

    def test_detection_results_strictly_conform_to_alert_contract(self, alert_schemas):
        ev_val, alert_val = alert_schemas
        engine = DetectionEngine()

        # Generate an exfiltration flow
        rec = FeatureRecord(
            flow_id="contract-test-001",
            timestamp="2026-09-06T12:00:00.000000Z",
            features={
                "src_ip": "192.168.1.77",
                "dst_ip": "203.0.113.88",
                "protocol": "TCP",
                "direction": "outbound",
                "byte_count": 5_000_000,
                "duration": 30.0,
                "bytes_per_sec": 166_666.0,
            },
        )

        results = engine.process(rec)
        assert len(results) >= 1
        result = results[0]

        # 1. Validate evidence signals against evidence-schema.json
        for ev in result.evidence:
            ev_val.validate(ev.to_contract_dict())

        # 2. Validate final alert dict against alert-schema.json
        alert_dict = result.to_alert_dict()
        alert_val.validate(alert_dict)

    def test_malformed_and_missing_features_no_unhandled_crash(self):
        engine = DetectionEngine()

        malformed_records = [
            FeatureRecord(flow_id="m1", timestamp="2026-09-06T12:00:00Z", features={}),
            FeatureRecord(
                flow_id="m2",
                timestamp="2026-09-06T12:00:00Z",
                features={"duration": -1.0, "byte_count": None, "src_ip": None},
            ),
        ]

        for r in malformed_records:
            res = engine.process(r)
            assert isinstance(res, list)

    def test_process_flow_convenience(self):
        engine = DetectionEngine()
        flow = Flow.model_validate({
            "flow_id": "flow-dns",
            "timestamp": "2026-09-06T12:00:00Z",
            "src_ip": "192.168.1.88",
            "dst_ip": "8.8.8.8",
            "protocol": "UDP",
            "dst_port": 53,
            "direction": "outbound",
            "byte_count": 950,
            "dns": {
                "query": "49bf8c201a4e7021cb834f9a0c71e84321098efba7124310bcda.tunnel.covert.org",
                "qtype": "TXT",
            },
        })

        results = engine.process_flow(flow)
        assert len(results) == 1
        assert results[0].threat_class == "DNS_TUNNELING"

    def test_deterministic_output(self):
        rec = FeatureRecord(
            flow_id="det-001",
            timestamp="2026-09-06T12:00:00.000000Z",
            features={
                "src_ip": "192.168.1.77",
                "dst_ip": "203.0.113.88",
                "direction": "outbound",
                "byte_count": 2_500_000,
                "duration": 15.0,
                "bytes_per_sec": 166_666.0,
            },
        )

        engine1 = DetectionEngine()
        engine2 = DetectionEngine()

        res1 = engine1.process(rec)
        res2 = engine2.process(rec)

        assert len(res1) == len(res2)
        assert res1[0].threat_class == res2[0].threat_class
        assert res1[0].confidence == res2[0].confidence

    def test_process_stream_with_flows_and_records(self):
        engine = DetectionEngine()
        flow = Flow.model_validate({
            "flow_id": "flow-dns-stream",
            "timestamp": "2026-09-06T12:00:00Z",
            "src_ip": "192.168.1.88",
            "dst_ip": "8.8.8.8",
            "protocol": "UDP",
            "dst_port": 53,
            "direction": "outbound",
            "byte_count": 950,
            "dns": {
                "query": "49bf8c201a4e7021cb834f9a0c71e84321098efba7124310bcda.tunnel.covert.org",
                "qtype": "TXT",
            },
        })
        rec = FeatureRecord(
            flow_id="exfil-stream",
            timestamp="2026-09-06T12:00:00.000000Z",
            features={
                "src_ip": "192.168.1.77",
                "dst_ip": "203.0.113.88",
                "direction": "outbound",
                "byte_count": 2_500_000,
                "duration": 15.0,
                "bytes_per_sec": 166_666.0,
            },
        )
        stream = [flow, rec]
        results = list(engine.process_stream(stream))
        assert len(results) == 2
        threats = {r.threat_class for r in results}
        assert threats == {"DNS_TUNNELING", "DATA_EXFILTRATION"}
