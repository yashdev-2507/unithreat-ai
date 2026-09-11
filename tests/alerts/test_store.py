"""
tests/alerts/test_store.py
==========================

Tests for BoundedAlertStore and BoundedFlowStore:
  - Newest-first retrieval and query filtering
  - Bounded capacity and automatic eviction
  - Flow ID lookup
  - Aggregated stats
  - Thread safety
"""

from __future__ import annotations

import concurrent.futures
import pytest

from unithreat.alerts.store import (
    BoundedAlertStore,
    BoundedFeatureStore,
    BoundedFlowStore,
    BoundedPredictionStore,
)
from unithreat.features.models import FeatureRecord
from unithreat.ml.models import MLPrediction


def _make_alert_dict(flow_id: str, threat_class: str, confidence: float, severity: str) -> dict:
    return {
        "timestamp": "2026-09-08T08:00:00.000000Z",
        "flow_id": flow_id,
        "threat_class": threat_class,
        "confidence": confidence,
        "severity": severity,
        "evidence": [],
    }


class TestBoundedAlertStore:
    def test_add_and_retrieve_newest_first(self):
        store = BoundedAlertStore(max_alerts=10)
        store.add(_make_alert_dict("f1", "DDOS", 0.9, "CRITICAL"))
        store.add(_make_alert_dict("f2", "C2_BEACONING", 0.8, "HIGH"))
        store.add(_make_alert_dict("f3", "RECONNAISSANCE", 0.6, "MEDIUM"))

        alerts = store.get_all()
        assert len(alerts) == 3
        # Newest first
        assert [a["flow_id"] for a in alerts] == ["f3", "f2", "f1"]

    def test_filter_by_threat_class(self):
        store = BoundedAlertStore(max_alerts=10)
        store.add(_make_alert_dict("f1", "DDOS", 0.9, "CRITICAL"))
        store.add(_make_alert_dict("f2", "C2_BEACONING", 0.8, "HIGH"))
        store.add(_make_alert_dict("f3", "DDOS", 0.85, "HIGH"))

        ddos_alerts = store.get_all(threat_class="DDOS")
        assert len(ddos_alerts) == 2
        assert all(a["threat_class"] == "DDOS" for a in ddos_alerts)

    def test_filter_by_severity_and_confidence(self):
        store = BoundedAlertStore(max_alerts=10)
        store.add(_make_alert_dict("f1", "DDOS", 0.95, "CRITICAL"))
        store.add(_make_alert_dict("f2", "C2_BEACONING", 0.78, "HIGH"))
        store.add(_make_alert_dict("f3", "DGA", 0.60, "MEDIUM"))

        high_conf = store.get_all(min_confidence=0.75)
        assert len(high_conf) == 2

        critical_only = store.get_all(severity="CRITICAL")
        assert len(critical_only) == 1
        assert critical_only[0]["flow_id"] == "f1"

    def test_lookup_by_flow_id(self):
        store = BoundedAlertStore(max_alerts=10)
        store.add(_make_alert_dict("flow-abc", "DDOS", 0.9, "HIGH"))
        found = store.get_by_flow_id("flow-abc")
        assert found is not None
        assert found["flow_id"] == "flow-abc"

        not_found = store.get_by_flow_id("nonexistent")
        assert not_found is None

    def test_capacity_eviction(self):
        # Store with max capacity of 3
        store = BoundedAlertStore(max_alerts=3)
        store.add(_make_alert_dict("f1", "DDOS", 0.9, "HIGH"))
        store.add(_make_alert_dict("f2", "DDOS", 0.9, "HIGH"))
        store.add(_make_alert_dict("f3", "DDOS", 0.9, "HIGH"))
        assert store.count() == 3

        # Adding 4th alert should evict f1
        store.add(_make_alert_dict("f4", "DDOS", 0.9, "HIGH"))
        assert store.count() == 3
        flow_ids = [a["flow_id"] for a in store.get_all()]
        assert flow_ids == ["f4", "f3", "f2"]
        assert store.get_by_flow_id("f1") is None

    def test_stats_computation(self):
        store = BoundedAlertStore(max_alerts=10)
        store.add(_make_alert_dict("f1", "DDOS", 0.95, "CRITICAL"))
        store.add(_make_alert_dict("f2", "DDOS", 0.80, "HIGH"))
        store.add(_make_alert_dict("f3", "C2_BEACONING", 0.75, "HIGH"))

        s = store.stats()
        assert s["total_alerts"] == 3
        assert s["by_threat_class"]["DDOS"] == 2
        assert s["by_threat_class"]["C2_BEACONING"] == 1
        assert s["by_severity"]["CRITICAL"] == 1
        assert s["by_severity"]["HIGH"] == 2

    def test_concurrent_access_safety(self):
        store = BoundedAlertStore(max_alerts=100)

        def worker(idx: int):
            for i in range(20):
                store.add(_make_alert_dict(f"w_{idx}_{i}", "DDOS", 0.9, "HIGH"))
                store.get_all(limit=5)
                store.stats()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, idx) for idx in range(8)]
            concurrent.futures.wait(futures)

        assert store.count() == 100


class TestBoundedFlowStore:
    def test_flow_store_capacity_and_lookup(self):
        store = BoundedFlowStore(max_flows=2)
        store.add({"flow_id": "fl-1", "src_ip": "1.1.1.1"})
        store.add({"flow_id": "fl-2", "src_ip": "2.2.2.2"})
        assert store.count() == 2

        assert store.get("fl-1") is not None
        store.add({"flow_id": "fl-3", "src_ip": "3.3.3.3"})
        assert store.count() == 2
        # fl-1 evicted
        assert store.get("fl-1") is None
        assert store.get("fl-3") is not None

    def test_flow_store_get_all_newest_first_and_limit(self):
        store = BoundedFlowStore(max_flows=10)
        store.add({"flow_id": "fl-1", "src_ip": "10.0.0.1", "protocol": "TCP"})
        store.add({"flow_id": "fl-2", "src_ip": "10.0.0.2", "protocol": "UDP"})
        store.add({"flow_id": "fl-3", "src_ip": "10.0.0.3", "protocol": "TCP"})

        flows = store.get_all()
        assert len(flows) == 3
        assert [f["flow_id"] for f in flows] == ["fl-3", "fl-2", "fl-1"]

        limited = store.get_all(limit=2)
        assert len(limited) == 2
        assert [f["flow_id"] for f in limited] == ["fl-3", "fl-2"]

    def test_flow_store_get_all_filtering(self):
        store = BoundedFlowStore(max_flows=10)
        store.add({"flow_id": "f1", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "protocol": "TCP"})
        store.add({"flow_id": "f2", "src_ip": "10.0.0.2", "dst_ip": "192.168.1.1", "protocol": "UDP"})
        store.add({"flow_id": "f3", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.2", "protocol": "tcp"})

        tcp_flows = store.get_all(protocol="TCP")
        assert len(tcp_flows) == 2
        assert {f["flow_id"] for f in tcp_flows} == {"f1", "f3"}

        src_flows = store.get_all(src_ip="10.0.0.1")
        assert len(src_flows) == 2

        dst_flows = store.get_all(dst_ip="192.168.1.2")
        assert len(dst_flows) == 1
        assert dst_flows[0]["flow_id"] == "f3"

    def test_flow_store_get_all_empty_and_clear(self):
        store = BoundedFlowStore(max_flows=10)
        assert store.get_all() == []

        store.add({"flow_id": "f1", "src_ip": "1.1.1.1"})
        assert store.count() == 1
        store.clear()
        assert store.count() == 0
        assert store.get("f1") is None
        assert store.get_all() == []


class TestBoundedFeatureStore:
    def test_feature_store_add_and_get(self):
        store = BoundedFeatureStore(max_features=5)

        # Add using FeatureRecord model
        rec = FeatureRecord(
            flow_id="feat-fl-1",
            timestamp="2026-09-08T12:00:00.000000Z",
            features={"pkt_rate": 100.5, "byte_count": 500},
        )
        stored = store.add(rec)
        assert stored["flow_id"] == "feat-fl-1"
        assert store.count() == 1

        retrieved = store.get("feat-fl-1")
        assert retrieved is not None
        assert retrieved["flow_id"] == "feat-fl-1"
        assert retrieved["features"]["pkt_rate"] == 100.5

        # Nonexistent flow_id returns None
        assert store.get("nonexistent") is None

    def test_feature_store_capacity_eviction(self):
        store = BoundedFeatureStore(max_features=2)
        store.add({"flow_id": "feat-1", "timestamp": "2026-09-08T12:00:00Z", "features": {}})
        store.add({"flow_id": "feat-2", "timestamp": "2026-09-08T12:01:00Z", "features": {}})
        assert store.count() == 2

        # 3rd insert should evict feat-1
        store.add({"flow_id": "feat-3", "timestamp": "2026-09-08T12:02:00Z", "features": {}})
        assert store.count() == 2
        assert store.get("feat-1") is None
        assert store.get("feat-2") is not None
        assert store.get("feat-3") is not None

    def test_feature_store_clear(self):
        store = BoundedFeatureStore(max_features=5)
        store.add({"flow_id": "feat-1", "timestamp": "2026-09-08T12:00:00Z", "features": {}})
        store.clear()
        assert store.count() == 0
        assert store.get("feat-1") is None

    def test_feature_store_concurrent_access(self):
        store = BoundedFeatureStore(max_features=100)

        def worker(idx: int):
            for i in range(20):
                store.add({
                    "flow_id": f"rec_{idx}_{i}",
                    "timestamp": "2026-09-08T12:00:00Z",
                    "features": {"idx": idx, "i": i},
                })
                store.get(f"rec_{idx}_{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, idx) for idx in range(8)]
            concurrent.futures.wait(futures)

        assert store.count() == 100


class TestBoundedPredictionStore:
    def test_prediction_store_add_and_get(self):
        store = BoundedPredictionStore(max_predictions=5)

        # Add using MLPrediction model
        pred = MLPrediction(
            flow_id="pred-fl-1",
            threat_class="DDOS",
            score=0.9234,
            model_version="rf-baseline-v1",
            calibrated=False,
        )
        stored = store.add(pred)
        assert stored["flow_id"] == "pred-fl-1"
        assert stored["threat_class"] == "DDOS"
        assert stored["score"] == 0.9234
        assert stored["calibrated"] is False
        assert "ml_score" not in stored
        assert store.count() == 1

        retrieved = store.get("pred-fl-1")
        assert retrieved is not None
        assert retrieved["flow_id"] == "pred-fl-1"
        assert retrieved["score"] == 0.9234

        # Nonexistent flow_id returns None
        assert store.get("nonexistent") is None

    def test_prediction_store_capacity_eviction(self):
        store = BoundedPredictionStore(max_predictions=2)
        store.add({"flow_id": "pred-1", "threat_class": "DDOS", "score": 0.9, "model_version": "v1"})
        store.add({"flow_id": "pred-2", "threat_class": "C2_BEACONING", "score": 0.8, "model_version": "v1"})
        assert store.count() == 2

        # 3rd insert should evict pred-1
        store.add({"flow_id": "pred-3", "threat_class": "DNS_TUNNELING", "score": 0.7, "model_version": "v1"})
        assert store.count() == 2
        assert store.get("pred-1") is None
        assert store.get("pred-2") is not None
        assert store.get("pred-3") is not None

    def test_prediction_store_clear(self):
        store = BoundedPredictionStore(max_predictions=5)
        store.add({"flow_id": "pred-1", "threat_class": "DDOS", "score": 0.9, "model_version": "v1"})
        store.clear()
        assert store.count() == 0
        assert store.get("pred-1") is None

    def test_prediction_store_concurrent_access(self):
        store = BoundedPredictionStore(max_predictions=100)

        def worker(idx: int):
            for i in range(20):
                store.add({
                    "flow_id": f"pred_{idx}_{i}",
                    "threat_class": "BENIGN",
                    "score": 0.5,
                    "model_version": "v1",
                })
                store.get(f"pred_{idx}_{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, idx) for idx in range(8)]
            concurrent.futures.wait(futures)

        assert store.count() == 100

