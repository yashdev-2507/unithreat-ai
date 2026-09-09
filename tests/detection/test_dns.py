"""
tests/detection/test_dns.py
===========================

Unit tests for DNSDetector.
"""

from __future__ import annotations

import pytest

from unithreat.detection.dns import DNSDetector
from unithreat.features.models import FeatureRecord


def _make_dns_record(
    query: str | None = None,
    query_len: int | None = None,
    entropy: float | None = None,
    qtype: str = "A",
    byte_count: int = 120,
    protocol: str = "UDP",
    dst_port: int = 53,
    has_dns: bool = True,
) -> FeatureRecord:
    return FeatureRecord(
        flow_id="dns-001",
        timestamp="2026-09-06T12:00:00Z",
        entity_id="192.168.1.88",
        features={
            "src_ip": "192.168.1.88",
            "dst_ip": "8.8.8.8",
            "src_port": 54123,
            "dst_port": dst_port,
            "protocol": protocol,
            "byte_count": byte_count,
            "has_dns": has_dns,
            "dns_query": query,
            "dns_query_length": query_len,
            "dns_entropy": entropy,
            "dns_qtype": qtype,
        },
    )


class TestDNSDetector:
    def test_normal_dns_not_detected(self):
        detector = DNSDetector()
        # Normal query to google.com
        rec = _make_dns_record(
            query="google.com",
            query_len=10,
            entropy=2.65,
            qtype="A",
            byte_count=85,
        )
        res = detector.detect(rec)
        assert res is None

    def test_dns_tunneling_detected(self):
        detector = DNSDetector()
        # Covert tunneling query with base32 encoded data
        rec = _make_dns_record(
            query="7b8f0412ac98b1e42f9a0c71e84321098efba7124310bcda.tunnel.data-drop.org",
            query_len=71,
            entropy=4.25,
            qtype="TXT",
            byte_count=850,
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "DNS_TUNNELING"
        assert res.confidence >= 0.75
        assert any(e.signal_name == "abnormal_query_length" for e in res.evidence)
        assert any(e.signal_name == "high_dns_entropy" for e in res.evidence)
        assert any(e.signal_name == "suspicious_dns_record_type" for e in res.evidence)

    def test_non_dns_traffic_ignored(self):
        detector = DNSDetector()
        rec = FeatureRecord(
            flow_id="tcp-web",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "protocol": "TCP",
                "dst_port": 443,
                "has_dns": False,
            },
        )
        res = detector.detect(rec)
        assert res is None

    def test_missing_query_features_handled_cleanly(self):
        detector = DNSDetector()
        # DNS flow without parsed query string
        rec = _make_dns_record(
            query=None,
            query_len=None,
            entropy=None,
            qtype=None,
        )
        res = detector.detect(rec)
        assert res is None

    def test_dga_domain_detected(self):
        detector = DNSDetector()
        # High-entropy algorithmic domain with zero vowels and long consonant cluster
        rec = _make_dns_record(
            query="xkqjvnmwptlzk.com",
            query_len=17,
            entropy=3.70,
            qtype="A",
            byte_count=78,
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "DGA"
        assert res.confidence >= 0.70
        ev_names = {e.signal_name for e in res.evidence}
        assert "dga_lexical_anomaly" in ev_names
        assert "high_dns_entropy" in ev_names
        assert "consonant_cluster_anomaly" in ev_names
        assert "abnormal_vowel_distribution" in ev_names

    def test_normal_long_domain_not_detected_as_dga(self):
        detector = DNSDetector()
        # Legitimate long English hyphenated domain
        rec = _make_dns_record(
            query="internal-telemetry-service-prod-us-east.company-corp.com",
            query_len=56,
            entropy=3.65,
            qtype="A",
            byte_count=120,
        )
        res = detector.detect(rec)
        # Should NOT be classified as DGA or tunneling
        assert res is None
