"""
tests/features/test_extractor.py
================================

Comprehensive unit tests for FeatureExtractor:
  - valid Flow → valid FeatureRecord
  - feature-schema.json validation
  - duration, packet_count, byte_count
  - packets_per_sec, bytes_per_sec, bytes_per_packet
  - zero-duration safety
  - TCP/UDP flags
  - DNS query length, DNS entropy, DNS record type
  - TLS version, SNI, JA3, cipher
  - QUIC metadata
  - Contextual features
  - Malformed input handling
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator

from unithreat.features.extractor import FeatureExtractor, compute_shannon_entropy, extract_features
from unithreat.features.models import FeatureRecord
from unithreat.ingest.models import Flow

ROOT = Path(__file__).resolve().parents[2]
FEATURE_SCHEMA_PATH = ROOT / "contracts" / "feature-schema.json"


@pytest.fixture(scope="module")
def feature_validator() -> Draft202012Validator:
    with FEATURE_SCHEMA_PATH.open(encoding="utf-8") as f:
        schema = json.load(f)
    return Draft202012Validator(schema)


def _base_flow_dict(**overrides) -> dict:
    base = {
        "flow_id": "flow-001",
        "timestamp": "2026-09-06T12:00:00.000000Z",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "direction": "outbound",
        "duration": 2.0,
        "packet_count": 10,
        "byte_count": 1000,
        "tcp_flags": "SYN-ACK",
    }
    base.update(overrides)
    return base


class TestFeatureExtractor:
    def test_valid_flow_to_valid_feature_record(self, feature_validator):
        flow = Flow.model_validate(_base_flow_dict())
        extractor = FeatureExtractor(enable_windowing=False)
        record = extractor.extract(flow)

        assert isinstance(record, FeatureRecord)
        assert record.flow_id == "flow-001"
        assert record.entity_id == "192.168.1.10"
        feature_validator.validate(record.model_dump())

    def test_feature_schema_validation_across_various_flows(self, feature_validator):
        extractor = FeatureExtractor(enable_windowing=False)
        variants = [
            _base_flow_dict(),
            _base_flow_dict(duration=0.0, packet_count=0, byte_count=0, tcp_flags=None),
            _base_flow_dict(
                dns={"query": "test.example.com", "qtype": "A", "rcode": "NOERROR"},
                protocol="UDP",
                dst_port=53,
            ),
            _base_flow_dict(
                tls={"version": "TLS 1.3", "sni": "api.domain.com", "ja3": "abc", "cipher": "0x1301"},
            ),
            _base_flow_dict(
                quic={"version": "1", "sni": "quic.domain.com"},
                protocol="UDP",
                dst_port=443,
            ),
        ]

        for var in variants:
            flow = Flow.model_validate(var)
            record = extractor.extract(flow)
            feature_validator.validate(record.model_dump())

    def test_duration_packet_and_byte_counts(self):
        flow = Flow.model_validate(_base_flow_dict(duration=4.5, packet_count=20, byte_count=5000))
        rec = extract_features(flow)

        assert rec.features["duration"] == 4.5
        assert rec.features["packet_count"] == 20
        assert rec.features["byte_count"] == 5000

    def test_rates_and_ratio_calculations(self):
        flow = Flow.model_validate(_base_flow_dict(duration=2.0, packet_count=10, byte_count=2000))
        rec = extract_features(flow)

        # packets/sec: 10 / 2.0 = 5.0
        assert rec.features["packets_per_sec"] == 5.0
        # bytes/sec: 2000 / 2.0 = 1000.0
        assert rec.features["bytes_per_sec"] == 1000.0
        # bytes/packet: 2000 / 10 = 200.0
        assert rec.features["bytes_per_packet"] == 200.0

    def test_zero_duration_safety(self):
        """Zero duration must not cause ZeroDivisionError and must produce non-negative rates."""
        flow = Flow.model_validate(_base_flow_dict(duration=0.0, packet_count=5, byte_count=250))
        rec = extract_features(flow)

        assert rec.features["duration"] == 0.0
        assert rec.features["packets_per_sec"] > 0
        assert rec.features["bytes_per_sec"] > 0
        assert rec.features["bytes_per_packet"] == 50.0

    def test_tcp_udp_flags(self):
        tcp_flow = Flow.model_validate(_base_flow_dict(tcp_flags="SYN-ACK-PSH", protocol="TCP"))
        rec_tcp = extract_features(tcp_flow)

        assert rec_tcp.features["is_tcp"] is True
        assert rec_tcp.features["is_udp"] is False
        assert rec_tcp.features["is_syn"] is True
        assert rec_tcp.features["is_ack"] is True
        assert rec_tcp.features["is_psh"] is True
        assert rec_tcp.features["is_fin"] is False
        assert rec_tcp.features["is_rst"] is False

        udp_flow = Flow.model_validate(_base_flow_dict(tcp_flags=None, protocol="UDP", dst_port=53))
        rec_udp = extract_features(udp_flow)

        assert rec_udp.features["is_tcp"] is False
        assert rec_udp.features["is_udp"] is True
        assert rec_udp.features["is_syn"] is False

    def test_dns_features(self):
        flow = Flow.model_validate(_base_flow_dict(
            protocol="UDP",
            dst_port=53,
            dns={
                "query": "malicious-data-chunk.tunnel.example.com",
                "qtype": "TXT",
                "rcode": "NOERROR",
            },
        ))
        rec = extract_features(flow)

        assert rec.features["has_dns"] is True
        assert rec.features["dns_query"] == "malicious-data-chunk.tunnel.example.com"
        assert rec.features["dns_query_length"] == len("malicious-data-chunk.tunnel.example.com")
        assert rec.features["dns_qtype"] == "TXT"
        assert rec.features["dns_rcode"] == "NOERROR"
        assert rec.features["dns_entropy"] > 3.0

    def test_shannon_entropy_calculation(self):
        assert compute_shannon_entropy("") == 0.0
        assert compute_shannon_entropy(None) == 0.0
        # "aaaa" has 0 entropy (only 1 distinct symbol)
        assert compute_shannon_entropy("aaaa") == 0.0
        # Random high entropy hex string
        ent = compute_shannon_entropy("7b8f0412ac98b1e42f9a0c71e84321098efba7124310bcda")
        assert ent > 3.5

    def test_tls_features(self):
        flow = Flow.model_validate(_base_flow_dict(
            tls={
                "version": "TLS 1.3",
                "sni": "198.51.100.25",
                "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
                "cipher": "TLS_AES_256_GCM_SHA384",
            },
        ))
        rec = extract_features(flow)

        assert rec.features["has_tls"] is True
        assert rec.features["tls_version"] == "TLS 1.3"
        assert rec.features["tls_sni"] == "198.51.100.25"
        assert rec.features["is_ip_sni"] is True
        assert rec.features["tls_ja3"] == "a0e9f5d64349fb13191bc781f81f42e1"
        assert rec.features["tls_cipher"] == "TLS_AES_256_GCM_SHA384"

    def test_quic_features(self):
        flow = Flow.model_validate(_base_flow_dict(
            quic={
                "version": "1",
                "sni": "quic-server.example.org",
            },
        ))
        rec = extract_features(flow)

        assert rec.features["has_quic"] is True
        assert rec.features["quic_version"] == "1"
        assert rec.features["quic_sni"] == "quic-server.example.org"

    def test_context_merging(self):
        flow = Flow.model_validate(_base_flow_dict())
        rec = extract_features(flow, context={"custom_score": 0.95, "cluster_id": "C-1"})

        assert rec.features["custom_score"] == 0.95
        assert rec.features["cluster_id"] == "C-1"

    def test_direct_dict_input_support(self):
        raw = _base_flow_dict()
        rec = extract_features(raw)
        assert isinstance(rec, FeatureRecord)
        assert rec.flow_id == raw["flow_id"]

    def test_malformed_input_rejection(self):
        extractor = FeatureExtractor()

        with pytest.raises(TypeError):
            extractor.extract("not-a-flow")  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            extractor.extract(None)  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="Cannot extract features from malformed flow dict"):
            extractor.extract({"flow_id": "f1"})  # Missing required fields: timestamp, src_ip, dst_ip, protocol
