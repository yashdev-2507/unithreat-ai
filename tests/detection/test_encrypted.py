"""
tests/detection/test_encrypted.py
=================================

Unit tests for EncryptedSessionDetector.
"""

from __future__ import annotations

import pytest

from unithreat.detection.encrypted import EncryptedSessionDetector
from unithreat.features.models import FeatureRecord


def _make_tls_record(
    version: str = "TLS 1.3",
    sni: str = "api.github.com",
    ja3: str | None = None,
    is_ip_sni: bool = False,
    has_tls: bool = True,
) -> FeatureRecord:
    return FeatureRecord(
        flow_id="tls-001",
        timestamp="2026-09-06T12:00:00Z",
        entity_id="192.168.1.50",
        features={
            "src_ip": "192.168.1.50",
            "dst_ip": "142.250.190.46",
            "dst_port": 443,
            "protocol": "TCP",
            "has_tls": has_tls,
            "tls_version": version,
            "tls_sni": sni,
            "tls_ja3": ja3,
            "is_ip_sni": is_ip_sni,
        },
    )


class TestEncryptedSessionDetector:
    def test_normal_tls_not_detected(self):
        detector = EncryptedSessionDetector()
        rec = _make_tls_record(version="TLS 1.3", sni="fonts.googleapis.com")
        res = detector.detect(rec)
        assert res is None

    def test_obsolete_tls_version_detected(self):
        detector = EncryptedSessionDetector()
        rec = _make_tls_record(version="TLS 1.0", sni="legacy-internal.company.net")
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "ENCRYPTED_ANOMALY"
        assert any(e.signal_name == "obsolete_tls_version" for e in res.evidence)

    def test_direct_ip_sni_detected(self):
        detector = EncryptedSessionDetector()
        rec = _make_tls_record(sni="198.51.100.25", is_ip_sni=True)
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "ENCRYPTED_ANOMALY"
        assert any(e.signal_name == "direct_ip_sni" for e in res.evidence)

    def test_multiple_anomalies_increase_confidence(self):
        detector = EncryptedSessionDetector()
        single_rec = _make_tls_record(sni="198.51.100.25", is_ip_sni=True)
        multi_rec = _make_tls_record(
            version="TLS 1.0",
            sni="198.51.100.25",
            is_ip_sni=True,
            ja3="a0e9f5d64349fb13191bc781f81f42e1",
        )

        res_single = detector.detect(single_rec)
        res_multi = detector.detect(multi_rec)

        assert res_single is not None
        assert res_multi is not None
        assert res_multi.confidence > res_single.confidence
        assert res_multi.severity == "HIGH"

    def test_suspicious_ja3_fingerprint_detected(self):
        detector = EncryptedSessionDetector()
        rec = _make_tls_record(
            version="TLS 1.3",
            sni="c2-endpoint.org",
            ja3="a0e9f5d64349fb13191bc781f81f42e1",
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "ENCRYPTED_ANOMALY"
        assert any(e.signal_name == "suspicious_tls_fingerprint" for e in res.evidence)

    def test_normal_quic_not_detected(self):
        detector = EncryptedSessionDetector()
        rec = FeatureRecord(
            flow_id="quic-benign-001",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.50",
                "dst_ip": "8.8.8.8",
                "dst_port": 443,
                "protocol": "UDP",
                "has_quic": True,
                "quic_version": "v1",
                "quic_sni": "dns.google.com",
                "is_ip_sni": False,
                "bytes_per_packet": 550.0,
                "packet_count": 8,
            },
        )
        res = detector.detect(rec)
        assert res is None

    def test_obsolete_quic_version_detected(self):
        detector = EncryptedSessionDetector()
        rec = FeatureRecord(
            flow_id="quic-legacy-001",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.50",
                "dst_ip": "198.51.100.25",
                "dst_port": 443,
                "protocol": "UDP",
                "has_quic": True,
                "quic_version": "Q035",
                "quic_sni": "legacy-quic.test.net",
                "is_ip_sni": False,
            },
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "ENCRYPTED_ANOMALY"
        assert any(e.signal_name == "obsolete_quic_version" for e in res.evidence)

    def test_insecure_cipher_detected(self):
        detector = EncryptedSessionDetector()
        rec = FeatureRecord(
            flow_id="tls-cipher-001",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.50",
                "dst_ip": "198.51.100.25",
                "dst_port": 443,
                "protocol": "TCP",
                "has_tls": True,
                "tls_version": "TLS 1.2",
                "tls_sni": "legacy-service.net",
                "tls_cipher": "TLS_RSA_WITH_RC4_128_MD5",
            },
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "ENCRYPTED_ANOMALY"
        assert any(e.signal_name == "insecure_cipher_suite" for e in res.evidence)

    def test_anomalous_packet_timing_profile_detected(self):
        detector = EncryptedSessionDetector()
        # Interactive keystroke/reverse-shell tunnel encapsulated in TLS: 40 tiny packets averaging 48 bytes
        rec = FeatureRecord(
            flow_id="tls-keystroke-001",
            timestamp="2026-09-06T12:00:00Z",
            features={
                "src_ip": "192.168.1.50",
                "dst_ip": "198.51.100.25",
                "dst_port": 443,
                "protocol": "TCP",
                "has_tls": True,
                "tls_version": "TLS 1.3",
                "tls_sni": "cdn-stealth.net",
                "packet_count": 40,
                "bytes_per_packet": 48.0,
                "duration": 12.0,
            },
        )
        res = detector.detect(rec)
        assert res is not None
        assert res.threat_class == "ENCRYPTED_ANOMALY"
        assert any(e.signal_name == "anomalous_packet_timing_profile" for e in res.evidence)
