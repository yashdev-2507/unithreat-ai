"""
unithreat.detection.encrypted
=============================

Encrypted session anomaly detection using passive metadata only.

STRICTLY CONSTRAINED:
  - NEVER decrypts payload or attempts payload inspection.
  - NEVER probes or connects to endpoints.
  - Flags 'encrypted-session anomaly', strictly distinguishing behavioral
    metadata signals from confirmed malware infection.
"""

from __future__ import annotations

from typing import Any

from unithreat.detection.base import BaseDetector
from unithreat.detection.config import EncryptedConfig
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


class EncryptedSessionDetector(BaseDetector):
    """
    Detects anomalous encrypted session characteristics using TLS/QUIC metadata.
    """

    def __init__(self, config: EncryptedConfig | None = None) -> None:
        self.config = config or EncryptedConfig()

    @property
    def threat_class(self) -> str:
        return "ENCRYPTED_ANOMALY"

    def detect(
        self,
        record: FeatureRecord,
        window_manager: BoundedWindowManager | None = None,
    ) -> DetectionResult | None:
        feat = record.features

        has_tls = bool(feat.get("has_tls"))
        has_quic = bool(feat.get("has_quic"))
        dst_port = feat.get("dst_port")
        protocol = str(feat.get("protocol") or "").upper()

        if not (has_tls or has_quic or dst_port in (443, 8443)):
            return None

        tls_ver = feat.get("tls_version")
        tls_sni = feat.get("tls_sni")
        tls_ja3 = feat.get("tls_ja3")
        tls_cipher = feat.get("tls_cipher")
        quic_ver = feat.get("quic_version")
        quic_sni = feat.get("quic_sni")
        is_ip_sni = bool(feat.get("is_ip_sni"))

        packet_count = int(feat.get("packet_count") or 0)
        bytes_per_packet = float(feat.get("bytes_per_packet") or 0.0)
        duration = float(feat.get("duration") or 0.0)

        evidence: list[EvidenceSignal] = []

        # 1. Check for obsolete / insecure TLS protocol versions
        if tls_ver and str(tls_ver) in self.config.obsolete_tls_versions:
            evidence.append(
                EvidenceSignal(
                    signal_name="obsolete_tls_version",
                    value=1.0,
                    direction="supporting",
                    reliability=0.95,
                    supporting_features=["tls_version"],
                    threat_class="ENCRYPTED_ANOMALY",
                )
            )

        # 2. Check for obsolete / deprecated QUIC versions
        if quic_ver and str(quic_ver) in self.config.obsolete_quic_versions:
            evidence.append(
                EvidenceSignal(
                    signal_name="obsolete_quic_version",
                    value=1.0,
                    direction="supporting",
                    reliability=0.92,
                    supporting_features=["quic_version"],
                    threat_class="ENCRYPTED_ANOMALY",
                )
            )

        # 3. Check for suspicious direct IP address in SNI (TLS or QUIC)
        if self.config.flag_direct_ip_sni and is_ip_sni:
            evidence.append(
                EvidenceSignal(
                    signal_name="direct_ip_sni",
                    value=1.0,
                    direction="supporting",
                    reliability=0.85,
                    supporting_features=["tls_sni", "quic_sni", "is_ip_sni"],
                    threat_class="ENCRYPTED_ANOMALY",
                )
            )

        # 4. Check for known suspicious JA3 client fingerprints
        if tls_ja3 and str(tls_ja3) in self.config.suspicious_ja3_hashes:
            evidence.append(
                EvidenceSignal(
                    signal_name="suspicious_tls_fingerprint",
                    value=1.0,
                    direction="supporting",
                    reliability=0.90,
                    supporting_features=["tls_ja3"],
                    threat_class="ENCRYPTED_ANOMALY",
                )
            )

        # 5. Check for insecure or weak cipher suites
        if tls_cipher:
            cipher_upper = str(tls_cipher).upper()
            if any(w in cipher_upper for w in self.config.insecure_ciphers):
                evidence.append(
                    EvidenceSignal(
                        signal_name="insecure_cipher_suite",
                        value=1.0,
                        direction="supporting",
                        reliability=0.92,
                        supporting_features=["tls_cipher"],
                        threat_class="ENCRYPTED_ANOMALY",
                    )
                )

        # 6. Check for anomalous packet-size/timing metadata in encrypted session
        # e.g. low-byte interactive keystroke / reverse shell beaconing
        if (
            packet_count >= self.config.min_keystroke_packets
            and 0 < bytes_per_packet <= self.config.max_keystroke_bpp
        ):
            evidence.append(
                EvidenceSignal(
                    signal_name="anomalous_packet_timing_profile",
                    value=round(bytes_per_packet, 2),
                    direction="supporting",
                    reliability=0.82,
                    supporting_features=["bytes_per_packet", "packet_count", "duration"],
                    threat_class="ENCRYPTED_ANOMALY",
                )
            )

        # If no metadata anomalies observed, benign encrypted session
        if not evidence:
            return None

        # Multi-signal confidence calculation
        confidence = 0.65
        if len(evidence) >= 3:
            confidence += 0.25
        elif len(evidence) == 2:
            confidence += 0.20
        elif len(evidence) == 1 and evidence[0].signal_name == "obsolete_tls_version":
            confidence += 0.15

        confidence = min(round(confidence, 2), 0.98)
        if confidence < self.config.confidence_threshold:
            return None

        severity = "HIGH" if len(evidence) >= 2 else "MEDIUM"

        explanation = (
            f"Encrypted session metadata anomaly observed for {feat.get('src_ip')} -> {feat.get('dst_ip')}: "
            f"{', '.join(e.signal_name for e in evidence)}. "
            f"(Passive metadata analysis only; no payload decryption.)"
        )

        return DetectionResult(
            timestamp=record.timestamp,
            flow_id=record.flow_id,
            threat_class="ENCRYPTED_ANOMALY",
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            detection_method="statistical",
            relevant_features={
                "tls_version": tls_ver,
                "tls_sni": tls_sni,
                "tls_ja3": tls_ja3,
                "tls_cipher": tls_cipher,
                "quic_version": quic_ver,
                "quic_sni": quic_sni,
                "is_ip_sni": is_ip_sni,
                "bytes_per_packet": bytes_per_packet,
                "packet_count": packet_count,
            },
            source_ip=str(feat.get("src_ip")),
            destination_ip=str(feat.get("dst_ip")),
            protocol=str(feat.get("protocol")),
            explanation=explanation,
        )
