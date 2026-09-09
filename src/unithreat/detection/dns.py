"""
unithreat.detection.dns
======================

DGA and DNS tunneling detection based on query length, lexical entropy, and record types.
"""

from __future__ import annotations

from typing import Any

from unithreat.detection.base import BaseDetector
from unithreat.detection.config import DNSConfig
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.extractor import compute_dns_lexical_metrics, compute_shannon_entropy
from unithreat.features.models import FeatureRecord


class DNSDetector(BaseDetector):
    """
    Detects covert DNS tunneling and DGA domain queries using observable metadata.
    """

    def __init__(self, config: DNSConfig | None = None) -> None:
        self.config = config or DNSConfig()

    @property
    def threat_class(self) -> str:
        return "DNS_TUNNELING"

    def detect(
        self,
        record: FeatureRecord,
        window_manager: BoundedWindowManager | None = None,
    ) -> DetectionResult | None:
        feat = record.features

        is_dns_flow = (
            bool(feat.get("has_dns"))
            or feat.get("dst_port") == 53
            or feat.get("protocol") in ("UDP", "DNS")
        )
        if not is_dns_flow:
            return None

        query = feat.get("dns_query")
        if not query or not isinstance(query, str):
            return None

        query_len = int(feat.get("dns_query_length") or len(query))
        raw_entropy = feat.get("dns_entropy")
        entropy = float(raw_entropy) if raw_entropy is not None else compute_shannon_entropy(query)
        qtype = str(feat.get("dns_qtype") or "").upper()
        byte_count = int(feat.get("byte_count") or 0)

        # Lexical metrics for DGA analysis
        vowel_ratio = feat.get("dns_vowel_ratio")
        consonant_run = feat.get("dns_max_consonant_run")
        ngram_score = feat.get("dns_ngram_score")
        digit_ratio = feat.get("dns_digit_ratio")

        if vowel_ratio is None or consonant_run is None or ngram_score is None or digit_ratio is None:
            lex = compute_dns_lexical_metrics(query)
            vowel_ratio = lex["dns_vowel_ratio"]
            consonant_run = lex["dns_max_consonant_run"]
            ngram_score = lex["dns_ngram_score"]
            digit_ratio = lex["dns_digit_ratio"]

        v_ratio = float(vowel_ratio) if vowel_ratio is not None else 0.5
        c_run = int(consonant_run) if consonant_run is not None else 0
        ng_score = float(ngram_score) if ngram_score is not None else 0.5
        d_ratio = float(digit_ratio) if digit_ratio is not None else 0.0

        # -----------------------------------------------------------------
        # Protection check: normal legitimate dictionary/hyphenated domains
        # (e.g. internal-telemetry-service-prod-us-east.company-corp.com)
        # must not be classified as DNS tunneling or DGA.
        # -----------------------------------------------------------------
        is_natural_domain = (v_ratio >= 0.25 and c_run <= 3 and ng_score >= 0.35 and d_ratio < 0.20)
        if is_natural_domain:
            return None

        # -----------------------------------------------------------------
        # 1. Evaluate DNS Tunneling (covert data transport channel)
        # Characteristics: very long queries, high entropy, TXT/NULL record
        # types, and large query/response byte sizes.
        # -----------------------------------------------------------------
        is_long_query = query_len >= self.config.min_query_length
        is_high_entropy = entropy >= self.config.min_entropy
        is_suspicious_qtype = qtype in self.config.suspicious_record_types
        is_large_dns_payload = byte_count >= 400

        is_tunneling = (
            (is_long_query and is_high_entropy)
            or (is_large_dns_payload and is_high_entropy)
            or (is_long_query and is_suspicious_qtype)
        )

        if is_tunneling:
            confidence = 0.65
            if is_long_query:
                confidence += min(0.15, (query_len - self.config.min_query_length) * 0.005)
            if entropy >= 4.0:
                confidence += 0.10
            if is_suspicious_qtype:
                confidence += 0.10

            confidence = min(round(confidence, 2), 0.98)
            if confidence < self.config.confidence_threshold:
                return None

            severity = "HIGH" if (query_len >= 60 and entropy >= 4.0) else "MEDIUM"

            evidence: list[EvidenceSignal] = [
                EvidenceSignal(
                    signal_name="abnormal_query_length",
                    value=float(query_len),
                    direction="supporting",
                    reliability=0.91,
                    supporting_features=["dns_query_length"],
                    threat_class="DNS_TUNNELING",
                ),
                EvidenceSignal(
                    signal_name="high_dns_entropy",
                    value=round(entropy, 3),
                    direction="supporting",
                    reliability=0.89,
                    supporting_features=["dns_entropy"],
                    threat_class="DNS_TUNNELING",
                ),
            ]

            if is_suspicious_qtype:
                evidence.append(
                    EvidenceSignal(
                        signal_name="suspicious_dns_record_type",
                        value=1.0,
                        direction="supporting",
                        reliability=0.85,
                        supporting_features=["dns_qtype"],
                        threat_class="DNS_TUNNELING",
                    )
                )

            if is_large_dns_payload:
                evidence.append(
                    EvidenceSignal(
                        signal_name="large_dns_payload",
                        value=float(byte_count),
                        direction="supporting",
                        reliability=0.87,
                        supporting_features=["byte_count"],
                        threat_class="DNS_TUNNELING",
                    )
                )

            explanation = (
                f"Covert DNS tunneling transport detected: query length {query_len} chars with Shannon entropy "
                f"{entropy:.3f} bits/char (record type={qtype or 'UNKNOWN'}, payload={byte_count} B)."
            )

            return DetectionResult(
                timestamp=record.timestamp,
                flow_id=record.flow_id,
                threat_class="DNS_TUNNELING",
                confidence=confidence,
                severity=severity,
                evidence=evidence,
                detection_method="statistical",
                relevant_features={
                    "dns_query_length": query_len,
                    "dns_entropy": entropy,
                    "dns_qtype": qtype or None,
                    "byte_count": byte_count,
                },
                source_ip=str(feat.get("src_ip")),
                destination_ip=str(feat.get("dst_ip")),
                protocol=str(feat.get("protocol")),
                explanation=explanation,
            )

        # -----------------------------------------------------------------
        # 2. Evaluate DGA Domains (Algorithmically Generated Domains)
        # Characteristics: pseudorandom domain name, high entropy on SLD,
        # unnatural character n-grams, low vowel ratio, long consonant runs.
        # Legitimate long domains (e.g. hyphenated names) are protected.
        is_dga_entropy = entropy >= self.config.dga_min_entropy
        is_lexical_anomaly = (
            c_run >= self.config.dga_min_consonant_run
            or v_ratio <= self.config.dga_max_vowel_ratio
            or ng_score <= self.config.dga_max_ngram_score
        )

        if is_dga_entropy and is_lexical_anomaly:
            confidence = 0.65
            if entropy >= 3.8:
                confidence += 0.10
            if c_run >= 6:
                confidence += 0.10
            elif c_run >= 4:
                confidence += 0.05
            if v_ratio <= 0.10:
                confidence += 0.10
            if ng_score <= 0.10:
                confidence += 0.05

            confidence = min(round(confidence, 2), 0.98)
            if confidence < self.config.confidence_threshold:
                return None

            severity = "HIGH" if (entropy >= 3.8 and c_run >= 6) else "MEDIUM"

            dga_evidence: list[EvidenceSignal] = [
                EvidenceSignal(
                    signal_name="dga_lexical_anomaly",
                    value=round(1.0 - ng_score, 3),
                    direction="supporting",
                    reliability=0.92,
                    supporting_features=["dns_query", "dns_ngram_score"],
                    threat_class="DGA",
                ),
                EvidenceSignal(
                    signal_name="high_dns_entropy",
                    value=round(entropy, 3),
                    direction="supporting",
                    reliability=0.89,
                    supporting_features=["dns_entropy"],
                    threat_class="DGA",
                ),
            ]

            if c_run >= self.config.dga_min_consonant_run:
                dga_evidence.append(
                    EvidenceSignal(
                        signal_name="consonant_cluster_anomaly",
                        value=float(c_run),
                        direction="supporting",
                        reliability=0.88,
                        supporting_features=["dns_max_consonant_run"],
                        threat_class="DGA",
                    )
                )

            if v_ratio <= self.config.dga_max_vowel_ratio:
                dga_evidence.append(
                    EvidenceSignal(
                        signal_name="abnormal_vowel_distribution",
                        value=round(v_ratio, 3),
                        direction="supporting",
                        reliability=0.86,
                        supporting_features=["dns_vowel_ratio"],
                        threat_class="DGA",
                    )
                )

            explanation = (
                f"Algorithmically generated domain (DGA) pattern detected in DNS query: "
                f"entropy={entropy:.3f} bits/char, consonant run={c_run}, vowel ratio={v_ratio:.2f}, "
                f"ngram score={ng_score:.2f}."
            )

            return DetectionResult(
                timestamp=record.timestamp,
                flow_id=record.flow_id,
                threat_class="DGA",
                confidence=confidence,
                severity=severity,
                evidence=dga_evidence,
                detection_method="statistical",
                relevant_features={
                    "dns_query": query,
                    "dns_entropy": entropy,
                    "dns_vowel_ratio": v_ratio,
                    "dns_max_consonant_run": c_run,
                    "dns_ngram_score": ng_score,
                },
                source_ip=str(feat.get("src_ip")),
                destination_ip=str(feat.get("dst_ip")),
                protocol=str(feat.get("protocol")),
                explanation=explanation,
            )

        return None
