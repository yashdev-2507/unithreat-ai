"""
unithreat.features.extractor
============================

Extracts normalized statistical and behavioral features from Flow events.

Computes:
  - Base flow metrics (duration, packet_count, byte_count, rates, ratios)
  - Zero-duration safety (prevents division by zero)
  - TCP and UDP flags (SYN, ACK, PSH, FIN, RST, URG)
  - DNS metadata metrics (query length, Shannon entropy, record type, rcode)
  - TLS metadata characteristics (version, SNI, JA3, cipher, IP-as-SNI)
  - QUIC metadata characteristics (version, SNI)
  - Incremental streaming window features:
      * Source/destination fan-out and unique host/port metrics
      * Flow frequency / rates
      * Inter-arrival times, standard deviation, coefficient of variation, periodicity
      * Protocol distributions (TCP ratio, UDP ratio)
      * Outbound/inbound directional byte volume and ratio
  - Contextual window metrics if provided
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import math
import re
from typing import Any

from unithreat.features.models import FeatureRecord
from unithreat.features.window import FeatureWindowTracker
from unithreat.ingest.models import Flow

_IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def compute_shannon_entropy(text: str | None) -> float:
    """Compute Shannon entropy (in bits per character) of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


_COMMON_ENGLISH_BIGRAMS = frozenset({
    "th", "he", "in", "er", "an", "re", "ed", "on", "es", "st", "en", "at", "to", "nt", "ha",
    "nd", "ou", "ea", "ng", "as", "or", "ti", "is", "et", "it", "ar", "te", "se", "hi", "of",
    "al", "de", "co", "ro", "li", "ra", "le", "sa", "si", "ma", "me", "ta", "ri", "ne", "la",
    "el", "io", "ca", "lo", "da", "di", "pe", "pa", "na", "no", "om", "mo", "ce", "ic", "ch",
    "sh", "ck", "ad", "ba", "be", "bo", "bu", "by", "do", "fa", "fe", "fi", "fo", "ga", "ge",
    "go", "gu", "ho", "id", "il", "im", "ja", "jo", "ju", "ka", "ke", "ki", "ko", "ku", "lu",
    "ly", "mi", "mu", "my", "nu", "ny", "ob", "oc", "op", "os", "ot", "ov", "ow", "ox", "oy",
    "pi", "po", "pu", "py", "qu", "ru", "ry", "so", "su", "sy", "tu", "ty", "ub", "ug", "um",
    "un", "up", "ur", "us", "ut", "va", "ve", "vi", "vo", "wa", "we", "wi", "wo", "ya", "ye",
    "yo", "za", "ze", "zi", "zo", "zu",
})

_VOWELS = frozenset({"a", "e", "i", "o", "u"})


def compute_dns_lexical_metrics(query: str | None) -> dict[str, float | int | None]:
    """
    Compute lexical features on DNS query for DGA and tunneling detection.

    Extracts core domain label and computes:
      - dns_vowel_ratio: fraction of vowels (a, e, i, o, u) in core label
      - dns_consonant_ratio: fraction of consonants in core label
      - dns_max_consonant_run: longest consecutive consonant sequence in core label
      - dns_ngram_score: ratio of common English bigrams in core label
      - dns_digit_ratio: fraction of digits in core label
    """
    if not query:
        return {
            "dns_vowel_ratio": None,
            "dns_consonant_ratio": None,
            "dns_max_consonant_run": None,
            "dns_ngram_score": None,
            "dns_digit_ratio": None,
        }

    parts = [p for p in query.strip(".").split(".") if p]
    if not parts:
        return {
            "dns_vowel_ratio": None,
            "dns_consonant_ratio": None,
            "dns_max_consonant_run": None,
            "dns_ngram_score": None,
            "dns_digit_ratio": None,
        }

    # Core label: if an unusually long label (>= 25 chars) exists, analyze it
    # as the candidate data/DGA payload; otherwise use standard SLD (parts[-2])
    longest_label = max(parts, key=len)
    if len(longest_label) >= 25:
        core = longest_label
    else:
        core = parts[-2] if len(parts) >= 2 else parts[0]
    core_clean = core.lower()

    alpha_chars = [c for c in core_clean if c.isalpha()]
    digits = [c for c in core_clean if c.isdigit()]
    total_len = len(core_clean)
    digit_ratio = round(len(digits) / total_len, 4) if total_len > 0 else 0.0

    if not alpha_chars:
        return {
            "dns_vowel_ratio": 0.0,
            "dns_consonant_ratio": 0.0,
            "dns_max_consonant_run": 0,
            "dns_ngram_score": 0.0,
            "dns_digit_ratio": digit_ratio,
        }

    vowel_count = sum(1 for c in alpha_chars if c in _VOWELS)
    consonant_count = len(alpha_chars) - vowel_count
    vowel_ratio = round(vowel_count / len(alpha_chars), 4)
    consonant_ratio = round(consonant_count / len(alpha_chars), 4)

    # Longest consecutive consonant run
    max_c_run = 0
    cur_c_run = 0
    for c in core_clean:
        if c.isalpha() and c not in _VOWELS:
            cur_c_run += 1
            if cur_c_run > max_c_run:
                max_c_run = cur_c_run
        else:
            cur_c_run = 0

    # Bigram score on alpha characters
    alpha_str = "".join(alpha_chars)
    if len(alpha_str) >= 2:
        bigrams = [alpha_str[i : i + 2] for i in range(len(alpha_str) - 1)]
        common_count = sum(1 for bg in bigrams if bg in _COMMON_ENGLISH_BIGRAMS)
        ngram_score = round(common_count / len(bigrams), 4)
    else:
        ngram_score = 1.0

    return {
        "dns_vowel_ratio": vowel_ratio,
        "dns_consonant_ratio": consonant_ratio,
        "dns_max_consonant_run": max_c_run,
        "dns_ngram_score": ngram_score,
        "dns_digit_ratio": digit_ratio,
    }


class FeatureExtractor:
    """
    Extracts numerical and categorical feature sets from passive flow records.
    Can be configured with an internal stateful window tracker for streaming aggregations.
    """

    def __init__(
        self,
        window_tracker: FeatureWindowTracker | None = None,
        enable_windowing: bool = True,
        window_duration_seconds: float = 60.0,
    ) -> None:
        if window_tracker is not None:
            self.window_tracker: FeatureWindowTracker | None = window_tracker
        elif enable_windowing:
            self.window_tracker = FeatureWindowTracker(window_duration_seconds=window_duration_seconds)
        else:
            self.window_tracker = None

    def extract(
        self,
        flow: Flow | dict[str, Any],
        context: dict[str, Any] | None = None,
        window_id: str | None = None,
    ) -> FeatureRecord:
        """
        Transform a Flow event into a validated FeatureRecord.

        Parameters
        ----------
        flow : Flow | dict[str, Any]
            Flow model instance or raw flow record dict.
        context : dict[str, Any] | None
            Optional caller-supplied contextual features to merge.
        window_id : str | None
            Optional window identifier.

        Returns
        -------
        FeatureRecord
            Validated feature record conforming to contracts/feature-schema.json.
        """
        # Validate and coerce input
        if isinstance(flow, dict):
            try:
                flow_obj = Flow.model_validate(flow)
            except Exception as exc:
                raise ValueError(f"Cannot extract features from malformed flow dict: {exc}") from exc
        elif isinstance(flow, Flow):
            flow_obj = flow
        else:
            raise TypeError(f"Expected Flow or dict, got {type(flow).__name__!r}")

        # Duration and count safety (zero-duration safety)
        raw_duration = flow_obj.duration
        duration = float(raw_duration) if raw_duration is not None and raw_duration >= 0.0 else 0.0

        raw_packets = flow_obj.packet_count
        packet_count = int(raw_packets) if raw_packets is not None and raw_packets >= 0 else 0

        raw_bytes = flow_obj.byte_count
        byte_count = int(raw_bytes) if raw_bytes is not None and raw_bytes >= 0 else 0

        # Safe rate calculations with zero-duration protection
        effective_duration = max(duration, 0.001)
        packets_per_sec = round(packet_count / effective_duration, 4) if packet_count > 0 else 0.0
        bytes_per_sec = round(byte_count / effective_duration, 4) if byte_count > 0 else 0.0
        bytes_per_packet = round(byte_count / packet_count, 4) if packet_count > 0 else 0.0

        tcp_flags = flow_obj.tcp_flags or ""
        protocol = flow_obj.protocol.upper()

        features: dict[str, float | int | str | bool | None] = {
            # Network coordinates
            "src_ip": flow_obj.src_ip,
            "dst_ip": flow_obj.dst_ip,
            "src_port": flow_obj.src_port,
            "dst_port": flow_obj.dst_port,
            "protocol": protocol,
            "direction": flow_obj.direction,
            # Flow volume and rates
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "bytes_per_packet": bytes_per_packet,
            # TCP and UDP flags
            "tcp_flags": flow_obj.tcp_flags,
            "is_syn": "SYN" in tcp_flags,
            "is_ack": "ACK" in tcp_flags,
            "is_psh": "PSH" in tcp_flags,
            "is_fin": "FIN" in tcp_flags,
            "is_rst": "RST" in tcp_flags,
            "is_urg": "URG" in tcp_flags,
            "is_udp": protocol == "UDP",
            "is_tcp": protocol == "TCP",
            # DNS metadata
            "has_dns": flow_obj.dns is not None,
            "dns_query": None,
            "dns_query_length": None,
            "dns_entropy": None,
            "dns_qtype": None,
            "dns_rcode": None,
            "dns_vowel_ratio": None,
            "dns_consonant_ratio": None,
            "dns_max_consonant_run": None,
            "dns_ngram_score": None,
            "dns_digit_ratio": None,
            # TLS metadata
            "has_tls": flow_obj.tls is not None,
            "tls_version": None,
            "tls_sni": None,
            "tls_ja3": None,
            "tls_cipher": None,
            "is_ip_sni": False,
            # QUIC metadata
            "has_quic": flow_obj.quic is not None,
            "quic_version": None,
            "quic_sni": None,
        }

        # Extract DNS metadata if available
        if flow_obj.dns and isinstance(flow_obj.dns, dict):
            query = flow_obj.dns.get("query")
            if isinstance(query, str):
                features["dns_query"] = query
                features["dns_query_length"] = len(query)
                features["dns_entropy"] = compute_shannon_entropy(query)
                features.update(compute_dns_lexical_metrics(query))

            qtype = flow_obj.dns.get("qtype")
            if isinstance(qtype, str):
                features["dns_qtype"] = qtype.upper()

            rcode = flow_obj.dns.get("rcode")
            if isinstance(rcode, str):
                features["dns_rcode"] = rcode.upper()

        # Extract TLS metadata if available
        if flow_obj.tls and isinstance(flow_obj.tls, dict):
            tls_ver = flow_obj.tls.get("version")
            if isinstance(tls_ver, str):
                features["tls_version"] = tls_ver

            sni = flow_obj.tls.get("sni")
            if isinstance(sni, str):
                features["tls_sni"] = sni
                features["is_ip_sni"] = bool(_IPV4_PATTERN.match(sni))

            ja3 = flow_obj.tls.get("ja3")
            if isinstance(ja3, str):
                features["tls_ja3"] = ja3

            cipher = flow_obj.tls.get("cipher")
            if isinstance(cipher, str):
                features["tls_cipher"] = cipher

        # Extract QUIC metadata if available
        if flow_obj.quic and isinstance(flow_obj.quic, dict):
            quic_ver = flow_obj.quic.get("version")
            if isinstance(quic_ver, str):
                features["quic_version"] = quic_ver

            quic_sni = flow_obj.quic.get("sni")
            if isinstance(quic_sni, str):
                features["quic_sni"] = quic_sni
                if not features["is_ip_sni"]:
                    features["is_ip_sni"] = bool(_IPV4_PATTERN.match(quic_sni))

        # Incremental sliding-window aggregation
        if self.window_tracker is not None:
            window_features = self.window_tracker.update_and_compute(
                flow_timestamp=flow_obj.timestamp,
                src_ip=flow_obj.src_ip,
                dst_ip=flow_obj.dst_ip,
                dst_port=flow_obj.dst_port,
                protocol=protocol,
                direction=flow_obj.direction,
                duration=duration,
                packet_count=packet_count,
                byte_count=byte_count,
            )
            features.update(window_features)

        # Merge caller-provided contextual metrics
        if context:
            for k, v in context.items():
                if isinstance(v, (int, float, str, bool)) or v is None:
                    features[k] = v

        timestamp_str = (
            flow_obj.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            if hasattr(flow_obj.timestamp, "strftime")
            else str(flow_obj.timestamp)
        )

        return FeatureRecord(
            flow_id=flow_obj.flow_id,
            timestamp=timestamp_str,
            entity_id=flow_obj.src_ip,
            window_id=window_id,
            features=features,
        )


def extract_features(
    flow: Flow | dict[str, Any],
    context: dict[str, Any] | None = None,
    window_id: str | None = None,
    window_tracker: FeatureWindowTracker | None = None,
) -> FeatureRecord:
    """
    Convenience helper to extract features from a flow record.
    """
    extractor = FeatureExtractor(window_tracker=window_tracker, enable_windowing=window_tracker is not None)
    return extractor.extract(flow=flow, context=context, window_id=window_id)
