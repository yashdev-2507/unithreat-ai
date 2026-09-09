"""
unithreat.ml.features
=====================

Feature selection and transformation utilities for tabular ML models.

Conforms strictly to contracts/feature-schema.json.
Uses exclusively features produced by unithreat.features.FeatureExtractor.
"""

from __future__ import annotations

import math
from typing import Any

from unithreat.features.models import FeatureRecord

# Canonical list of security-relevant feature keys (37 features)
FEATURE_NAMES: list[str] = [
    # Base flow volume and rate metrics
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_sec",
    "bytes_per_sec",
    "bytes_per_packet",
    # TCP and UDP flags
    "is_syn",
    "is_ack",
    "is_psh",
    "is_fin",
    "is_rst",
    "is_urg",
    "is_tcp",
    "is_udp",
    # DNS metadata and lexical metrics
    "has_dns",
    "dns_query_length",
    "dns_entropy",
    "dns_vowel_ratio",
    "dns_consonant_ratio",
    "dns_max_consonant_run",
    "dns_ngram_score",
    "dns_digit_ratio",
    # TLS and QUIC session metadata
    "has_tls",
    "has_quic",
    "is_ip_sni",
    # Streaming window / behavioral aggregations
    "src_fan_out",
    "unique_dst_hosts",
    "unique_dst_ports",
    "dst_fan_in",
    "flow_rate",
    "inter_arrival_time",
    "mean_inter_arrival_time",
    "inter_arrival_std",
    "periodicity_score",
    "protocol_tcp_ratio",
    "protocol_udp_ratio",
    "outbound_inbound_byte_ratio",
]

_BOOLEAN_FEATURES = frozenset({
    "is_syn",
    "is_ack",
    "is_psh",
    "is_fin",
    "is_rst",
    "is_urg",
    "is_tcp",
    "is_udp",
    "has_dns",
    "has_tls",
    "has_quic",
    "is_ip_sni",
})


def extract_feature_vector(record_or_features: FeatureRecord | dict[str, Any]) -> list[float]:
    """
    Extract an ordered numeric feature vector from a FeatureRecord or feature dictionary.

    Missing numeric features are represented as float('nan') to be imputed by the pipeline.
    Boolean features are converted to 1.0 (True) or 0.0 (False / missing).

    Parameters
    ----------
    record_or_features : FeatureRecord | dict[str, Any]
        FeatureRecord instance or raw feature dictionary.

    Returns
    -------
    list[float]
        Ordered feature vector matching FEATURE_NAMES.
    """
    if isinstance(record_or_features, FeatureRecord):
        feat_dict = record_or_features.features
    elif isinstance(record_or_features, dict):
        if "features" in record_or_features and isinstance(record_or_features["features"], dict):
            feat_dict = record_or_features["features"]
        else:
            feat_dict = record_or_features
    else:
        raise TypeError(f"Expected FeatureRecord or dict, got {type(record_or_features).__name__!r}")

    vector: list[float] = []
    for name in FEATURE_NAMES:
        val = feat_dict.get(name)

        if name in _BOOLEAN_FEATURES:
            vector.append(1.0 if bool(val) else 0.0)
        elif val is None:
            vector.append(float("nan"))
        elif isinstance(val, (int, float)):
            vector.append(float(val))
        elif isinstance(val, bool):
            vector.append(1.0 if val else 0.0)
        else:
            # Fallback for non-numeric/unknown types
            vector.append(float("nan"))

    return vector
