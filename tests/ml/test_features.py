"""
tests/ml/test_features.py
=========================

Tests for feature selection, extraction, and vectorization for ML models.
"""

from __future__ import annotations

import math
import pytest

from unithreat.features.models import FeatureRecord
from unithreat.ml.features import (
    FEATURE_NAMES,
    extract_feature_vector,
)


class TestFeatureExtraction:
    def test_feature_vector_dimension_matches_feature_names(self):
        feat_dict = {
            "duration": 1.5,
            "packet_count": 10,
            "byte_count": 1500,
            "packets_per_sec": 6.67,
            "bytes_per_sec": 1000.0,
            "bytes_per_packet": 150.0,
            "is_syn": True,
            "is_ack": False,
            "is_tcp": True,
            "is_udp": False,
        }
        vec = extract_feature_vector(feat_dict)
        assert len(vec) == len(FEATURE_NAMES)
        assert len(vec) == 37

    def test_extract_from_feature_record_instance(self):
        record = FeatureRecord(
            flow_id="test-flow-001",
            timestamp="2026-09-06T12:00:00.000000Z",
            entity_id="192.168.1.50",
            features={
                "duration": 0.5,
                "packet_count": 4,
                "byte_count": 240,
                "is_syn": True,
                "is_tcp": True,
            },
        )
        vec = extract_feature_vector(record)
        assert len(vec) == len(FEATURE_NAMES)
        # Find index of duration
        idx_duration = FEATURE_NAMES.index("duration")
        assert vec[idx_duration] == 0.5
        # Find index of is_syn
        idx_syn = FEATURE_NAMES.index("is_syn")
        assert vec[idx_syn] == 1.0

    def test_missing_and_none_features_become_nan(self):
        feat_dict = {"duration": 2.0}
        vec = extract_feature_vector(feat_dict)
        idx_byte_count = FEATURE_NAMES.index("byte_count")
        assert math.isnan(vec[idx_byte_count])

    def test_boolean_features_cast_to_float_binary(self):
        feat_dict = {
            "is_syn": True,
            "is_ack": False,
            "has_dns": True,
            "has_tls": False,
        }
        vec = extract_feature_vector(feat_dict)
        assert vec[FEATURE_NAMES.index("is_syn")] == 1.0
        assert vec[FEATURE_NAMES.index("is_ack")] == 0.0
        assert vec[FEATURE_NAMES.index("has_dns")] == 1.0
        assert vec[FEATURE_NAMES.index("has_tls")] == 0.0

    def test_invalid_input_type_raises_type_error(self):
        with pytest.raises(TypeError, match="Expected FeatureRecord or dict"):
            extract_feature_vector(["not", "a", "record"])  # type: ignore[arg-type]
