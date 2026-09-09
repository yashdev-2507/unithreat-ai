"""
unithreat.features
==================

Feature extraction module for UniThreat AI.

Exported
--------
``FeatureRecord``
    Normalized feature record model matching contracts/feature-schema.json.
``FeatureExtractor``
    Extracts statistical, behavioral, and metadata features from Flow events.
``FeatureWindowTracker``
    Stateful bounded sliding window tracker for streaming feature aggregations.
``extract_features``
    Convenience function to extract features from a Flow instance.
``compute_shannon_entropy``
    Utility computing Shannon entropy in bits per character.
"""

from unithreat.features.extractor import (
    FeatureExtractor,
    compute_dns_lexical_metrics,
    compute_shannon_entropy,
    extract_features,
)
from unithreat.features.models import FeatureRecord
from unithreat.features.window import FeatureWindowTracker

__all__ = [
    "FeatureExtractor",
    "FeatureRecord",
    "FeatureWindowTracker",
    "compute_dns_lexical_metrics",
    "compute_shannon_entropy",
    "extract_features",
]
