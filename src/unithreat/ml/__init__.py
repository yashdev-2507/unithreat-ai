"""
unithreat.ml
============

Machine Learning Intelligence Layer for UniThreat AI.

Provides:
  - Feature vectorization based on contracts/feature-schema.json
  - Multi-run dataset generation & group-aware train/val/test splitting
  - Scikit-learn RandomForestClassifier tabular training pipeline
  - Pipeline serialization with version metadata
  - Single-flow inference strictly conforming to contracts/ml-prediction-schema.json
"""

from unithreat.ml.dataset import (
    ALL_CLASSES,
    SCENARIO_LABEL_MAP,
    generate_labelled_dataset,
    load_dataset_jsonl,
    save_dataset_jsonl,
    split_dataset_by_group,
)
from unithreat.ml.features import FEATURE_NAMES, extract_feature_vector
from unithreat.ml.inference import MLInferenceEngine
from unithreat.ml.models import MLPrediction
from unithreat.ml.pipeline import (
    DEFAULT_MODEL_VERSION,
    create_model_pipeline,
    load_pipeline,
    save_pipeline,
)
from unithreat.ml.train import train_model

__all__ = [
    "ALL_CLASSES",
    "DEFAULT_MODEL_VERSION",
    "FEATURE_NAMES",
    "MLInferenceEngine",
    "MLPrediction",
    "SCENARIO_LABEL_MAP",
    "create_model_pipeline",
    "extract_feature_vector",
    "generate_labelled_dataset",
    "load_dataset_jsonl",
    "load_pipeline",
    "save_dataset_jsonl",
    "save_pipeline",
    "split_dataset_by_group",
    "train_model",
]
