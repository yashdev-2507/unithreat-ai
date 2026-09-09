"""
unithreat.ml.pipeline
=====================

Model pipeline definition, serialization, and deserialization using scikit-learn and joblib.

Uses:
  SimpleImputer(strategy="median") -> RandomForestClassifier(class_weight="balanced")

No scaling is used, as tree-based ensembles are invariant to monotonic feature scaling.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from unithreat.ml.features import FEATURE_NAMES

DEFAULT_MODEL_VERSION = "rf-baseline-v1"


def create_model_pipeline(
    seed: int = 42,
    n_estimators: int = 100,
    max_depth: int | None = 15,
) -> Pipeline:
    """
    Create a fresh scikit-learn Pipeline with median imputation and RandomForestClassifier.
    """
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                min_samples_split=2,
                class_weight="balanced",
                random_state=seed,
                n_jobs=-1,
            ),
        ),
    ])


def save_pipeline(
    pipeline: Pipeline,
    metadata: dict[str, Any],
    model_dir: Path | str,
) -> Path:
    """
    Persist the trained pipeline and its metadata to the specified directory.

    Files written:
      - model_dir / "model.joblib"
      - model_dir / "metadata.json"
    """
    dir_path = Path(model_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    model_path = dir_path / "model.joblib"
    metadata_path = dir_path / "metadata.json"

    joblib.dump(pipeline, model_path)

    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return dir_path


def load_pipeline(model_dir: Path | str) -> tuple[Pipeline, dict[str, Any]]:
    """
    Load a persisted pipeline and its metadata from disk.

    Parameters
    ----------
    model_dir : Path | str
        Directory containing model.joblib and metadata.json.

    Returns
    -------
    tuple of (Pipeline, dict[str, Any])
    """
    dir_path = Path(model_dir)
    model_path = dir_path / "model.joblib"
    metadata_path = dir_path / "metadata.json"

    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found at: {model_path}")
    if not metadata_path.exists():
        raise FileNotFoundError(f"Metadata file not found at: {metadata_path}")

    pipeline: Pipeline = joblib.load(model_path)
    with metadata_path.open("r", encoding="utf-8") as f:
        metadata: dict[str, Any] = json.load(f)

    return pipeline, metadata
