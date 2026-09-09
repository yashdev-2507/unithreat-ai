"""
unithreat.ml.train
==================

Training and evaluation pipeline for UniThreat AI tabular threat classifier.

Performs:
  1. Group/run-aware dataset splitting (avoiding session/temporal data leakage)
  2. Missing value handling (SimpleImputer)
  3. Deterministic training with fixed random seed
  4. Comprehensive evaluation (accuracy, precision, recall, F1, confusion matrix)
  5. Feature importance extraction
  6. Persistence of model pipeline and version metadata
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from unithreat.ml.dataset import (
    ALL_CLASSES,
    generate_labelled_dataset,
    split_dataset_by_group,
)
from unithreat.ml.features import FEATURE_NAMES, extract_feature_vector
from unithreat.ml.pipeline import (
    DEFAULT_MODEL_VERSION,
    create_model_pipeline,
    save_pipeline,
)


def _prepare_xy(dataset: list[dict[str, Any]]) -> tuple[list[list[float]], list[str]]:
    """Convert dataset records to feature matrix X and label vector y."""
    x: list[list[float]] = []
    y: list[str] = []
    for item in dataset:
        vec = extract_feature_vector(item["features"])
        x.append(vec)
        y.append(item["label"])
    return x, y


def train_model(
    dataset: list[dict[str, Any]] | None = None,
    model_dir: Path | str | None = None,
    model_version: str = DEFAULT_MODEL_VERSION,
    seed: int = 42,
    n_estimators: int = 100,
    max_depth: int | None = 15,
    runs_per_scenario: int = 5,
    flows_per_run: int = 50,
) -> dict[str, Any]:
    """
    Train and evaluate a RandomForestClassifier threat detection model.

    Parameters
    ----------
    dataset : list[dict[str, Any]] | None
        Pre-loaded dataset. If None, a synthetic dataset is generated across all 8 classes.
    model_dir : Path | str | None
        Directory where model and metadata will be saved.
    model_version : str
        Identifier for the model release (default: "rf-baseline-v1").
    seed : int
        Random seed for deterministic training and splitting.
    n_estimators : int
        Number of decision trees in the random forest.
    max_depth : int | None
        Maximum tree depth.
    runs_per_scenario : int
        Number of distinct simulation runs per class (if generating synthetic dataset).
    flows_per_run : int
        Flows per simulation run (if generating synthetic dataset).

    Returns
    -------
    dict[str, Any]
        Comprehensive training report including metrics, class distribution,
        feature importances, and saved paths.
    """
    if dataset is None:
        dataset = generate_labelled_dataset(
            runs_per_scenario=runs_per_scenario,
            flows_per_run=flows_per_run,
            seed_base=seed,
        )

    # 1. Group/run-aware split to prevent data leakage
    train_set, val_set, test_set = split_dataset_by_group(
        dataset=dataset,
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        seed=seed,
    )

    x_train, y_train = _prepare_xy(train_set)
    x_test, y_test = _prepare_xy(test_set)
    x_val, y_val = _prepare_xy(val_set)

    # 2. Fit pipeline
    pipeline = create_model_pipeline(
        seed=seed,
        n_estimators=n_estimators,
        max_depth=max_depth,
    )
    pipeline.fit(x_train, y_train)

    # 3. Evaluate on held-out test set
    classes = list(pipeline.named_steps["classifier"].classes_)
    y_pred = pipeline.predict(x_test)

    acc = float(accuracy_score(y_test, y_pred))
    p_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    p_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    r_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    r_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1_mac = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    f1_wgt = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()

    # 4. Feature importances (Gini)
    rf_clf = pipeline.named_steps["classifier"]
    importances = rf_clf.feature_importances_
    feat_imp_dict = {
        name: round(float(imp), 5)
        for name, imp in sorted(zip(FEATURE_NAMES, importances, strict=True), key=lambda t: t[1], reverse=True)
    }

    # 5. Class distribution
    all_labels = [s["label"] for s in dataset]
    class_dist = {cls: all_labels.count(cls) for cls in ALL_CLASSES}

    metadata: dict[str, Any] = {
        "model_version": model_version,
        "algorithm": "RandomForestClassifier",
        "calibrated": False,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
        "feature_names": FEATURE_NAMES,
        "classes": classes,
        "hyperparameters": {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "class_weight": "balanced",
            "imputer_strategy": "median",
        },
        "dataset_summary": {
            "total_samples": len(dataset),
            "train_samples": len(train_set),
            "val_samples": len(val_set),
            "test_samples": len(test_set),
            "class_distribution": class_dist,
        },
        "metrics": {
            "accuracy": round(acc, 4),
            "precision_macro": round(p_macro, 4),
            "precision_weighted": round(p_weighted, 4),
            "recall_macro": round(r_macro, 4),
            "recall_weighted": round(r_weighted, 4),
            "f1_macro": round(f1_mac, 4),
            "f1_weighted": round(f1_wgt, 4),
        },
        "confusion_matrix": {
            "labels": classes,
            "matrix": cm,
        },
        "feature_importances": feat_imp_dict,
    }

    # 6. Model persistence
    if model_dir is not None:
        save_pipeline(pipeline, metadata, model_dir=model_dir)

    return {
        "pipeline": pipeline,
        "metadata": metadata,
        "metrics": metadata["metrics"],
        "classes": classes,
        "feature_importances": feat_imp_dict,
    }
