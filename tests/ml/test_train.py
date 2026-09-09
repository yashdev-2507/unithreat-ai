"""
tests/ml/test_train.py
======================

Tests for deterministic training, metrics reporting, and multi-class representation.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from unithreat.ml.dataset import ALL_CLASSES, generate_labelled_dataset
from unithreat.ml.train import train_model


class TestTraining:
    def test_training_succeeds_and_covers_all_eight_classes(self, tmp_path: Path):
        # Quick dataset: 3 runs per scenario, 15 flows per run
        dataset = generate_labelled_dataset(runs_per_scenario=3, flows_per_run=15, seed_base=42)
        model_dir = tmp_path / "trained_model"

        result = train_model(
            dataset=dataset,
            model_dir=model_dir,
            seed=42,
            n_estimators=25,
            max_depth=10,
        )

        assert "pipeline" in result
        assert "metadata" in result
        assert "metrics" in result
        assert "classes" in result
        assert "feature_importances" in result

        metrics = result["metrics"]
        assert "accuracy" in metrics
        assert "precision_macro" in metrics
        assert "recall_macro" in metrics
        assert "f1_macro" in metrics
        assert metrics["accuracy"] >= 0.85

        # All 8 classes should be recognized by classifier
        assert set(result["classes"]) == set(ALL_CLASSES)

        # Persistence verified
        assert (model_dir / "model.joblib").exists()
        assert (model_dir / "metadata.json").exists()

    def test_deterministic_training_with_fixed_seed(self):
        dataset = generate_labelled_dataset(runs_per_scenario=3, flows_per_run=10, seed_base=123)

        run_1 = train_model(dataset=dataset, seed=999, n_estimators=15, max_depth=8)
        run_2 = train_model(dataset=dataset, seed=999, n_estimators=15, max_depth=8)

        assert run_1["metrics"]["accuracy"] == run_2["metrics"]["accuracy"]
        assert run_1["metrics"]["f1_macro"] == run_2["metrics"]["f1_macro"]
        assert run_1["feature_importances"] == run_2["feature_importances"]

    def test_feature_importances_sum_to_one(self):
        dataset = generate_labelled_dataset(runs_per_scenario=3, flows_per_run=10, seed_base=42)
        result = train_model(dataset=dataset, seed=42, n_estimators=20, max_depth=8)

        total_imp = sum(result["feature_importances"].values())
        assert round(total_imp, 2) == 1.00
