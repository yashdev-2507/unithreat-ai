"""
tests/ml/test_pipeline.py
=========================

Tests for model pipeline construction and joblib serialization.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from unithreat.ml.pipeline import (
    DEFAULT_MODEL_VERSION,
    create_model_pipeline,
    load_pipeline,
    save_pipeline,
)


class TestPipeline:
    def test_pipeline_structure(self):
        pipeline = create_model_pipeline(seed=42)
        assert isinstance(pipeline, Pipeline)
        assert "imputer" in pipeline.named_steps
        assert "classifier" in pipeline.named_steps
        assert isinstance(pipeline.named_steps["imputer"], SimpleImputer)
        assert isinstance(pipeline.named_steps["classifier"], RandomForestClassifier)

    def test_save_and_load_roundtrip(self, tmp_path: Path):
        pipeline = create_model_pipeline(seed=42, n_estimators=10, max_depth=5)
        # Dummy fit
        x_dummy = [[1.0] * 32, [0.0] * 32]
        y_dummy = ["BENIGN", "DDOS"]
        pipeline.fit(x_dummy, y_dummy)

        metadata = {
            "model_version": "test-v1",
            "classes": ["BENIGN", "DDOS"],
        }

        save_dir = tmp_path / "model_dir"
        save_pipeline(pipeline, metadata, model_dir=save_dir)

        assert (save_dir / "model.joblib").exists()
        assert (save_dir / "metadata.json").exists()

        loaded_pipeline, loaded_metadata = load_pipeline(save_dir)
        assert isinstance(loaded_pipeline, Pipeline)
        assert loaded_metadata["model_version"] == "test-v1"

        # Check predictions match
        pred_original = pipeline.predict(x_dummy)
        pred_loaded = loaded_pipeline.predict(x_dummy)
        assert list(pred_original) == list(pred_loaded)

    def test_load_nonexistent_directory_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_pipeline(tmp_path / "nonexistent")
