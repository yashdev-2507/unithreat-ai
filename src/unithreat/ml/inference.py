"""
unithreat.ml.inference
======================

Inference engine for tabular threat classification.

Implements single-record inference conforming strictly to contracts/ml-prediction-schema.json:
  - flow_id: string
  - threat_class: string
  - score: number [0, 1] (uncalibrated confidence index)
  - model_version: string
  - calibrated: boolean (strictly False)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from sklearn.pipeline import Pipeline

from unithreat.features.models import FeatureRecord
from unithreat.ml.features import FEATURE_NAMES, extract_feature_vector
from unithreat.ml.models import MLPrediction
from unithreat.ml.pipeline import DEFAULT_MODEL_VERSION, load_pipeline


class MLInferenceEngine:
    """
    Stateful inference engine that holds a pre-loaded trained ML pipeline in memory.

    Optimized for low-latency, single-flow streaming inference without reloading models.
    """

    def __init__(
        self,
        model_dir: Path | str | None = None,
        pipeline: Pipeline | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize the inference engine with an in-memory pipeline or from a saved directory.
        """
        if pipeline is not None:
            self.pipeline: Pipeline = pipeline
            self.metadata: dict[str, Any] = metadata or {
                "model_version": DEFAULT_MODEL_VERSION,
                "classes": list(pipeline.named_steps["classifier"].classes_),
            }
        elif model_dir is not None:
            self.pipeline, self.metadata = load_pipeline(model_dir)
        else:
            raise ValueError("Either 'pipeline' or 'model_dir' must be provided to MLInferenceEngine.")

        self.model_version: str = self.metadata.get("model_version", DEFAULT_MODEL_VERSION)
        self.classes: list[str] = list(self.pipeline.named_steps["classifier"].classes_)
        self.feature_importances: dict[str, float] = self.metadata.get("feature_importances", {})

        # Ensure single-threaded execution for single-sample inference (avoids threadpool overhead)
        if hasattr(self.pipeline.named_steps.get("classifier"), "n_jobs"):
            self.pipeline.named_steps["classifier"].n_jobs = 1

    def predict(self, record_or_dict: FeatureRecord | dict[str, Any]) -> MLPrediction:
        """
        Run inference on a single FeatureRecord or valid feature record dictionary.

        Returns an MLPrediction instance that serializes directly to
        contracts/ml-prediction-schema.json.

        Parameters
        ----------
        record_or_dict : FeatureRecord | dict[str, Any]
            Normalized feature record conforming to contracts/feature-schema.json.

        Returns
        -------
        MLPrediction
            Prediction object conforming to contracts/ml-prediction-schema.json.
        """
        if record_or_dict is None:
            raise ValueError("Input feature record cannot be None.")

        # Extract flow_id
        if isinstance(record_or_dict, FeatureRecord):
            flow_id = record_or_dict.flow_id
        elif isinstance(record_or_dict, dict):
            flow_id = record_or_dict.get("flow_id")
            if not flow_id or not isinstance(flow_id, str):
                raise ValueError("Input dictionary must contain a non-empty 'flow_id' string.")
        else:
            raise TypeError(f"Expected FeatureRecord or dict, got {type(record_or_dict).__name__!r}")

        # Extract feature vector
        vector = extract_feature_vector(record_or_dict)
        x_mat = np.array([vector], dtype=float)

        # Predict probabilities
        probabilities = self.pipeline.predict_proba(x_mat)[0]
        max_idx = int(np.argmax(probabilities))
        predicted_class = self.classes[max_idx]
        score = float(probabilities[max_idx])

        return MLPrediction(
            flow_id=flow_id,
            threat_class=predicted_class,
            score=round(score, 4),
            model_version=self.model_version,
            calibrated=False,
        )

    def predict_detailed(
        self,
        record_or_dict: FeatureRecord | dict[str, Any],
        top_k_features: int = 5,
    ) -> dict[str, Any]:
        """
        Run inference with lightweight explainability metrics.

        Provides top influential global features and their values for this flow,
        without violating the strict contract of `predict()` / MLPrediction.

        Returns
        -------
        dict[str, Any]
            Prediction details including top feature values and class probabilities.
        """
        pred = self.predict(record_or_dict)
        vec = extract_feature_vector(record_or_dict)
        feat_map = dict(zip(FEATURE_NAMES, vec, strict=True))

        # Sort features by global importance and extract observed value for this sample
        top_features: list[dict[str, Any]] = []
        for feat_name, importance in sorted(
            self.feature_importances.items(), key=lambda t: t[1], reverse=True
        )[:top_k_features]:
            top_features.append({
                "feature_name": feat_name,
                "importance": importance,
                "observed_value": feat_map.get(feat_name),
            })

        return {
            "prediction": pred.to_contract_dict(),
            "top_features": top_features,
        }
