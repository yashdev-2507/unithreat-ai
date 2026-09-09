"""
unithreat.ml.models
===================

Data models for ML inference and prediction results.

Strictly aligned with contracts/ml-prediction-schema.json:
  - flow_id: string (required)
  - threat_class: string (required)
  - score: number between 0 and 1 (required)
  - model_version: string (required)
  - calibrated: boolean (optional)
  - additionalProperties: false
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class MLPrediction(BaseModel):
    """
    ML model prediction result conforming strictly to contracts/ml-prediction-schema.json.
    
    Note: 'score' represents the raw uncalibrated classifier confidence index
    (e.g., ensemble tree voting ratio), NOT an empirically calibrated probability.
    'calibrated' is set to False accordingly.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    flow_id: str
    threat_class: str
    score: float = Field(ge=0.0, le=1.0)
    model_version: str
    calibrated: bool = False

    def to_contract_dict(self) -> dict[str, Any]:
        """
        Produce a dictionary that validates strictly against contracts/ml-prediction-schema.json.
        """
        return {
            "flow_id": self.flow_id,
            "threat_class": self.threat_class,
            "score": round(float(self.score), 4),
            "model_version": self.model_version,
            "calibrated": self.calibrated,
        }
