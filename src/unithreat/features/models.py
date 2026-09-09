"""
unithreat.features.models
=========================

Data models for normalized feature records.

The schema is strictly governed by contracts/feature-schema.json.
This module must stay in sync with that contract.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class FeatureRecord(BaseModel):
    """
    Normalized network feature record.

    Mirrors contracts/feature-schema.json exactly:
      - flow_id: string (required)
      - timestamp: ISO 8601 date-time string (required)
      - entity_id: string or null (optional)
      - window_id: string or null (optional)
      - features: dict of string -> (number | string | boolean | null) (required)
    """

    model_config = {"frozen": True}

    flow_id: str
    timestamp: str
    entity_id: str | None = None
    window_id: str | None = None
    features: dict[str, float | int | str | bool | None] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, v: object) -> str:
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if isinstance(v, str):
            return v
        raise ValueError(f"Invalid timestamp format: {v!r}")
