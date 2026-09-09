"""
unithreat.detection.result
=========================

Standardized detection result and evidence data models.

Strictly aligned with:
  - contracts/evidence-schema.json (EvidenceSignal)
  - contracts/alert-schema.json (DetectionResult.to_alert_dict)
"""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


class EvidenceSignal(BaseModel):
    """
    Threat evidence signal conforming to contracts/evidence-schema.json.
    """

    model_config = {"frozen": True}

    signal_name: str
    value: float
    direction: Literal["supporting", "contradicting", "neutral"] = "supporting"
    reliability: float = Field(ge=0.0, le=1.0)
    supporting_features: list[str]
    threat_class: str | None = None

    def to_contract_dict(self) -> dict[str, Any]:
        """Convert to dict matching contracts/evidence-schema.json exactly."""
        d: dict[str, Any] = {
            "signal_name": self.signal_name,
            "value": float(self.value),
            "direction": self.direction,
            "reliability": float(self.reliability),
            "supporting_features": list(self.supporting_features),
        }
        if self.threat_class is not None:
            d["threat_class"] = self.threat_class
        return d


class DetectionResult(BaseModel):
    """
    Result produced by a threat detector.

    Can be converted directly to an alert dictionary matching contracts/alert-schema.json.
    """

    model_config = {"frozen": True}

    timestamp: str
    flow_id: str
    threat_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    evidence: list[EvidenceSignal]
    detection_method: str = "statistical"
    relevant_features: dict[str, Any] = Field(default_factory=dict)
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    model_version: str | None = "statistical-v1"
    explanation: str | None = None

    def to_alert_dict(self) -> dict[str, Any]:
        """
        Produce a dictionary that validates strictly against contracts/alert-schema.json.
        """
        alert: dict[str, Any] = {
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "threat_class": self.threat_class,
            "confidence": round(float(self.confidence), 4),
            "severity": self.severity,
            "evidence": [ev.to_contract_dict() for ev in self.evidence],
        }

        if self.source_ip is not None:
            alert["source_ip"] = self.source_ip
        if self.destination_ip is not None:
            alert["destination_ip"] = self.destination_ip
        if self.protocol is not None:
            alert["protocol"] = self.protocol
        if self.model_version is not None:
            alert["model_version"] = self.model_version
        if self.explanation is not None:
            alert["explanation"] = self.explanation

        return alert
