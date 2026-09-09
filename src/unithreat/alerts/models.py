"""
unithreat.alerts.models
=======================

Standardized threat alert model conforming strictly to contracts/alert-schema.json.
"""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field

from unithreat.detection.result import EvidenceSignal


class ThreatAlert(BaseModel):
    """
    Standardized threat alert model.

    Strictly mirrors contracts/alert-schema.json:
      - timestamp: string (date-time format)
      - flow_id: string
      - threat_class: string
      - confidence: number between 0 and 1
      - severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
      - evidence: array of items matching contracts/evidence-schema.json
      - source_ip: string | null (optional)
      - destination_ip: string | null (optional)
      - protocol: string | null (optional)
      - model_version: string | null (optional)
      - explanation: string | null (optional)
      - additionalProperties: false
    """

    model_config = {"frozen": True, "extra": "forbid"}

    timestamp: str
    flow_id: str
    threat_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    evidence: list[EvidenceSignal]
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    model_version: str | None = None
    explanation: str | None = None

    def to_contract_dict(self) -> dict[str, Any]:
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
