"""
unithreat.detection.exfiltration
================================

Data exfiltration detection based on abnormal outbound volumes and directional asymmetry.
"""

from __future__ import annotations

from typing import Any

from unithreat.detection.base import BaseDetector
from unithreat.detection.config import ExfiltrationConfig
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


class ExfiltrationDetector(BaseDetector):
    """
    Detects potential data exfiltration via abnormal outbound byte volume and duration.
    """

    def __init__(self, config: ExfiltrationConfig | None = None) -> None:
        self.config = config or ExfiltrationConfig()

    @property
    def threat_class(self) -> str:
        return "DATA_EXFILTRATION"

    def detect(
        self,
        record: FeatureRecord,
        window_manager: BoundedWindowManager | None = None,
    ) -> DetectionResult | None:
        feat = record.features

        direction = feat.get("direction")
        byte_count = int(feat.get("byte_count") or 0)
        duration = float(feat.get("duration") or 0.0)
        bytes_per_sec = float(feat.get("bytes_per_sec") or 0.0)

        # Inbound traffic (e.g. ordinary file downloads) is strictly NOT exfiltration
        if direction == "inbound":
            return None

        # Determine directional byte ratio from window or feature record
        ratio: float | None = None
        feature_ratio = feat.get("outbound_inbound_byte_ratio")
        if feature_ratio is not None:
            try:
                ratio = float(feature_ratio)
            except (ValueError, TypeError):
                ratio = None

        src_ip = feat.get("src_ip")
        if ratio is None and window_manager is not None and src_ip:
            events = window_manager.get_source_history(str(src_ip))
            win_outbound = sum(e.byte_count for e in events if e.direction == "outbound")
            win_inbound = sum(e.byte_count for e in events if e.direction == "inbound")
            if win_inbound > 0:
                ratio = round(win_outbound / win_inbound, 2)
            elif win_outbound > 0 and win_inbound == 0:
                ratio = round(float(win_outbound), 2)

        # If ratio indicates normal balanced bidirectional traffic (inbound is substantial),
        # reject as normal traffic
        if ratio is not None and ratio < 2.0:
            return None

        # Volume constraint
        if byte_count < self.config.min_outbound_bytes:
            return None

        is_sustained = duration >= self.config.min_duration or bytes_per_sec >= self.config.min_outbound_bytes_per_sec
        is_ratio_anomaly = ratio is not None and ratio >= self.config.min_outbound_inbound_ratio

        if not (is_sustained or is_ratio_anomaly):
            return None

        # Build grounded confidence based on volume, duration, and ratio asymmetry
        confidence = 0.60
        if byte_count >= self.config.min_outbound_bytes * 3:
            confidence += 0.15
        elif byte_count >= self.config.min_outbound_bytes * 1.5:
            confidence += 0.08

        if duration >= 10.0:
            confidence += 0.10
        if bytes_per_sec >= self.config.min_outbound_bytes_per_sec * 2:
            confidence += 0.05

        if is_ratio_anomaly and ratio is not None:
            if ratio >= 20.0:
                confidence += 0.10
            else:
                confidence += 0.05

        confidence = min(round(confidence, 2), 0.98)
        if confidence < self.config.confidence_threshold:
            return None

        severity = "HIGH" if (byte_count >= 4_000_000 or (is_ratio_anomaly and byte_count >= 2_000_000)) else "MEDIUM"

        evidence: list[EvidenceSignal] = [
            EvidenceSignal(
                signal_name="large_outbound_volume",
                value=float(byte_count),
                direction="supporting",
                reliability=0.92,
                supporting_features=["byte_count", "direction"],
                threat_class="DATA_EXFILTRATION",
            ),
        ]

        if is_sustained:
            evidence.append(
                EvidenceSignal(
                    signal_name="sustained_transfer",
                    value=float(duration),
                    direction="supporting",
                    reliability=0.88,
                    supporting_features=["duration", "bytes_per_sec"],
                    threat_class="DATA_EXFILTRATION",
                )
            )

        if is_ratio_anomaly and ratio is not None:
            evidence.append(
                EvidenceSignal(
                    signal_name="outbound_inbound_ratio",
                    value=round(float(ratio), 2),
                    direction="supporting",
                    reliability=0.90,
                    supporting_features=["outbound_inbound_byte_ratio", "direction", "byte_count"],
                    threat_class="DATA_EXFILTRATION",
                )
            )

        ratio_desc = f", outbound/inbound ratio={ratio:.1f}" if ratio is not None else ""
        explanation = (
            f"Sustained large-volume outbound data transfer detected from {feat.get('src_ip')}: "
            f"{byte_count:,} bytes transferred over {duration:.1f}s ({bytes_per_sec:,.1f} B/s){ratio_desc}."
        )

        return DetectionResult(
            timestamp=record.timestamp,
            flow_id=record.flow_id,
            threat_class="DATA_EXFILTRATION",
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            detection_method="statistical",
            relevant_features={
                "byte_count": byte_count,
                "duration": duration,
                "bytes_per_sec": bytes_per_sec,
                "direction": direction,
                "outbound_inbound_ratio": ratio,
            },
            source_ip=str(feat.get("src_ip")),
            destination_ip=str(feat.get("dst_ip")),
            protocol=str(feat.get("protocol")),
            explanation=explanation,
        )
