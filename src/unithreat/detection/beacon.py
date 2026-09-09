"""
unithreat.detection.beacon
==========================

Command-and-control (C2) beaconing detection based on inter-arrival regularity.
"""

from __future__ import annotations

import math
from typing import Any

from unithreat.detection.base import BaseDetector
from unithreat.detection.config import BeaconConfig
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


class C2BeaconDetector(BaseDetector):
    """
    Detects periodic beaconing behavior between host pairs using timing variance.
    """

    def __init__(self, config: BeaconConfig | None = None) -> None:
        self.config = config or BeaconConfig()

    @property
    def threat_class(self) -> str:
        return "C2_BEACONING"

    def detect(
        self,
        record: FeatureRecord,
        window_manager: BoundedWindowManager | None = None,
    ) -> DetectionResult | None:
        feat = record.features
        src_ip = feat.get("src_ip")
        dst_ip = feat.get("dst_ip")

        if not src_ip or not dst_ip or not window_manager:
            return None

        events = window_manager.get_pair_history(str(src_ip), str(dst_ip))
        if len(events) < self.config.min_connections:
            return None

        # Calculate inter-arrival intervals
        timestamps = [e.timestamp for e in events]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:], strict=True)]

        # Must have positive intervals and not be instantaneous bulk downloads
        if not intervals or any(i <= 0.0 for i in intervals):
            return None

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1.0:
            # Sub-second bursts are typically web assets, not periodic beacon heartbeats
            return None

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_interval = math.sqrt(variance)
        cv_interval = std_interval / mean_interval
        periodicity_score = max(0.0, 1.0 - cv_interval)

        if cv_interval > self.config.max_inter_arrival_cv:
            return None

        if periodicity_score < self.config.min_periodicity_score:
            return None

        # Check byte consistency
        byte_counts = [e.byte_count for e in events]
        mean_bytes = sum(byte_counts) / len(byte_counts)
        byte_var = sum((b - mean_bytes) ** 2 for b in byte_counts) / len(byte_counts)
        cv_bytes = math.sqrt(byte_var) / max(mean_bytes, 1.0)

        # Grounded confidence scoring based on timing regularity
        if cv_interval < 0.05:
            base_conf = 0.94
        elif cv_interval < 0.10:
            base_conf = 0.88
        elif cv_interval < 0.18:
            base_conf = 0.80
        else:
            base_conf = 0.70

        if cv_bytes <= self.config.max_byte_count_cv:
            base_conf += 0.05

        confidence = min(round(base_conf, 2), 0.98)
        if confidence < self.config.confidence_threshold:
            return None

        severity = "HIGH" if (len(events) >= 6 and cv_interval < 0.12) else "MEDIUM"

        evidence: list[EvidenceSignal] = [
            EvidenceSignal(
                signal_name="temporal_periodicity",
                value=round(periodicity_score, 4),
                direction="supporting",
                reliability=0.94,
                supporting_features=["timestamp", "duration"],
                threat_class="C2_BEACONING",
            ),
            EvidenceSignal(
                signal_name="connection_repetition",
                value=float(len(events)),
                direction="supporting",
                reliability=0.90,
                supporting_features=["src_ip", "dst_ip", "dst_port"],
                threat_class="C2_BEACONING",
            ),
        ]

        if cv_bytes <= self.config.max_byte_count_cv:
            evidence.append(
                EvidenceSignal(
                    signal_name="payload_size_consistency",
                    value=round(1.0 - cv_bytes, 4),
                    direction="supporting",
                    reliability=0.86,
                    supporting_features=["byte_count"],
                    threat_class="C2_BEACONING",
                )
            )

        explanation = (
            f"Periodic beaconing pattern detected between {src_ip} and {dst_ip}: {len(events)} connections "
            f"with mean interval {mean_interval:.2f}s and high periodicity score {periodicity_score:.3f} (CV={cv_interval:.3f})."
        )

        return DetectionResult(
            timestamp=record.timestamp,
            flow_id=record.flow_id,
            threat_class="C2_BEACONING",
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            detection_method="behavioral",
            relevant_features={
                "connection_count": len(events),
                "mean_interval_sec": round(mean_interval, 3),
                "inter_arrival_cv": round(cv_interval, 4),
                "periodicity_score": round(periodicity_score, 4),
                "byte_count_cv": round(cv_bytes, 4),
            },
            source_ip=str(src_ip),
            destination_ip=str(dst_ip),
            protocol=str(feat.get("protocol")),
            explanation=explanation,
        )
