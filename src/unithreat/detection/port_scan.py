"""
unithreat.detection.port_scan
=============================

Reconnaissance and port scanning detection based on source-aggregated fan-out.
"""

from __future__ import annotations

from typing import Any

from unithreat.detection.base import BaseDetector
from unithreat.detection.config import PortScanConfig
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


class PortScanDetector(BaseDetector):
    """
    Detects vertical port scans and horizontal host sweeps within a bounded window.
    """

    def __init__(self, config: PortScanConfig | None = None) -> None:
        self.config = config or PortScanConfig()

    @property
    def threat_class(self) -> str:
        return "RECONNAISSANCE"

    def detect(
        self,
        record: FeatureRecord,
        window_manager: BoundedWindowManager | None = None,
    ) -> DetectionResult | None:
        feat = record.features
        src_ip = feat.get("src_ip")
        if not src_ip or not window_manager:
            return None

        events = window_manager.get_source_history(str(src_ip))
        if len(events) < min(self.config.min_probed_ports, self.config.min_probed_hosts):
            return None

        probed_ports = {e.dst_port for e in events if e.dst_port is not None}
        probed_hosts = {e.dst_ip for e in events if e.dst_ip}

        is_vertical = len(probed_ports) >= self.config.min_probed_ports
        is_horizontal = len(probed_hosts) >= self.config.min_probed_hosts

        if not (is_vertical or is_horizontal):
            return None

        # Check for typical lightweight probe patterns (short duration, low byte count)
        total_ev = len(events)
        probe_flows = sum(
            1
            for e in events
            if e.duration <= self.config.max_probe_duration
            and e.byte_count <= self.config.max_probe_bytes
        )
        probe_ratio = round(probe_flows / total_ev, 3)

        # Grounded confidence calculation
        max_dimension = max(len(probed_ports), len(probed_hosts))
        base_conf = 0.60
        diversity_boost = min(0.25, (max_dimension - 8) * 0.015)
        pattern_boost = 0.10 if probe_ratio >= 0.70 else 0.0

        confidence = min(round(base_conf + diversity_boost + pattern_boost, 2), 0.98)
        if confidence < self.config.confidence_threshold:
            return None

        severity = "HIGH" if max_dimension >= 25 else "MEDIUM"

        evidence: list[EvidenceSignal] = []
        if is_vertical:
            evidence.append(
                EvidenceSignal(
                    signal_name="port_fan_out",
                    value=float(len(probed_ports)),
                    direction="supporting",
                    reliability=0.92,
                    supporting_features=["dst_port"],
                    threat_class="RECONNAISSANCE",
                )
            )

        if is_horizontal:
            evidence.append(
                EvidenceSignal(
                    signal_name="host_sweep",
                    value=float(len(probed_hosts)),
                    direction="supporting",
                    reliability=0.90,
                    supporting_features=["dst_ip"],
                    threat_class="RECONNAISSANCE",
                )
            )

        if probe_ratio >= 0.50:
            evidence.append(
                EvidenceSignal(
                    signal_name="syn_probe_pattern",
                    value=probe_ratio,
                    direction="supporting",
                    reliability=0.85,
                    supporting_features=["duration", "byte_count", "tcp_flags"],
                    threat_class="RECONNAISSANCE",
                )
            )

        explanation = (
            f"Reconnaissance behavior from {src_ip}: contacted {len(probed_ports)} distinct ports "
            f"across {len(probed_hosts)} destination hosts with {probe_ratio * 100:.1f}% probe-like flows."
        )

        return DetectionResult(
            timestamp=record.timestamp,
            flow_id=record.flow_id,
            threat_class="RECONNAISSANCE",
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            detection_method="statistical",
            relevant_features={
                "probed_ports_count": len(probed_ports),
                "probed_hosts_count": len(probed_hosts),
                "probe_ratio": probe_ratio,
                "total_events": total_ev,
            },
            source_ip=str(src_ip),
            destination_ip=str(feat.get("dst_ip")),
            protocol=str(feat.get("protocol")),
            explanation=explanation,
        )
