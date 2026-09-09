"""
unithreat.detection.ddos
========================

Volumetric and protocol DDoS detection based on destination-aggregated metrics.
"""

from __future__ import annotations

from collections import Counter
import math
from typing import Any

from unithreat.detection.base import BaseDetector
from unithreat.detection.config import DDoSConfig
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


class DDoSDetector(BaseDetector):
    """
    Detects volumetric, SYN-flood, and UDP-flood denial-of-service traffic.
    """

    def __init__(self, config: DDoSConfig | None = None) -> None:
        self.config = config or DDoSConfig()

    @property
    def threat_class(self) -> str:
        return "DDOS"

    def detect(
        self,
        record: FeatureRecord,
        window_manager: BoundedWindowManager | None = None,
    ) -> DetectionResult | None:
        feat = record.features
        dst_ip = feat.get("dst_ip")
        if not dst_ip or not window_manager:
            return None

        events = window_manager.get_destination_history(str(dst_ip))
        if len(events) < 5:
            return None

        # Calculate time span and rates across observed window
        span = max(events[-1].timestamp - events[0].timestamp, 0.01)
        flow_rate = round(len(events) / span, 2)
        total_packets = sum(e.packet_count for e in events)
        packet_rate = round(total_packets / span, 2)

        unique_sources = len({e.src_ip for e in events})
        src_counts = Counter(e.src_ip for e in events)
        total_ev = len(events)
        source_entropy = round(
            -sum((c / total_ev) * math.log2(c / total_ev) for c in src_counts.values()), 3
        )

        syn_count = sum(1 for e in events if e.is_syn)
        udp_count = sum(1 for e in events if e.is_udp)
        syn_ratio = round(syn_count / total_ev, 3)
        udp_ratio = round(udp_count / total_ev, 3)

        # Evaluate detection conditions
        is_rate_abnormal = (
            flow_rate >= self.config.min_flow_rate
            or packet_rate >= self.config.min_packet_rate
        )
        is_source_distributed = (
            unique_sources >= self.config.min_unique_sources
            or source_entropy >= self.config.min_source_entropy
        )
        is_protocol_skewed = (
            syn_ratio >= self.config.syn_ratio_threshold
            or udp_ratio >= self.config.udp_ratio_threshold
        )

        # Single source is reconnaissance/probing, not a distributed flood
        if unique_sources < 3:
            return None

        if not (is_rate_abnormal and (is_source_distributed or is_protocol_skewed)):
            return None

        # Build confidence score grounded in signal strengths
        confidence = 0.50
        if flow_rate >= self.config.min_flow_rate * 2:
            confidence += 0.20
        elif flow_rate >= self.config.min_flow_rate:
            confidence += 0.10

        if unique_sources >= self.config.min_unique_sources:
            confidence += 0.15
        if source_entropy >= self.config.min_source_entropy:
            confidence += 0.10
        if is_protocol_skewed:
            confidence += 0.15

        confidence = min(round(confidence, 2), 0.99)
        if confidence < self.config.confidence_threshold:
            return None

        # Determine severity
        if flow_rate > 200 or packet_rate > 2000 or unique_sources > 50:
            severity = "CRITICAL"
        elif flow_rate > 60 or unique_sources > 20:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        evidence: list[EvidenceSignal] = [
            EvidenceSignal(
                signal_name="high_flow_rate",
                value=flow_rate,
                direction="supporting",
                reliability=0.92,
                supporting_features=["packets_per_sec", "bytes_per_sec"],
                threat_class="DDOS",
            ),
            EvidenceSignal(
                signal_name="source_ip_diversity",
                value=float(unique_sources),
                direction="supporting",
                reliability=0.88,
                supporting_features=["src_ip"],
                threat_class="DDOS",
            ),
            EvidenceSignal(
                signal_name="destination_concentration",
                value=float(total_ev),
                direction="supporting",
                reliability=0.91,
                supporting_features=["dst_ip"],
                threat_class="DDOS",
            ),
        ]

        if source_entropy >= self.config.min_source_entropy:
            evidence.append(
                EvidenceSignal(
                    signal_name="distributed_source_diversity",
                    value=source_entropy,
                    direction="supporting",
                    reliability=0.88,
                    supporting_features=["src_ip"],
                    threat_class="DDOS",
                )
            )

        if is_protocol_skewed:
            proto_val = syn_ratio if syn_ratio >= self.config.syn_ratio_threshold else udp_ratio
            sig_name = "syn_flood_pattern" if syn_ratio >= self.config.syn_ratio_threshold else "udp_flood_pattern"
            evidence.append(
                EvidenceSignal(
                    signal_name=sig_name,
                    value=proto_val,
                    direction="supporting",
                    reliability=0.90,
                    supporting_features=["tcp_flags", "protocol"],
                    threat_class="DDOS",
                )
            )

        return DetectionResult(
            timestamp=record.timestamp,
            flow_id=record.flow_id,
            threat_class="DDOS",
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            detection_method="statistical",
            relevant_features={
                "flow_rate": flow_rate,
                "packet_rate": packet_rate,
                "unique_sources": unique_sources,
                "source_entropy": source_entropy,
                "syn_ratio": syn_ratio,
                "udp_ratio": udp_ratio,
                "destination_concentration_events": total_ev,
            },
            source_ip=str(feat.get("src_ip")),
            destination_ip=str(dst_ip),
            protocol=str(feat.get("protocol")),
            explanation=(
                f"Volumetric flood targeting {dst_ip} detected with {flow_rate} flows/sec, "
                f"distributed/spoofing-like source diversity ({unique_sources} distinct sources, source entropy={source_entropy} bits), "
                f"and protocol concentration (SYN={syn_ratio}, UDP={udp_ratio}). (Passive metadata observation; not confirmed spoofing.)"
            ),
        )
