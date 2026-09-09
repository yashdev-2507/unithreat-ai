"""
unithreat.detection.engine
=========================

Threat detection engine orchestrating statistical and behavioral detectors.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Sequence

from unithreat.detection.base import BaseDetector
from unithreat.detection.beacon import C2BeaconDetector
from unithreat.detection.config import DetectionConfig
from unithreat.detection.ddos import DDoSDetector
from unithreat.detection.dns import DNSDetector
from unithreat.detection.encrypted import EncryptedSessionDetector
from unithreat.detection.exfiltration import ExfiltrationDetector
from unithreat.detection.port_scan import PortScanDetector
from unithreat.detection.result import DetectionResult
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.extractor import FeatureExtractor
from unithreat.features.models import FeatureRecord
from unithreat.ingest.models import Flow


class DetectionEngine:
    """
    Core threat detection engine running registered statistical/behavioral detectors.
    """

    def __init__(
        self,
        config: DetectionConfig | None = None,
        detectors: Sequence[BaseDetector] | None = None,
    ) -> None:
        self.config = config or DetectionConfig()
        self.window_manager = BoundedWindowManager(config=self.config.window)
        self.extractor = FeatureExtractor()

        if detectors is not None:
            self.detectors = list(detectors)
        else:
            # Default suite of all six statistical and behavioral detectors
            self.detectors = [
                DDoSDetector(config=self.config.ddos),
                PortScanDetector(config=self.config.port_scan),
                C2BeaconDetector(config=self.config.beacon),
                DNSDetector(config=self.config.dns),
                ExfiltrationDetector(config=self.config.exfiltration),
                EncryptedSessionDetector(config=self.config.encrypted),
            ]

    def register_detector(self, detector: BaseDetector) -> None:
        """Register an additional detector to the engine."""
        self.detectors.append(detector)

    def process(self, record: FeatureRecord) -> list[DetectionResult]:
        """
        Process a normalized FeatureRecord through the window manager and detectors.

        Returns
        -------
        list[DetectionResult]
            Any detected threat results for the current flow/window.
        """
        # 1. Incrementally update bounded sliding windows
        self.window_manager.update(record)

        # 2. Evaluate all registered detectors
        results: list[DetectionResult] = []
        for detector in self.detectors:
            try:
                res = detector.detect(record, window_manager=self.window_manager)
                if res is not None:
                    results.append(res)
            except Exception:
                # Keep processing remaining detectors if one raises an error on malformed data
                continue

        return results

    def process_flow(self, flow: Flow) -> list[DetectionResult]:
        """
        Convenience end-to-end method: extracts features from Flow and detects threats.
        """
        record = self.extractor.extract(flow)
        return self.process(record)

    def process_stream(
        self,
        stream: Iterable[Flow | FeatureRecord],
    ) -> Iterator[DetectionResult]:
        """
        Incremental generator processing an incoming stream of Flows or FeatureRecords.
        """
        for item in stream:
            if isinstance(item, FeatureRecord):
                for res in self.process(item):
                    yield res
            else:
                for res in self.process_flow(item):
                    yield res
