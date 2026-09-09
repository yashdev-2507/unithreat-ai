"""
unithreat.detection.base
=======================

Abstract base detector definition and common utilities.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from unithreat.detection.result import DetectionResult
from unithreat.detection.window import BoundedWindowManager
from unithreat.features.models import FeatureRecord


class BaseDetector(ABC):
    """
    Abstract contract for statistical and behavioral threat detectors.
    """

    @property
    @abstractmethod
    def threat_class(self) -> str:
        """Name of the threat class identified by this detector."""
        ...

    @abstractmethod
    def detect(
        self,
        record: FeatureRecord,
        window_manager: BoundedWindowManager | None = None,
    ) -> DetectionResult | None:
        """
        Analyze a FeatureRecord (optionally leveraging BoundedWindowManager).

        Returns
        -------
        DetectionResult | None
            Detection result with supporting evidence if anomalous behavior
            exceeds configured threshold; None otherwise.
        """
        ...
