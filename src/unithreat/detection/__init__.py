"""
unithreat.detection
===================

Threat detection package for UniThreat AI.

Statistical and behavioral threat detection across the six core SIH threat classes:
  - DDoS (volumetric and protocol floods)
  - Reconnaissance (port scanning and host sweeps)
  - Botnet C2 Beaconing (periodic timing regularity)
  - DNS Tunneling and DGA (entropy, length, anomalous queries)
  - Data Exfiltration (bulk outbound asymmetry and volume)
  - Encrypted Session Anomaly (passive TLS/QUIC metadata characteristics)
"""

from unithreat.detection.base import BaseDetector
from unithreat.detection.beacon import C2BeaconDetector
from unithreat.detection.config import (
    BeaconConfig,
    DDoSConfig,
    DetectionConfig,
    DNSConfig,
    EncryptedConfig,
    ExfiltrationConfig,
    PortScanConfig,
    WindowConfig,
)
from unithreat.detection.ddos import DDoSDetector
from unithreat.detection.dns import DNSDetector
from unithreat.detection.encrypted import EncryptedSessionDetector
from unithreat.detection.engine import DetectionEngine
from unithreat.detection.exfiltration import ExfiltrationDetector
from unithreat.detection.port_scan import PortScanDetector
from unithreat.detection.result import DetectionResult, EvidenceSignal
from unithreat.detection.window import BoundedWindowManager

__all__ = [
    "BaseDetector",
    "BeaconConfig",
    "BoundedWindowManager",
    "C2BeaconDetector",
    "DDoSConfig",
    "DDoSDetector",
    "DNSConfig",
    "DNSDetector",
    "DetectionConfig",
    "DetectionEngine",
    "DetectionResult",
    "EncryptedConfig",
    "EncryptedSessionDetector",
    "EvidenceSignal",
    "ExfiltrationConfig",
    "ExfiltrationDetector",
    "PortScanConfig",
    "PortScanDetector",
    "WindowConfig",
]
