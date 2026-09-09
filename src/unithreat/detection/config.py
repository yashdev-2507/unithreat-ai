"""
unithreat.detection.config
=========================

Centralized configuration for statistical and behavioral threat detectors.

All detection thresholds, time-window parameters, and confidence criteria
are centralized here to allow straightforward tuning and experimentation.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class DDoSConfig(BaseModel):
    """Thresholds for volumetric and protocol DDoS detection."""

    min_flow_rate: float = Field(default=30.0, description="Minimum flows/sec targeting destination")
    min_unique_sources: int = Field(default=12, description="Minimum distinct sources targeting destination")
    min_source_entropy: float = Field(default=2.2, description="Minimum source IP Shannon entropy")
    min_packet_rate: float = Field(default=80.0, description="Minimum packets/sec targeting destination")
    syn_ratio_threshold: float = Field(default=0.60, description="Fraction of SYN flows indicating SYN flood")
    udp_ratio_threshold: float = Field(default=0.60, description="Fraction of UDP flows indicating UDP flood")
    confidence_threshold: float = Field(default=0.60, description="Minimum confidence to emit DDoS alert")


class PortScanConfig(BaseModel):
    """Thresholds for reconnaissance and port scanning detection."""

    min_probed_ports: int = Field(default=8, description="Minimum distinct ports contacted by source")
    min_probed_hosts: int = Field(default=8, description="Minimum distinct hosts contacted by source")
    max_probe_bytes: int = Field(default=120, description="Maximum bytes per flow for probe classification")
    max_probe_duration: float = Field(default=0.05, description="Maximum duration (s) for probe classification")
    confidence_threshold: float = Field(default=0.60, description="Minimum confidence to emit scan alert")


class BeaconConfig(BaseModel):
    """Thresholds for C2 beaconing detection."""

    min_connections: int = Field(default=4, description="Minimum repeated connections required for periodicity evaluation")
    max_inter_arrival_cv: float = Field(default=0.25, description="Maximum coefficient of variation of inter-arrival times")
    min_periodicity_score: float = Field(default=0.75, description="Minimum periodicity score (1 - CV)")
    max_byte_count_cv: float = Field(default=0.30, description="Maximum coefficient of variation for byte counts")
    confidence_threshold: float = Field(default=0.60, description="Minimum confidence to emit beacon alert")


class DNSConfig(BaseModel):
    """Thresholds for DGA and DNS tunneling detection."""

    min_query_length: int = Field(default=45, description="Minimum query length for suspicious DNS detection")
    min_entropy: float = Field(default=3.6, description="Minimum Shannon entropy of DNS query string")
    suspicious_record_types: tuple[str, ...] = ("TXT", "NULL")
    min_query_frequency: float = Field(default=4.0, description="Minimum DNS queries/sec from host")
    dga_min_entropy: float = Field(default=3.4, description="Minimum Shannon entropy of DGA domain name")
    dga_max_vowel_ratio: float = Field(default=0.18, description="Maximum vowel ratio indicative of DGA")
    dga_min_consonant_run: int = Field(default=4, description="Minimum consecutive consonants indicative of DGA")
    dga_max_ngram_score: float = Field(default=0.20, description="Maximum common bigram ratio indicative of DGA")
    confidence_threshold: float = Field(default=0.60, description="Minimum confidence to emit DNS alert")


class ExfiltrationConfig(BaseModel):
    """Thresholds for data exfiltration detection."""

    min_outbound_bytes: int = Field(default=800_000, description="Minimum outbound bytes indicating bulk transfer")
    min_outbound_bytes_per_sec: float = Field(default=20_000.0, description="Minimum outbound transfer rate")
    min_duration: float = Field(default=5.0, description="Minimum transfer duration in seconds")
    min_outbound_inbound_ratio: float = Field(default=5.0, description="Minimum ratio of outbound to inbound bytes")
    confidence_threshold: float = Field(default=0.60, description="Minimum confidence to emit exfiltration alert")


class EncryptedConfig(BaseModel):
    """Thresholds for metadata-based encrypted session anomaly detection."""

    obsolete_tls_versions: tuple[str, ...] = ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
    obsolete_quic_versions: tuple[str, ...] = ("Q035", "Q039", "Q043", "Q044", "Q046", "draft-29")
    suspicious_ja3_hashes: tuple[str, ...] = (
        "a0e9f5d64349fb13191bc781f81f42e1",
        "6523955681710972a912da05b766ad63",
        "72a589da586844d7f0818ce684948eea",
        "b32309a26951912be7dba376398abc3b",
    )
    insecure_ciphers: tuple[str, ...] = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")
    flag_direct_ip_sni: bool = Field(default=True, description="Flag sessions using direct IPv4 address as SNI")
    max_keystroke_bpp: float = Field(default=65.0, description="Maximum bytes/packet for interactive keystroke tunnel anomaly")
    min_keystroke_packets: int = Field(default=20, description="Minimum packets for interactive keystroke tunnel anomaly")
    confidence_threshold: float = Field(default=0.60, description="Minimum confidence to emit anomaly alert")


class WindowConfig(BaseModel):
    """Parameters for bounded sliding temporal windows."""

    window_duration_seconds: float = Field(default=60.0, description="Sliding window duration in seconds")
    max_events_per_entity: int = Field(default=200, description="Maximum stored events per tracked entity")
    max_tracked_entities: int = Field(default=10_000, description="Maximum number of active tracked entities")


class DetectionConfig(BaseModel):
    """Top-level configuration for the detection engine and all detectors."""

    ddos: DDoSConfig = Field(default_factory=DDoSConfig)
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    beacon: BeaconConfig = Field(default_factory=BeaconConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    exfiltration: ExfiltrationConfig = Field(default_factory=ExfiltrationConfig)
    encrypted: EncryptedConfig = Field(default_factory=EncryptedConfig)
    window: WindowConfig = Field(default_factory=WindowConfig)
