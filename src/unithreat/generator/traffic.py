"""
unithreat.generator.traffic
===========================

Synthetic network flow event generator for testing and demonstration.

This module produces realistic, schema-compliant passive flow records for
evaluating the UniThreat detection pipeline across multiple threat scenarios:
  - benign: Normal background network traffic
  - ddos: Volumetric flood concentrated against target infrastructure
  - port_scan: Scanning probes across multiple destination ports/hosts
  - c2_beacon: Highly periodic outbound beaconing to an external C2 node
  - dns_tunnel: High-frequency, high-entropy DNS queries with data encapsulation
  - exfiltration: Large-volume, sustained outbound data transfers

Every generated record strictly adheres to contracts/flow-schema.json.
This generator is strictly for development and testing; it does NOT communicate
with real networks.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import random
from typing import Any, Iterator

VALID_SCENARIOS = (
    "benign",
    "ddos",
    "port_scan",
    "c2_beacon",
    "dns_tunnel",
    "exfiltration",
    "dga",
    "encrypted_anomaly",
)

# Base start time for synthetic flows (deterministic reference)
DEFAULT_START_TIME = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)


def _format_timestamp(dt: datetime) -> str:
    """Format datetime as ISO 8601 string conforming to date-time format."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TrafficGenerator:
    """
    Stateful traffic generator supporting deterministic scenario replay.
    """

    def __init__(
        self,
        scenario: str,
        seed: int | None = None,
        start_time: datetime | None = None,
    ) -> None:
        if scenario not in VALID_SCENARIOS:
            raise ValueError(
                f"Invalid scenario '{scenario}'. Supported scenarios: {list(VALID_SCENARIOS)}"
            )

        self.scenario = scenario
        self.rng = random.Random(seed)
        self.current_time = start_time or DEFAULT_START_TIME

    def generate(self, count: int) -> Iterator[dict[str, Any]]:
        """
        Generate `count` flow records for the configured scenario.
        """
        if not isinstance(count, int) or count <= 0:
            raise ValueError("Count must be an integer greater than 0.")

        handler = getattr(self, f"_generate_{self.scenario}")
        for idx in range(1, count + 1):
            yield handler(idx)

    def _generate_benign(self, idx: int) -> dict[str, Any]:
        delta_sec = self.rng.uniform(0.05, 1.2)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        flow_type = self.rng.choices(
            ["https", "http", "dns", "internal", "ntp"],
            weights=[50, 15, 20, 10, 5],
        )[0]

        src_ip = f"192.168.1.{self.rng.randint(10, 150)}"
        src_port = self.rng.randint(1024, 65535)

        if flow_type == "https":
            dst_ip = self.rng.choice(["142.250.190.46", "93.184.216.34", "151.101.1.140", "104.16.132.229"])
            dst_port = 443
            protocol = "TCP"
            direction = "outbound"
            duration = round(self.rng.uniform(0.2, 8.0), 4)
            packet_count = self.rng.randint(12, 60)
            byte_count = self.rng.randint(2500, 45000)
            tcp_flags = "ACK-PSH"
            tls: dict[str, Any] | None = {
                "version": "TLS 1.3",
                "sni": self.rng.choice(["api.github.com", "cdn.jsdelivr.net", "fonts.googleapis.com", "login.microsoft.com"]),
            }
            dns = None

        elif flow_type == "http":
            dst_ip = self.rng.choice(["93.184.216.34", "151.101.1.140", "185.199.108.153"])
            dst_port = 80
            protocol = "TCP"
            direction = "outbound"
            duration = round(self.rng.uniform(0.1, 3.5), 4)
            packet_count = self.rng.randint(8, 25)
            byte_count = self.rng.randint(900, 12000)
            tcp_flags = "ACK-PSH"
            tls = None
            dns = None

        elif flow_type == "dns":
            dst_ip = self.rng.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"])
            dst_port = 53
            protocol = "UDP"
            direction = "outbound"
            duration = round(self.rng.uniform(0.01, 0.08), 4)
            packet_count = 2
            byte_count = self.rng.randint(110, 380)
            tcp_flags = None
            tls = None
            dns = {
                "query": self.rng.choice(["updates.ubuntu.com", "slack.com", "api.github.com", "wikipedia.org"]),
                "qtype": "A",
                "rcode": "NOERROR",
            }

        elif flow_type == "internal":
            dst_ip = f"192.168.1.{self.rng.choice([5, 20, 25, 30])}"
            dst_port = self.rng.choice([22, 445, 8080])
            protocol = "TCP"
            direction = "internal"
            duration = round(self.rng.uniform(0.5, 15.0), 4)
            packet_count = self.rng.randint(15, 80)
            byte_count = self.rng.randint(1800, 32000)
            tcp_flags = "ACK-PSH"
            tls = None
            dns = None

        else:  # ntp
            dst_ip = "129.6.15.28"
            dst_port = 123
            protocol = "UDP"
            direction = "outbound"
            duration = 0.005
            packet_count = 2
            byte_count = 96
            tcp_flags = None
            tls = None
            dns = None

        return {
            "flow_id": f"benign-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "direction": direction,
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "tcp_flags": tcp_flags,
            "dns": dns,
            "tls": tls,
            "quic": None,
        }

    def _generate_ddos(self, idx: int) -> dict[str, Any]:
        # High flow rate: tiny timestamp increments
        delta_sec = self.rng.uniform(0.0005, 0.004)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        target_ip = "10.0.0.50"
        src_ip = f"{self.rng.randint(11, 220)}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"
        src_port = self.rng.randint(1024, 65535)

        is_syn = self.rng.random() < 0.70
        if is_syn:
            protocol = "TCP"
            dst_port = self.rng.choice([80, 443])
            tcp_flags = "SYN"
            duration = round(self.rng.uniform(0.0001, 0.02), 4)
            packet_count = self.rng.randint(1, 3)
            byte_count = self.rng.randint(40, 180)
        else:
            protocol = "UDP"
            dst_port = self.rng.choice([53, 123, 80, 443, self.rng.randint(10000, 60000)])
            tcp_flags = None
            duration = round(self.rng.uniform(0.0, 0.01), 4)
            packet_count = self.rng.randint(1, 5)
            byte_count = self.rng.randint(512, 1420)

        return {
            "flow_id": f"ddos-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": src_ip,
            "dst_ip": target_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "direction": "inbound",
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "tcp_flags": tcp_flags,
            "dns": None,
            "tls": None,
            "quic": None,
        }

    def _generate_port_scan(self, idx: int) -> dict[str, Any]:
        # Rapid scanning probes from a single scanner host
        delta_sec = self.rng.uniform(0.005, 0.025)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        scanner_ip = "192.168.1.105"
        target_ip = "192.168.1.50"

        # Common scanned port list mixed with sequential ports
        scan_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
            445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443,
        ]
        if idx <= len(scan_ports):
            dst_port = scan_ports[idx - 1]
        else:
            dst_port = self.rng.randint(1, 1024)

        return {
            "flow_id": f"portscan-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": self.rng.randint(40000, 65535),
            "dst_port": dst_port,
            "protocol": "TCP",
            "direction": "internal",
            "duration": round(self.rng.uniform(0.0002, 0.015), 4),
            "packet_count": 1,
            "byte_count": self.rng.choice([40, 44, 52, 60]),
            "tcp_flags": "SYN",
            "dns": None,
            "tls": None,
            "quic": None,
        }

    def _generate_c2_beacon(self, idx: int) -> dict[str, Any]:
        # Highly periodic beaconing (e.g. 30s interval with subtle jitter)
        jitter = self.rng.gauss(0.0, 0.4)
        delta_sec = max(1.0, 30.0 + jitter)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        compromised_host = "192.168.1.42"
        c2_server = "198.51.100.25"

        return {
            "flow_id": f"c2-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": compromised_host,
            "dst_ip": c2_server,
            "src_port": 49821,
            "dst_port": 443,
            "protocol": "TCP",
            "direction": "outbound",
            "duration": round(self.rng.uniform(0.22, 0.28), 4),
            "packet_count": self.rng.choice([6, 8]),
            "byte_count": self.rng.choice([512, 528, 544]),
            "tcp_flags": "ACK-PSH",
            "dns": None,
            "tls": {
                "version": "TLS 1.3",
                "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
                "sni": "telemetry-sync.cloud-api.net",
            },
            "quic": None,
        }

    def _generate_dns_tunnel(self, idx: int) -> dict[str, Any]:
        # High frequency DNS queries with encoded payload subdomains
        delta_sec = self.rng.uniform(0.04, 0.18)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        src_ip = "192.168.1.88"
        dst_ip = "8.8.8.8"

        # Long, high-entropy encoded subdomain (e.g. base32/hex data)
        payload_chunk = "".join(self.rng.choices("0123456789abcdef", k=48))
        query = f"{payload_chunk}.tunnel.data-exfil.org"

        return {
            "flow_id": f"dnstunnel-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": self.rng.randint(30000, 65535),
            "dst_port": 53,
            "protocol": "UDP",
            "direction": "outbound",
            "duration": round(self.rng.uniform(0.015, 0.09), 4),
            "packet_count": self.rng.choice([2, 4]),
            "byte_count": self.rng.randint(480, 1380),
            "tcp_flags": None,
            "dns": {
                "query": query,
                "qtype": "TXT",
                "rcode": "NOERROR",
                "query_length": len(query),
            },
            "tls": None,
            "quic": None,
        }

    def _generate_exfiltration(self, idx: int) -> dict[str, Any]:
        # Sustained, heavy outbound data transfer
        delta_sec = self.rng.uniform(2.0, 6.0)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        src_ip = "192.168.1.77"
        dst_ip = "203.0.113.88"

        byte_count = self.rng.randint(1_200_000, 8_500_000)
        packet_count = byte_count // self.rng.randint(1300, 1460)
        duration = round(self.rng.uniform(12.0, 48.0), 4)

        return {
            "flow_id": f"exfil-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": self.rng.randint(40000, 65535),
            "dst_port": 443,
            "protocol": "TCP",
            "direction": "outbound",
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "tcp_flags": "ACK-PSH",
            "dns": None,
            "tls": {
                "version": "TLS 1.3",
                "sni": "vault-storage.cloud-sync.com",
            },
            "quic": None,
        }

    def _generate_dga(self, idx: int) -> dict[str, Any]:
        delta_sec = self.rng.uniform(0.1, 1.2)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        src_ip = f"192.168.1.{self.rng.choice([33, 44, 55, 66, 77])}"
        dst_ip = self.rng.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9"])

        # Varied algorithmic domain generation with high consonant ratio, varied length, and varied TLDs
        domain_len = self.rng.randint(13, 23)
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"
        digits = "0123456789"
        
        # Compose core label with high consonant concentration and varied runs
        core_chars = []
        for _ in range(domain_len):
            roll = self.rng.random()
            if roll < 0.78:
                core_chars.append(self.rng.choice(consonants))
            elif roll < 0.90:
                core_chars.append(self.rng.choice(vowels))
            else:
                core_chars.append(self.rng.choice(digits))
        core_label = "".join(core_chars)

        tld = self.rng.choice(["biz", "info", "net", "org", "cc", "top", "xyz", "club"])
        qtype = self.rng.choices(["A", "AAAA"], weights=[90, 10])[0]
        query = f"{core_label}.{tld}"

        return {
            "flow_id": f"dga-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": self.rng.randint(30000, 65535),
            "dst_port": 53,
            "protocol": "UDP",
            "direction": "outbound",
            "duration": round(self.rng.uniform(0.01, 0.08), 4),
            "packet_count": self.rng.choice([1, 2]),
            "byte_count": self.rng.randint(65, 150),
            "tcp_flags": None,
            "dns": {
                "query": query,
                "qtype": qtype,
                "rcode": "NOERROR",
                "query_length": len(query),
            },
            "tls": None,
            "quic": None,
        }

    def _generate_encrypted_anomaly(self, idx: int) -> dict[str, Any]:
        delta_sec = self.rng.uniform(0.5, 4.0)
        self.current_time = datetime.fromtimestamp(
            self.current_time.timestamp() + delta_sec, tz=timezone.utc
        )

        src_ip = f"192.168.1.{self.rng.randint(10, 180)}"
        dst_ip = self.rng.choice(["198.51.100.22", "203.0.113.88", "192.0.2.14", "185.199.110.153"])
        src_port = self.rng.randint(1024, 65535)

        # Diverse encrypted anomaly archetypes (not a single static signature)
        anomaly_type = self.rng.choices(
            ["obsolete_tls_cipher", "direct_ip_sni", "obsolete_quic", "keystroke_timing", "malicious_ja3"],
            weights=[30, 25, 15, 15, 15],
        )[0]

        if anomaly_type == "obsolete_tls_cipher":
            protocol = "TCP"
            dst_port = self.rng.choice([443, 8443])
            duration = round(self.rng.uniform(0.5, 5.0), 4)
            packet_count = self.rng.randint(10, 40)
            byte_count = self.rng.randint(2000, 15000)
            tcp_flags = "ACK-PSH"
            tls = {
                "version": self.rng.choice(["TLS 1.0", "TLS 1.1", "SSL 3.0"]),
                "sni": self.rng.choice(["secure-backup.cloud.net", "legacy-portal.internal-mgmt.org"]),
                "cipher_suite": self.rng.choice([
                    "TLS_RSA_WITH_RC4_128_MD5",
                    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                    "TLS_RSA_WITH_RC4_128_SHA",
                    "TLS_RSA_WITH_DES_CBC_SHA",
                ]),
            }
            quic = None

        elif anomaly_type == "direct_ip_sni":
            protocol = "TCP"
            dst_port = self.rng.choice([443, 9443])
            duration = round(self.rng.uniform(0.2, 4.0), 4)
            packet_count = self.rng.randint(8, 30)
            byte_count = self.rng.randint(1500, 12000)
            tcp_flags = "ACK-PSH"
            ip_literal = self.rng.choice(["198.51.100.22", "203.0.113.88", "192.0.2.45"])
            tls = {
                "version": self.rng.choice(["TLS 1.2", "TLS 1.3"]),
                "sni": ip_literal,
            }
            quic = None

        elif anomaly_type == "obsolete_quic":
            protocol = "UDP"
            dst_port = 443
            duration = round(self.rng.uniform(0.1, 2.0), 4)
            packet_count = self.rng.randint(6, 25)
            byte_count = self.rng.randint(1200, 9000)
            tcp_flags = None
            tls = None
            quic = {
                "version": self.rng.choice(["Q043", "Q046", "Q050", "mvfst-24"]),
                "sni": self.rng.choice(["quic-edge.telemetry-node.net", "198.51.100.99"]),
            }

        elif anomaly_type == "keystroke_timing":
            protocol = "TCP"
            dst_port = self.rng.choice([443, 2222])
            duration = round(self.rng.uniform(15.0, 45.0), 4)
            packet_count = self.rng.randint(50, 120)
            # Small packets typical of interactive keystroke encrypted shell (bytes_per_packet <= 80)
            byte_count = packet_count * self.rng.randint(52, 74)
            tcp_flags = "ACK-PSH"
            tls = {
                "version": "TLS 1.3",
                "sni": "shell-relay.cloud-ops.net",
            }
            quic = None

        else:  # malicious_ja3
            protocol = "TCP"
            dst_port = 443
            duration = round(self.rng.uniform(0.4, 3.5), 4)
            packet_count = self.rng.randint(10, 35)
            byte_count = self.rng.randint(1800, 14000)
            tcp_flags = "ACK-PSH"
            tls = {
                "version": "TLS 1.2",
                "sni": "cdn-cache.cloud-service.com",
                "ja3": self.rng.choice([
                    "6734f37431670b3ab4292b8f60f29984",
                    "b32309a26951912be7dba376398abc3b",
                    "72a589da586844d7f0818ce684948eea",
                ]),
            }
            quic = None

        return {
            "flow_id": f"enc-anomaly-{idx:06d}",
            "timestamp": _format_timestamp(self.current_time),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "direction": "outbound",
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "tcp_flags": tcp_flags,
            "dns": None,
            "tls": tls,
            "quic": quic,
        }



def generate_flows(
    scenario: str,
    count: int,
    seed: int | None = None,
    start_time: datetime | None = None,
) -> Iterator[dict[str, Any]]:
    """
    Generate `count` flow records for a given `scenario`.

    Parameters
    ----------
    scenario : str
        One of 'benign', 'ddos', 'port_scan', 'c2_beacon', 'dns_tunnel', 'exfiltration'.
    count : int
        Number of flow records to generate (must be > 0).
    seed : int | None
        Optional random seed for deterministic generation.
    start_time : datetime | None
        Optional baseline timestamp (default: 2026-09-06T12:00:00Z).

    Returns
    -------
    Iterator[dict[str, Any]]
        Stream of raw flow dicts adhering strictly to contracts/flow-schema.json.
    """
    generator = TrafficGenerator(scenario=scenario, seed=seed, start_time=start_time)
    yield from generator.generate(count)


def write_flows_jsonl(
    flows: Iterator[dict[str, Any]],
    output_path: str | Path | None = None,
) -> int:
    """
    Write a stream of flow records to a JSONL file or stdout.

    Parameters
    ----------
    flows : Iterator[dict[str, Any]]
        Stream of flow dicts.
    output_path : str | Path | None
        File path to write to, or None / '-' for stdout.

    Returns
    -------
    int
        Total number of records written.
    """
    count = 0
    if output_path and str(output_path) != "-":
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for flow in flows:
                f.write(json.dumps(flow) + "\n")
                count += 1
    else:
        for flow in flows:
            print(json.dumps(flow))
            count += 1
    return count
