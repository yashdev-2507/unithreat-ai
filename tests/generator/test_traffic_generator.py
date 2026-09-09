"""
tests/generator/test_traffic_generator.py
=========================================

Comprehensive test suite for the synthetic traffic generator.

Validates:
- Every scenario generates records.
- Generated records conform strictly to contracts/flow-schema.json.
- Determinism: identical seed produces identical output.
- Non-determinism / seed sensitivity: different seeds produce different output.
- Invalid scenario and count arguments are rejected cleanly.
- JSONL output can be consumed and parsed by the existing ingest/replay layer.
- Scenario-specific behavioral patterns (DDoS, port scan, C2 beacon, DNS tunnel, exfiltration).
- CLI interface handles valid and invalid options properly.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator

from unithreat.generator import (
    VALID_SCENARIOS,
    TrafficGenerator,
    generate_flows,
    write_flows_jsonl,
)
from unithreat.ingest.adapters.jsonl import replay_jsonl
from unithreat.ingest.models import Flow
from unithreat.ingest.parser import parse_flow
from scripts.generate_traffic import main as cli_main

ROOT = Path(__file__).resolve().parents[2]
FLOW_SCHEMA_PATH = ROOT / "contracts" / "flow-schema.json"


@pytest.fixture(scope="module")
def flow_schema() -> dict:
    with FLOW_SCHEMA_PATH.open(encoding="utf-8") as f:
        schema = json.load(f)
    Draft202012Validator.check_schema(schema)
    return schema


@pytest.fixture(scope="module")
def schema_validator(flow_schema: dict) -> Draft202012Validator:
    return Draft202012Validator(flow_schema)


# ---------------------------------------------------------------------------
# Scenario generation & schema compliance tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", VALID_SCENARIOS)
def test_every_scenario_generates_valid_records(scenario: str, schema_validator: Draft202012Validator):
    flows = list(generate_flows(scenario=scenario, count=30, seed=42))
    assert len(flows) == 30

    for flow in flows:
        # 1. JSON Schema validation
        schema_validator.validate(flow)

        # 2. Ingest layer parser and Pydantic model validation
        parsed_flow = parse_flow(flow)
        assert isinstance(parsed_flow, Flow)
        assert parsed_flow.flow_id == flow["flow_id"]
        assert parsed_flow.protocol == flow["protocol"]


# ---------------------------------------------------------------------------
# Determinism tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", VALID_SCENARIOS)
def test_same_seed_produces_identical_output(scenario: str):
    run_1 = list(generate_flows(scenario=scenario, count=25, seed=1337))
    run_2 = list(generate_flows(scenario=scenario, count=25, seed=1337))

    assert run_1 == run_2
    assert [f["flow_id"] for f in run_1] == [f["flow_id"] for f in run_2]
    assert [f["timestamp"] for f in run_1] == [f["timestamp"] for f in run_2]


@pytest.mark.parametrize("scenario", VALID_SCENARIOS)
def test_different_seeds_produce_different_output(scenario: str):
    run_a = list(generate_flows(scenario=scenario, count=20, seed=111))
    run_b = list(generate_flows(scenario=scenario, count=20, seed=999))

    assert run_a != run_b


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------


def test_invalid_scenario_rejected():
    with pytest.raises(ValueError, match="Invalid scenario 'unsupported_scenario'"):
        list(generate_flows(scenario="unsupported_scenario", count=10))

    with pytest.raises(ValueError, match="Invalid scenario 'malware'"):
        TrafficGenerator(scenario="malware")


@pytest.mark.parametrize("invalid_count", [0, -1, -50, "10", 3.14, None])
def test_invalid_count_rejected(invalid_count):
    with pytest.raises(ValueError, match="Count must be an integer greater than 0"):
        list(generate_flows(scenario="benign", count=invalid_count))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Replay layer integration tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", VALID_SCENARIOS)
def test_jsonl_output_consumed_by_ingest_replay(scenario: str, tmp_path: Path):
    output_file = tmp_path / f"{scenario}.jsonl"
    flows = list(generate_flows(scenario=scenario, count=20, seed=42))

    written = write_flows_jsonl(flows, output_path=output_file)
    assert written == 20
    assert output_file.exists()

    # Ingest using existing replay_jsonl adapter
    replayed = list(replay_jsonl(output_file, speed_factor=0.0))
    assert len(replayed) == 20

    for original, ingested in zip(flows, replayed, strict=True):
        assert ingested.flow_id == original["flow_id"]
        assert ingested.src_ip == original["src_ip"]
        assert ingested.dst_ip == original["dst_ip"]
        assert ingested.protocol == original["protocol"]
        assert ingested.src_port == original["src_port"]
        assert ingested.dst_port == original["dst_port"]
        assert ingested.direction == original["direction"]
        assert ingested.byte_count == original["byte_count"]


# ---------------------------------------------------------------------------
# Scenario behavioral pattern tests
# ---------------------------------------------------------------------------


class TestScenarioCharacteristics:
    def test_ddos_behavioral_pattern(self):
        flows = list(generate_flows(scenario="ddos", count=50, seed=42))

        # 1. Target concentration: all flows should target the designated victim IP
        dst_ips = {f["dst_ip"] for f in flows}
        assert len(dst_ips) == 1
        assert "10.0.0.50" in dst_ips

        # 2. Source diversity: multiple distinct source IPs
        src_ips = {f["src_ip"] for f in flows}
        assert len(src_ips) > 30

        # 3. Protocol distribution: mix of TCP (SYN flood) and UDP
        protocols = {f["protocol"] for f in flows}
        assert "TCP" in protocols
        assert "UDP" in protocols

        # 4. Low duration / packet flood characteristics
        for f in flows:
            assert f["duration"] <= 0.05
            assert f["direction"] == "inbound"

    def test_port_scan_behavioral_pattern(self):
        flows = list(generate_flows(scenario="port_scan", count=40, seed=42))

        # 1. Scanning source concentration: single or few scanner host(s)
        src_ips = {f["src_ip"] for f in flows}
        assert len(src_ips) == 1

        # 2. Port diversity: probing many destination ports
        dst_ports = {f["dst_port"] for f in flows}
        assert len(dst_ports) > 15

        # 3. Short flows with low byte counts (SYN probes)
        for f in flows:
            assert f["protocol"] == "TCP"
            assert f["tcp_flags"] == "SYN"
            assert f["packet_count"] == 1
            assert f["byte_count"] <= 80
            assert f["duration"] < 0.05

    def test_c2_beacon_behavioral_pattern(self):
        from datetime import datetime
        flows = list(generate_flows(scenario="c2_beacon", count=20, seed=42))

        # 1. Consistent host pair
        src_ips = {f["src_ip"] for f in flows}
        dst_ips = {f["dst_ip"] for f in flows}
        assert len(src_ips) == 1
        assert len(dst_ips) == 1

        # 2. Consistent flow properties
        for f in flows:
            assert f["protocol"] == "TCP"
            assert f["dst_port"] == 443
            assert f["direction"] == "outbound"
            assert f["tls"] is not None
            assert f["tls"]["version"] == "TLS 1.3"

        # 3. Regular periodicity (timestamps separated by approx 30s +/- 1s)
        timestamps = [
            datetime.fromisoformat(f["timestamp"].replace("Z", "+00:00")).timestamp()
            for f in flows
        ]
        deltas = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:], strict=True)]
        for d in deltas:
            assert 28.0 <= d <= 32.0

    def test_dns_tunnel_behavioral_pattern(self):
        flows = list(generate_flows(scenario="dns_tunnel", count=30, seed=42))

        for f in flows:
            assert f["protocol"] == "UDP"
            assert f["dst_port"] == 53
            assert f["direction"] == "outbound"
            assert f["dns"] is not None
            # Tunnel metadata: long encoded query
            query = f["dns"]["query"]
            assert "tunnel" in query
            assert len(query) > 50
            assert f["dns"]["qtype"] == "TXT"
            assert f["byte_count"] > 300

    def test_exfiltration_behavioral_pattern(self):
        flows = list(generate_flows(scenario="exfiltration", count=20, seed=42))

        for f in flows:
            assert f["direction"] == "outbound"
            assert f["protocol"] == "TCP"
            # High byte volume transferred outbound
            assert f["byte_count"] >= 1_000_000
            assert f["duration"] >= 10.0
            assert f["packet_count"] >= 500

    def test_dga_behavioral_pattern(self):
        flows = list(generate_flows(scenario="dga", count=30, seed=42))

        for f in flows:
            assert f["protocol"] == "UDP"
            assert f["dst_port"] == 53
            assert f["direction"] == "outbound"
            assert f["dns"] is not None
            assert f["dns"]["qtype"] in ("A", "AAAA")
            assert f["dns"]["rcode"] == "NOERROR"
            assert len(f["dns"]["query"]) >= 15

    def test_encrypted_anomaly_behavioral_pattern(self):
        flows = list(generate_flows(scenario="encrypted_anomaly", count=40, seed=42))

        for f in flows:
            assert f["direction"] == "outbound"
            assert (f["tls"] is not None) or (f["quic"] is not None)



# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_generates_file(self, tmp_path: Path):
        output_file = tmp_path / "cli_test.jsonl"
        exit_code = cli_main([
            "--scenario", "benign",
            "--count", "15",
            "--seed", "42",
            "--output", str(output_file),
        ])

        assert exit_code == 0
        assert output_file.exists()

        lines = output_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 15

        first_record = json.loads(lines[0])
        assert first_record["flow_id"] == "benign-000001"

    def test_cli_invalid_scenario_exits_nonzero(self):
        exit_code = cli_main([
            "--scenario", "invalid_scenario",
            "--count", "10",
        ])
        assert exit_code != 0

    def test_cli_invalid_count_exits_nonzero(self):
        exit_code = cli_main([
            "--scenario", "benign",
            "--count", "0",
        ])
        assert exit_code != 0

        exit_code = cli_main([
            "--scenario", "benign",
            "--count", "-5",
        ])
        assert exit_code != 0
