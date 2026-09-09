"""
tests/test_benchmark.py
=======================

Automated verification tests for the pipeline benchmarking suite.
Verifies metrics collection, data separation, environment detection, and store boundedness.
Does NOT assert arbitrary performance thresholds.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from scripts.benchmark_pipeline import (
    BenchmarkMetrics,
    generate_benchmark_traffic,
    get_process_rss_kb,
    get_system_environment,
    run_benchmark,
)

ROOT = Path(__file__).resolve().parents[1]


class TestBenchmarkUtility:
    def test_get_system_environment_fields(self):
        env = get_system_environment()
        assert isinstance(env, dict)
        assert "platform" in env
        assert "cpu_model" in env
        assert "cpu_count" in env
        assert env["cpu_count"] >= 1
        assert "python_version" in env
        assert "total_ram_mb" in env
        assert env["environment_note"] == "Measured on the development/test environment."

    def test_get_process_rss_returns_positive_int(self):
        rss_kb = get_process_rss_kb()
        assert isinstance(rss_kb, int)
        assert rss_kb > 0

    def test_generate_benchmark_traffic_mixed(self):
        count = 24
        flows, gen_time = generate_benchmark_traffic(count=count, scenario="mixed", seed=123)
        assert len(flows) == count
        assert gen_time >= 0.0
        # Check chronological ordering
        timestamps = [f["timestamp"] for f in flows]
        assert timestamps == sorted(timestamps)
        # Check flows contain required fields
        for f in flows:
            assert "flow_id" in f
            assert "src_ip" in f
            assert "dst_ip" in f
            assert "protocol" in f

    def test_generate_benchmark_traffic_single_scenario(self):
        count = 10
        flows, gen_time = generate_benchmark_traffic(count=count, scenario="ddos", seed=42)
        assert len(flows) == count
        assert gen_time >= 0.0

    def test_generate_benchmark_traffic_invalid_scenario_raises(self):
        with pytest.raises(ValueError, match="Invalid scenario"):
            generate_benchmark_traffic(count=10, scenario="nonexistent_scenario")

    def test_run_benchmark_execution_and_metrics(self):
        metrics = run_benchmark(
            flow_count=16,
            scenario="mixed",
            seed=42,
            warmup_count=5,
        )
        assert isinstance(metrics, BenchmarkMetrics)
        assert metrics.total_flows == 16
        assert metrics.processing_time_s > 0.0
        assert metrics.throughput_fps > 0.0
        assert metrics.mean_latency_ms > 0.0
        assert metrics.p50_latency_ms > 0.0
        assert metrics.p95_latency_ms >= metrics.p50_latency_ms
        assert metrics.p99_latency_ms >= metrics.p95_latency_ms
        assert metrics.min_latency_ms <= metrics.mean_latency_ms <= metrics.max_latency_ms
        # Stores must respect their bounded capacities
        assert metrics.alert_store_count <= metrics.alert_store_capacity
        assert metrics.flow_store_count <= metrics.flow_store_capacity
        assert metrics.dedup_tracked_keys >= 0
        assert metrics.rss_before_mb > 0.0
        assert metrics.rss_after_mb > 0.0
        assert metrics.peak_rss_mb > 0.0
