#!/usr/bin/env python3
"""
scripts/benchmark_pipeline.py
=============================

Comprehensive performance benchmarking utility for UniThreat AI streaming detection pipeline.

Measures actual end-to-end pipeline throughput, latency percentiles (P50, P95, P99),
memory consumption, and verified bounded store capacity under realistic mixed threat traffic.

Pipeline under test:
    Flow (Raw Dict / Ingest)
    -> FeatureExtractor (37 features + sliding windows)
    -> DetectionEngine (6 statistical & behavioral detectors)
    -> MLInferenceEngine (Random Forest classifier)
    -> AlertFusionEngine (Deterministic 4-case fusion)
    -> AlertDeduplicator (Bounded LRU suppression)
    -> BoundedAlertStore & BoundedFlowStore (Bounded ring buffers)

Usage:
    python scripts/benchmark_pipeline.py --flows 1000 5000 10000 --scenario mixed --seed 42
    python scripts/benchmark_pipeline.py --flows 1000 --json --output artifacts/benchmarks/benchmark.json
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import sys
import time
from typing import Any

# Ensure src is on sys.path
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import numpy as np

from unithreat.alerts.pipeline import IntegratedPipeline
from unithreat.generator import VALID_SCENARIOS, generate_flows
from unithreat.ml.inference import MLInferenceEngine


def get_system_environment() -> dict[str, Any]:
    """Retrieve detailed hardware and OS environment info for reproducibility."""
    cpu_model = "Unknown"
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if "model name" in line:
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except Exception:
        cpu_model = platform.processor() or "Unknown"

    total_ram_mb = 0.0
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if "MemTotal:" in line:
                    total_ram_mb = float(line.split()[1]) / 1024.0
                    break
    except Exception:
        pass

    return {
        "platform": platform.platform(),
        "os_name": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count() or 1,
        "total_ram_mb": round(total_ram_mb, 1),
        "environment_note": "Measured on the development/test environment.",
    }


def get_process_rss_kb() -> int:
    """Retrieve current process resident set size (VmRSS) in KiB from /proc/self/status."""
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:
        pass
    # Fallback to getrusage maxrss
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def generate_benchmark_traffic(
    count: int,
    scenario: str = "mixed",
    seed: int = 42,
    start_time: datetime | None = None,
) -> tuple[list[dict[str, Any]], float]:
    """
    Generate synthetic flows for benchmarking, isolated from pipeline execution time.

    Returns:
        (flows, generation_elapsed_seconds)
    """
    t_start = time.perf_counter()
    flows: list[dict[str, Any]] = []

    if scenario == "mixed":
        scenarios = list(VALID_SCENARIOS)
        base_count = count // len(scenarios)
        remainder = count % len(scenarios)

        for i, sc in enumerate(scenarios):
            n = base_count + (1 if i < remainder else 0)
            if n > 0:
                flows.extend(list(generate_flows(
                    scenario=sc,
                    count=n,
                    seed=seed + i * 100,
                    start_time=start_time,
                )))
        # Sort chronologically to simulate a realistic interleaved multi-scenario stream
        flows.sort(key=lambda f: f["timestamp"])
    else:
        if scenario not in VALID_SCENARIOS:
            raise ValueError(f"Invalid scenario '{scenario}'. Choose from {VALID_SCENARIOS} or 'mixed'")
        flows.extend(list(generate_flows(
            scenario=scenario,
            count=count,
            seed=seed,
            start_time=start_time,
        )))

    t_elapsed = time.perf_counter() - t_start
    return flows, t_elapsed


@dataclass
class BenchmarkMetrics:
    total_flows: int
    scenario: str
    seed: int
    generation_time_s: float
    processing_time_s: float
    throughput_fps: float
    mean_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    std_latency_ms: float
    total_alerts_produced: int
    alerts_by_threat_class: dict[str, int]
    alerts_by_severity: dict[str, int]
    alert_store_capacity: int
    alert_store_count: int
    flow_store_capacity: int
    flow_store_count: int
    dedup_tracked_keys: int
    feature_src_entities: int
    feature_dst_entities: int
    rss_before_mb: float
    rss_after_mb: float
    rss_delta_mb: float
    peak_rss_mb: float
    environment: dict[str, Any]


def run_benchmark(
    flow_count: int,
    scenario: str = "mixed",
    seed: int = 42,
    model_dir: Path | str | None = _ROOT / "artifacts" / "models" / "rf-baseline-v1",
    warmup_count: int = 50,
) -> BenchmarkMetrics:
    """
    Run an end-to-end benchmark on the complete UniThreat detection pipeline.
    """
    env_info = get_system_environment()

    # 1. Initialize complete pipeline
    ml_engine = None
    if model_dir:
        p = Path(model_dir)
        if (p / "model.joblib").exists():
            ml_engine = MLInferenceEngine(model_dir=p)

    pipeline = IntegratedPipeline(
        ml_engine=ml_engine,
        enable_windowing=True,
    )

    # 2. Warmup phase (warm up JIT, caches, model weights)
    if warmup_count > 0:
        warmup_flows, _ = generate_benchmark_traffic(
            count=warmup_count,
            scenario=scenario,
            seed=seed + 9999,
        )
        for wf in warmup_flows:
            pipeline.process_flow(wf)

        # Clear pipeline storage state after warmup so benchmark starts pristine
        pipeline.alert_store.clear()
        pipeline.flow_store.clear()
        pipeline.deduplicator.clear()
        pipeline.total_flows_processed = 0

    # 3. Generate test traffic (isolated timing)
    flows, gen_time_s = generate_benchmark_traffic(
        count=flow_count,
        scenario=scenario,
        seed=seed,
    )

    # 4. Measure pipeline execution
    rss_before_kb = get_process_rss_kb()
    latencies_ms: list[float] = []
    total_alerts = 0

    t_start = time.perf_counter()
    for flow in flows:
        f_start = time.perf_counter()
        alerts = pipeline.process_flow(flow)
        f_end = time.perf_counter()

        latencies_ms.append((f_end - f_start) * 1000.0)
        total_alerts += len(alerts)

    t_elapsed = time.perf_counter() - t_start
    rss_after_kb = get_process_rss_kb()
    peak_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # 5. Compute metrics
    lat_arr = np.array(latencies_ms)
    throughput = len(flows) / t_elapsed if t_elapsed > 0 else 0.0

    stats = pipeline.alert_store.stats()

    # Entity counts in feature extractor window tracker
    src_entities = len(pipeline.extractor.window_tracker._src_windows)
    dst_entities = len(pipeline.extractor.window_tracker._dst_windows)

    return BenchmarkMetrics(
        total_flows=len(flows),
        scenario=scenario,
        seed=seed,
        generation_time_s=round(gen_time_s, 4),
        processing_time_s=round(t_elapsed, 4),
        throughput_fps=round(throughput, 2),
        mean_latency_ms=round(float(np.mean(lat_arr)), 3),
        p50_latency_ms=round(float(np.percentile(lat_arr, 50)), 3),
        p95_latency_ms=round(float(np.percentile(lat_arr, 95)), 3),
        p99_latency_ms=round(float(np.percentile(lat_arr, 99)), 3),
        min_latency_ms=round(float(np.min(lat_arr)), 3),
        max_latency_ms=round(float(np.max(lat_arr)), 3),
        std_latency_ms=round(float(np.std(lat_arr)), 3),
        total_alerts_produced=total_alerts,
        alerts_by_threat_class=stats.get("by_threat_class", {}),
        alerts_by_severity=stats.get("by_severity", {}),
        alert_store_capacity=pipeline.alert_store.max_alerts,
        alert_store_count=pipeline.alert_store.count(),
        flow_store_capacity=pipeline.flow_store.max_flows,
        flow_store_count=pipeline.flow_store.count(),
        dedup_tracked_keys=len(pipeline.deduplicator._seen_keys),
        feature_src_entities=src_entities,
        feature_dst_entities=dst_entities,
        rss_before_mb=round(rss_before_kb / 1024.0, 2),
        rss_after_mb=round(rss_after_kb / 1024.0, 2),
        rss_delta_mb=round((rss_after_kb - rss_before_kb) / 1024.0, 2),
        peak_rss_mb=round(peak_rss_kb / 1024.0, 2),
        environment=env_info,
    )


def print_benchmark_summary(metrics: BenchmarkMetrics) -> None:
    """Print human-readable benchmark table to stdout."""
    print("=" * 76)
    print(f" UniThreat AI Pipeline Benchmark: {metrics.total_flows:,} flows ({metrics.scenario})")
    print("=" * 76)
    print(f" Environment         : {metrics.environment['cpu_model']} ({metrics.environment['cpu_count']} cores)")
    print(f" OS / Platform       : {metrics.environment['platform']}")
    print(f" Python Version      : {metrics.environment['python_version']}")
    print(f" RAM Available       : {metrics.environment['total_ram_mb']:,} MB")
    print(f" Environment Note    : {metrics.environment['environment_note']}")
    print("-" * 76)
    print(f" Total Flows Tested  : {metrics.total_flows:,} flows")
    print(f" Data Gen Time       : {metrics.generation_time_s:.3f} s (isolated from processing)")
    print(f" Pipeline Proc Time  : {metrics.processing_time_s:.3f} s")
    print(f" Throughput          : {metrics.throughput_fps:,.2f} flows/sec")
    print("-" * 76)
    print(" Latency Statistics (per flow):")
    print(f"   Mean Latency      : {metrics.mean_latency_ms:.3f} ms")
    print(f"   P50 (Median)      : {metrics.p50_latency_ms:.3f} ms")
    print(f"   P95               : {metrics.p95_latency_ms:.3f} ms")
    print(f"   P99               : {metrics.p99_latency_ms:.3f} ms")
    print(f"   Min / Max         : {metrics.min_latency_ms:.3f} ms / {metrics.max_latency_ms:.3f} ms")
    print(f"   Std Deviation     : {metrics.std_latency_ms:.3f} ms")
    print("-" * 76)
    print(" Detection & Bounded Memory Verification:")
    print(f"   Total Alerts      : {metrics.total_alerts_produced:,}")
    print(f"   Alert Store Size  : {metrics.alert_store_count:,} / {metrics.alert_store_capacity:,} (bounded)")
    print(f"   Flow Store Size   : {metrics.flow_store_count:,} / {metrics.flow_store_capacity:,} (bounded)")
    print(f"   Dedup Keys Tracked: {metrics.dedup_tracked_keys:,}")
    print(f"   Active Window IPs : {metrics.feature_src_entities:,} src, {metrics.feature_dst_entities:,} dst")
    print(f"   RSS (Start/End)   : {metrics.rss_before_mb:.1f} MB -> {metrics.rss_after_mb:.1f} MB (delta: {metrics.rss_delta_mb:+.1f} MB)")
    print(f"   Peak RSS          : {metrics.peak_rss_mb:.1f} MB")
    if metrics.alerts_by_threat_class:
        print(f"   Threat Breakdown  : {metrics.alerts_by_threat_class}")
    if metrics.alerts_by_severity:
        print(f"   Severity Breakdown: {metrics.alerts_by_severity}")
    print("=" * 76)
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark UniThreat AI end-to-end streaming detection pipeline."
    )
    parser.add_argument(
        "--flows",
        type=int,
        nargs="+",
        default=[1000, 5000, 10000],
        help="One or more flow volumes to benchmark (default: 1000 5000 10000).",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="mixed",
        help=f"Traffic scenario: 'mixed' (default) or one of {VALID_SCENARIOS}.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--model-dir",
        type=str,
        default=str(_ROOT / "artifacts" / "models" / "rf-baseline-v1"),
        help="Directory containing trained model.joblib.",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=50,
        help="Number of warmup flows (default: 50).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON metrics to stdout.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional file path to save JSON benchmark results.",
    )

    args = parser.parse_args()

    results: list[dict[str, Any]] = []

    for count in args.flows:
        if not args.json:
            print(f"[*] Starting benchmark run for {count:,} flows ({args.scenario} traffic)...")
        metrics = run_benchmark(
            flow_count=count,
            scenario=args.scenario,
            seed=args.seed,
            model_dir=args.model_dir,
            warmup_count=args.warmup,
        )
        if not args.json:
            print_benchmark_summary(metrics)
        results.append(asdict(metrics))

    if args.json:
        print(json.dumps(results, indent=2))

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        if not args.json:
            print(f"[+] Saved benchmark results to {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
