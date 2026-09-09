"""
unithreat.ml.dataset
====================

Dataset generation, loading, and group/run-aware splitting for ML training.

Supports all 8 project threat classes:
  - BENIGN
  - DDOS
  - C2_BEACONING
  - DGA
  - DNS_TUNNELING
  - RECONNAISSANCE
  - DATA_EXFILTRATION
  - ENCRYPTED_ANOMALY
"""

from __future__ import annotations

import json
from pathlib import Path
import random
from typing import Any

from unithreat.features.extractor import FeatureExtractor
from unithreat.features.models import FeatureRecord
from unithreat.generator.traffic import generate_flows

SCENARIO_LABEL_MAP: dict[str, str] = {
    "benign": "BENIGN",
    "ddos": "DDOS",
    "c2_beacon": "C2_BEACONING",
    "dga": "DGA",
    "dns_tunnel": "DNS_TUNNELING",
    "port_scan": "RECONNAISSANCE",
    "exfiltration": "DATA_EXFILTRATION",
    "encrypted_anomaly": "ENCRYPTED_ANOMALY",
}

ALL_CLASSES: tuple[str, ...] = (
    "BENIGN",
    "DDOS",
    "C2_BEACONING",
    "DGA",
    "DNS_TUNNELING",
    "RECONNAISSANCE",
    "DATA_EXFILTRATION",
    "ENCRYPTED_ANOMALY",
)


def generate_labelled_dataset(
    runs_per_scenario: int = 5,
    flows_per_run: int = 50,
    seed_base: int = 42,
) -> list[dict[str, Any]]:
    """
    Generate a reproducible labelled dataset across all 8 threat classes.

    Uses multiple distinct simulation runs per scenario to support group-aware
    train/validation/test splitting without session/temporal correlation leakage.

    Parameters
    ----------
    runs_per_scenario : int
        Number of distinct simulation runs generated for each scenario.
    flows_per_run : int
        Number of consecutive flow records per simulation run.
    seed_base : int
        Base random seed for reproducible multi-run generation.

    Returns
    -------
    list[dict[str, Any]]
        List of labelled sample dictionaries, each containing:
        - flow_id: str
        - run_id: str (unique identifier for the simulation run)
        - label: str (threat class)
        - features: dict[str, Any] (FeatureRecord features)
        - timestamp: str
    """
    dataset: list[dict[str, Any]] = []

    for scenario_idx, (scenario, label) in enumerate(SCENARIO_LABEL_MAP.items()):
        for run_idx in range(runs_per_scenario):
            run_id = f"{scenario}_run_{run_idx}"
            run_seed = seed_base + (scenario_idx * 100) + run_idx

            # Each simulation run uses its own stateful feature window tracker
            extractor = FeatureExtractor(enable_windowing=True)
            flows = generate_flows(scenario=scenario, count=flows_per_run, seed=run_seed)

            for flow_dict in flows:
                record = extractor.extract(flow_dict)
                dataset.append({
                    "flow_id": record.flow_id,
                    "run_id": run_id,
                    "label": label,
                    "features": record.features,
                    "timestamp": record.timestamp,
                })

    return dataset


def split_dataset_by_group(
    dataset: list[dict[str, Any]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Split dataset into train, validation, and test sets using group/run-aware partitioning.

    Ensures that all flows belonging to a specific simulation run (run_id) are placed
    exclusively into one partition (train, val, or test). This prevents temporal and
    session correlation leakage between adjacent flows in the same run.

    Parameters
    ----------
    dataset : list[dict[str, Any]]
        Labelled dataset samples.
    train_ratio : float
        Proportion of runs allocated to training (default: 0.70).
    val_ratio : float
        Proportion of runs allocated to validation (default: 0.15).
    test_ratio : float
        Proportion of runs allocated to testing (default: 0.15).
    seed : int
        Random seed for deterministic run allocation.

    Returns
    -------
    tuple of (train_set, val_set, test_set)
    """
    # Group runs per label
    runs_by_label: dict[str, list[str]] = {}
    samples_by_run: dict[str, list[dict[str, Any]]] = {}

    for sample in dataset:
        lbl = sample["label"]
        r_id = sample.get("run_id", "default_run")
        if lbl not in runs_by_label:
            runs_by_label[lbl] = []
        if r_id not in runs_by_label[lbl]:
            runs_by_label[lbl].append(r_id)

        if r_id not in samples_by_run:
            samples_by_run[r_id] = []
        samples_by_run[r_id].append(sample)

    rng = random.Random(seed)
    train_runs: set[str] = set()
    val_runs: set[str] = set()
    test_runs: set[str] = set()

    for lbl, runs in sorted(runs_by_label.items()):
        shuffled = list(runs)
        rng.shuffle(shuffled)
        n_runs = len(shuffled)

        if n_runs >= 3:
            n_test = max(1, int(round(n_runs * test_ratio)))
            n_val = max(1, int(round(n_runs * val_ratio)))
            # Ensure at least 1 run for training
            if n_runs - n_val - n_test < 1:
                n_test = 1
                n_val = 1
            n_train = n_runs - n_val - n_test
            t_r = shuffled[:n_train]
            v_r = shuffled[n_train : n_train + n_val]
            te_r = shuffled[n_train + n_val :]
        elif n_runs == 2:
            t_r = [shuffled[0]]
            v_r = [shuffled[1]]
            te_r = [shuffled[1]]  # Note: with 2 runs, test shares val
        else:
            # Fallback for single run per class: split samples directly
            t_r = shuffled
            v_r = shuffled
            te_r = []

        train_runs.update(t_r)
        val_runs.update(v_r)
        test_runs.update(te_r)

    train_set: list[dict[str, Any]] = []
    val_set: list[dict[str, Any]] = []
    test_set: list[dict[str, Any]] = []

    for r_id, samples in samples_by_run.items():
        if r_id in train_runs:
            train_set.extend(samples)
        if r_id in val_runs:
            val_set.extend(samples)
        if r_id in test_runs:
            test_set.extend(samples)

    return train_set, val_set, test_set


def save_dataset_jsonl(dataset: list[dict[str, Any]], path: Path | str) -> int:
    """Save labelled dataset to a JSONL file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for sample in dataset:
            f.write(json.dumps(sample) + "\n")
    return len(dataset)


def load_dataset_jsonl(path: Path | str) -> list[dict[str, Any]]:
    """Load labelled dataset from a JSONL file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dataset file not found: {p}")
    records: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    return records
