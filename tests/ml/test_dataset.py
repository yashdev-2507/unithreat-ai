"""
tests/ml/test_dataset.py
========================

Tests for dataset generation, JSONL persistence, and group/run-aware splitting.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from unithreat.ml.dataset import (
    ALL_CLASSES,
    SCENARIO_LABEL_MAP,
    generate_labelled_dataset,
    load_dataset_jsonl,
    save_dataset_jsonl,
    split_dataset_by_group,
)


class TestDatasetGeneration:
    def test_generates_all_eight_classes(self):
        dataset = generate_labelled_dataset(runs_per_scenario=1, flows_per_run=10, seed_base=42)
        assert len(dataset) == 8 * 10
        labels = {s["label"] for s in dataset}
        assert labels == set(ALL_CLASSES)
        assert len(labels) == 8

    def test_sample_structure_and_features(self):
        dataset = generate_labelled_dataset(runs_per_scenario=1, flows_per_run=5, seed_base=100)
        sample = dataset[0]
        assert "flow_id" in sample
        assert "run_id" in sample
        assert "label" in sample
        assert "features" in sample
        assert "timestamp" in sample
        assert isinstance(sample["features"], dict)

    def test_jsonl_persistence_roundtrip(self, tmp_path: Path):
        dataset = generate_labelled_dataset(runs_per_scenario=1, flows_per_run=5, seed_base=200)
        file_path = tmp_path / "test_dataset.jsonl"

        saved_count = save_dataset_jsonl(dataset, file_path)
        assert saved_count == len(dataset)
        assert file_path.exists()

        loaded = load_dataset_jsonl(file_path)
        assert len(loaded) == len(dataset)
        assert loaded[0]["flow_id"] == dataset[0]["flow_id"]
        assert loaded[0]["label"] == dataset[0]["label"]


class TestGroupAwareSplitting:
    def test_runs_do_not_leak_across_splits(self):
        # Generate with 4 runs per scenario
        dataset = generate_labelled_dataset(runs_per_scenario=4, flows_per_run=10, seed_base=42)
        train, val, test = split_dataset_by_group(
            dataset, train_ratio=0.50, val_ratio=0.25, test_ratio=0.25, seed=42
        )

        train_runs = {s["run_id"] for s in train}
        val_runs = {s["run_id"] for s in val}
        test_runs = {s["run_id"] for s in test}

        # Verify no run overlap
        assert len(train_runs.intersection(val_runs)) == 0
        assert len(train_runs.intersection(test_runs)) == 0
        assert len(val_runs.intersection(test_runs)) == 0

        # Verify all samples are accounted for
        assert len(train) + len(val) + len(test) == len(dataset)

    def test_all_classes_present_in_train(self):
        dataset = generate_labelled_dataset(runs_per_scenario=3, flows_per_run=10, seed_base=42)
        train, val, test = split_dataset_by_group(dataset, seed=42)

        train_labels = {s["label"] for s in train}
        assert train_labels == set(ALL_CLASSES)
