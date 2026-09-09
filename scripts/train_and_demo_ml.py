#!/usr/bin/env python3
"""
scripts/train_and_demo_ml.py
============================

CLI demonstration script to train a baseline RandomForest threat classifier
and execute sample inferences conforming to contracts/ml-prediction-schema.json.

Usage
-----
python scripts/train_and_demo_ml.py --model-dir artifacts/models/rf-baseline-v1
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

# Ensure src is on sys.path
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from jsonschema import Draft202012Validator

from unithreat.features.extractor import FeatureExtractor
from unithreat.generator import VALID_SCENARIOS, generate_flows
from unithreat.ml.dataset import ALL_CLASSES, generate_labelled_dataset
from unithreat.ml.inference import MLInferenceEngine
from unithreat.ml.train import train_model

ML_SCHEMA_PATH = _ROOT / "contracts" / "ml-prediction-schema.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Train baseline ML model and run sample inference.")
    parser.add_argument(
        "--model-dir",
        default="artifacts/models/rf-baseline-v1",
        help="Directory to save the trained model artifacts.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility.",
    )
    parser.add_argument(
        "--runs-per-scenario",
        type=int,
        default=5,
        help="Number of independent simulation runs per scenario.",
    )
    parser.add_argument(
        "--flows-per-run",
        type=int,
        default=30,
        help="Number of flow records per simulation run.",
    )
    args = parser.parse_args()

    model_dir = Path(args.model_dir)

    print("=" * 65)
    print("UniThreat AI — ML Intelligence Layer Training & Demonstration")
    print("=" * 65)

    # 1. Dataset Generation
    print(f"\n[1/4] Generating multi-run synthetic dataset across all 8 classes...")
    t0 = time.perf_counter()
    dataset = generate_labelled_dataset(
        runs_per_scenario=args.runs_per_scenario,
        flows_per_run=args.flows_per_run,
        seed_base=args.seed,
    )
    gen_time = time.perf_counter() - t0
    print(f"      Generated {len(dataset)} flows across {8 * args.runs_per_scenario} simulation runs in {gen_time:.2f}s.")

    # 2. Model Training with Group/Run-Aware Split
    print(f"\n[2/4] Training RandomForestClassifier baseline (seed={args.seed})...")
    t0 = time.perf_counter()
    result = train_model(
        dataset=dataset,
        model_dir=model_dir,
        seed=args.seed,
        n_estimators=100,
        max_depth=15,
    )
    train_time = time.perf_counter() - t0

    metrics = result["metrics"]
    print(f"      Training completed in {train_time:.2f}s.")
    print(f"      Model saved to: {model_dir}")
    print("\n--- Evaluation Metrics on Held-Out Test Set (Run-Aware Split) ---")
    print(f"  * Accuracy:           {metrics['accuracy'] * 100:.2f}%")
    print(f"  * Precision (Macro):  {metrics['precision_macro'] * 100:.2f}%")
    print(f"  * Recall (Macro):     {metrics['recall_macro'] * 100:.2f}%")
    print(f"  * F1 Score (Macro):   {metrics['f1_macro'] * 100:.2f}%")
    print(f"  * F1 Score (Weighted):{metrics['f1_weighted'] * 100:.2f}%")

    print("\n--- Top 5 Global Gini Feature Importances ---")
    for feat, imp in list(result["feature_importances"].items())[:5]:
        print(f"  * {feat:<30} : {imp:.4f}")

    # 3. Load MLInferenceEngine
    print(f"\n[3/4] Initializing MLInferenceEngine from {model_dir}...")
    engine = MLInferenceEngine(model_dir=model_dir)

    with ML_SCHEMA_PATH.open(encoding="utf-8") as f:
        ml_schema = json.load(f)
    validator = Draft202012Validator(ml_schema)

    # 4. Run Sample Inference across Scenarios
    print(f"\n[4/4] Executing sample single-flow inferences across scenarios...")
    extractor = FeatureExtractor(enable_windowing=True)

    print("\n" + "=" * 65)
    print("Sample Inferences (contracts/ml-prediction-schema.json validated):")
    print("=" * 65)

    for scenario in VALID_SCENARIOS:
        sample_flow = next(generate_flows(scenario=scenario, count=1, seed=999))
        record = extractor.extract(sample_flow)

        t_inf0 = time.perf_counter()
        prediction = engine.predict(record)
        lat_ms = (time.perf_counter() - t_inf0) * 1000.0

        contract_dict = prediction.to_contract_dict()
        validator.validate(contract_dict)

        print(f"\nScenario: [{scenario}]")
        print(f"  Flow ID:      {prediction.flow_id}")
        print(f"  Predicted:    {prediction.threat_class}")
        print(f"  Score:        {prediction.score:.4f} (uncalibrated model score)")
        print(f"  Calibrated:   {prediction.calibrated}")
        print(f"  Latency:      {lat_ms:.2f} ms")
        print(f"  Contract:     VALID JSON according to contracts/ml-prediction-schema.json")
        print(f"  JSON output:  {json.dumps(contract_dict)}")

    print("\n" + "=" * 65)
    print("Demonstration successfully completed!")
    print("=" * 65)
    return 0


if __name__ == "__main__":
    sys.exit(main())
