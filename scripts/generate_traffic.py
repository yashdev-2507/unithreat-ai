#!/usr/bin/env python3
"""
scripts/generate_traffic.py
===========================

CLI script to generate synthetic network flow records for testing and demo.

Usage
-----
python scripts/generate_traffic.py --scenario benign --count 100 --seed 42 --output data/generated/benign.jsonl
python scripts/generate_traffic.py --scenario ddos --count 500 --seed 42 --output data/generated/ddos.jsonl
"""

import argparse
import sys
from pathlib import Path

# Add src to sys.path so the script can be run directly without installing the package
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from unithreat.generator import (
    VALID_SCENARIOS,
    generate_flows,
    write_flows_jsonl,
)


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic network flow records conforming to contracts/flow-schema.json."
    )
    parser.add_argument(
        "--scenario",
        required=True,
        choices=VALID_SCENARIOS,
        help=f"Traffic scenario to generate. Choices: {', '.join(VALID_SCENARIOS)}",
    )
    parser.add_argument(
        "--count",
        required=True,
        type=int,
        help="Number of flow records to generate (must be > 0).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for deterministic generation.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path (e.g. data/generated/benign.jsonl). Defaults to stdout if omitted or '-'.",
    )

    parsed = parser.parse_args(args)
    if parsed.count <= 0:
        parser.error("--count must be greater than 0.")

    return parsed


def main(args: list[str] | None = None) -> int:
    try:
        parsed = parse_args(args)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1

    flows = generate_flows(
        scenario=parsed.scenario,
        count=parsed.count,
        seed=parsed.seed,
    )

    written = write_flows_jsonl(flows, output_path=parsed.output)

    if parsed.output and parsed.output != "-":
        sys.stderr.write(
            f"Successfully generated {written} '{parsed.scenario}' flows to {parsed.output}\n"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
