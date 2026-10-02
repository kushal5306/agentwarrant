"""Run the benchmark: python benchmark/run.py [--policy path.yaml] [--json]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentwarrant import Policy  # noqa: E402
from agentwarrant.bench import run_cases  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", type=Path)
    ap.add_argument("--cases", type=Path, default=ROOT / "benchmark" / "cases.yaml")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    policy = Policy.from_file(a.policy) if a.policy else Policy.default()
    r = run_cases(yaml.safe_load(a.cases.read_text(encoding="utf-8"))["cases"], policy)
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    print(f"policy: {r['policy']}   cases: {r['cases']}")
    print(f"attacks blocked : {r['attacks_blocked']}/{r['attacks']}  ({r['detection_rate']:.1%})")
    print(f"benign blocked  : {r['benign_blocked']}/{r['benign']}  ({r['false_positive_rate']:.1%} false positives)")
    print(f"latency         : p50 {r['latency_ms_p50']} ms, p95 {r['latency_ms_p95']} ms\n")
    print(f"{'category':<20}{'correct':>10}")
    for cat, v in r["by_category"].items():
        print(f"{cat:<20}{v['correct']:>5}/{v['total']:<4}")
    if r["misses"]:
        print("\nmisses:")
        for m in r["misses"]:
            print(f"  {m['id']:<6} expected {m['expected']:<7} got {m['got']}")


if __name__ == "__main__":
    main()
