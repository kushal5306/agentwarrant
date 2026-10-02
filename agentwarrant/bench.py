"""Benchmark runner: how many attacks are stopped, and how many normal calls get through."""

from __future__ import annotations

import statistics
import time
from collections import defaultdict
from typing import Any

from .guard import Guard
from .models import ToolCall, Verdict
from .policy import Policy

_UNICODE_TAG = 0xE0000


def expand(text: Any) -> Any:
    """Cases are stored as plain YAML. ``{{tag:...}}`` becomes invisible Unicode tag
    characters and ``{{zw}}`` a zero-width space, so the file stays readable."""
    if isinstance(text, dict):
        return {k: expand(v) for k, v in text.items()}
    if isinstance(text, list):
        return [expand(v) for v in text]
    if not isinstance(text, str):
        return text
    out = text.replace("{{zw}}", "​")
    while "{{tag:" in out:
        start = out.index("{{tag:")
        end = out.index("}}", start)
        hidden = "".join(chr(_UNICODE_TAG + ord(c)) for c in out[start + 6:end])
        out = out[:start] + hidden + out[end + 2:]
    return out


def run_cases(cases: list[dict[str, Any]], policy: Policy) -> dict[str, Any]:
    rows, lat = [], []
    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "correct": 0})
    for c in cases:
        guard = Guard(policy)  # fresh guard: cases are independent
        call = ToolCall(tool=c["tool"], args=expand(c.get("args", {})), session="bench")
        t0 = time.perf_counter()
        d = guard.evaluate(call)
        lat.append((time.perf_counter() - t0) * 1000)
        expected = c["expect"]
        got = d.verdict.value
        # A benign call that needs review is still a correct outcome if review was expected.
        correct = got == expected
        cat = c.get("category", "other")
        by_cat[cat]["total"] += 1
        by_cat[cat]["correct"] += int(correct)
        rows.append({
            "id": c["id"], "category": cat, "attack": c.get("attack", expected == "deny"),
            "expected": expected, "got": got, "correct": correct,
            "note": c.get("note", ""),
            "why": [f"{f.check}: {f.message}" for f in d.findings if f.severity.value != "info"],
        })

    attacks = [r for r in rows if r["attack"]]
    benign = [r for r in rows if not r["attack"]]
    blocked = sum(1 for r in attacks if r["got"] == Verdict.DENY.value)
    false_pos = sum(1 for r in benign if r["got"] == Verdict.DENY.value)
    lat_sorted = sorted(lat)
    return {
        "policy": policy.name,
        "cases": len(rows),
        "attacks": len(attacks),
        "attacks_blocked": blocked,
        "detection_rate": round(blocked / len(attacks), 6) if attacks else None,
        "benign": len(benign),
        "benign_blocked": false_pos,
        "false_positive_rate": round(false_pos / len(benign), 6) if benign else None,
        "accuracy": round(sum(r["correct"] for r in rows) / len(rows), 6) if rows else None,
        "latency_ms_p50": round(statistics.median(lat), 3) if lat else None,
        "latency_ms_p95": round(lat_sorted[int(0.95 * (len(lat_sorted) - 1))], 3) if lat else None,
        "by_category": {k: v for k, v in sorted(by_cat.items())},
        "misses": [r for r in rows if not r["correct"]],
    }
