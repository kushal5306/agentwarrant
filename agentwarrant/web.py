"""JSON-in / JSON-out facade used by the browser playground (Pyodide).

The playground runs this exact package in the browser, so what you see in the
demo is the library's real behaviour, not a re-implementation.
"""

from __future__ import annotations

import json
from typing import Any

import yaml
from pydantic import ValidationError

from .controls import CONTROLS
from .guard import Guard
from .models import Verdict
from .policy import Policy

_guard: Guard | None = None


def _g() -> Guard:
    global _guard
    if _guard is None:
        _guard = Guard(Policy.default())
    return _guard


def _ok(**kw: Any) -> str:
    return json.dumps({"ok": True, **kw}, ensure_ascii=False, default=str)


def _err(msg: str) -> str:
    return json.dumps({"ok": False, "error": msg}, ensure_ascii=False)


def default_policy_yaml() -> str:
    from pathlib import Path
    return (Path(__file__).parent / "policies" / "default.yaml").read_text(encoding="utf-8")


def controls() -> str:
    return json.dumps(CONTROLS, ensure_ascii=False)


def set_policy(text: str) -> str:
    try:
        policy = Policy.from_yaml(text)
    except yaml.YAMLError as e:
        return _err(f"YAML syntax error: {e}")
    except ValidationError as e:
        lines = []
        for err in e.errors()[:6]:
            loc = " → ".join(str(x) for x in err["loc"])
            lines.append(f"{loc}: {err['msg']}")
        return _err("Policy is invalid:\n" + "\n".join(lines))
    except ValueError as e:
        return _err(str(e))
    _g().set_policy(policy)
    return _ok(name=policy.name, tools=sorted(policy.tools))


def check(payload: str) -> str:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as e:
        return _err(f"Not valid JSON: {e.msg} (line {e.lineno}, column {e.colno})")
    if not isinstance(data, dict) or not isinstance(data.get("tool"), str):
        return _err('Expected an object like {"tool": "name", "args": {...}}')
    args = data.get("args", {})
    if not isinstance(args, dict):
        return _err('"args" must be an object')
    d = _g().check(data["tool"], args, session=str(data.get("session", "demo")))
    return _ok(decision=_decision_json(d), entry=_g().audit.entries[-1])


def approve(decision_id: str, reviewer: str, approved: bool, note: str = "") -> str:
    try:
        final = _g().approve(decision_id, reviewer=reviewer, approved=approved, note=note)
    except (KeyError, ValueError) as e:
        return _err(str(e).strip("'\""))
    return _ok(verdict=final.value, entry=_g().audit.entries[-1])


def log() -> str:
    return json.dumps(_g().audit.entries, ensure_ascii=False, default=str)


def export_jsonl() -> str:
    return _g().audit.to_jsonl()


def verify() -> str:
    r = _g().audit.verify()
    return _ok(valid=r.ok, checked=r.checked, broken_at=r.broken_at, reason=r.reason, head=_g().audit.head)


def tamper(seq: int) -> str:
    """Demo only: quietly rewrite one record, the way an insider might try to."""
    entries = _g().audit.entries
    if not 0 <= seq < len(entries):
        return _err("no such record")
    e = entries[seq]
    if e.get("kind") == "decision":
        before = e.get("verdict")
        e["verdict"] = "allow" if before != "allow" else "deny"
        change = f"verdict {before} → {e['verdict']}"
    elif e.get("kind") == "review":
        e["reviewer"] = "someone-else"
        change = "reviewer → someone-else"
    else:
        e["policy"] = "edited"
        change = "policy name edited"
    return _ok(seq=seq, change=change)


def reset() -> str:
    global _guard
    keep = _guard.policy if _guard else Policy.default()
    _guard = Guard(keep)
    return _ok()


def reset_session(session: str = "demo") -> str:
    _g().reset_session(session)
    return _ok()


def benchmark(cases_yaml: str) -> str:
    """Run the attack/benign suite against the *current* policy in a fresh guard."""
    from .bench import run_cases
    cases = yaml.safe_load(cases_yaml)["cases"]
    return json.dumps(run_cases(cases, _g().policy), ensure_ascii=False)


def _decision_json(d) -> dict[str, Any]:
    return {
        "id": d.id,
        "tool": d.call.tool,
        "verdict": d.verdict.value,
        "risk": d.risk,
        "latency_ms": d.latency_ms,
        "findings": [
            {"check": f.check, "message": f.message, "severity": f.severity.value, "arg": f.arg, "controls": f.controls}
            for f in d.findings
        ],
        "controls": d.controls,
        "pending": d.verdict is Verdict.REVIEW,
    }
