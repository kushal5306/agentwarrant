"""The guard: checks every proposed tool call against the policy before it runs."""

from __future__ import annotations

import functools
import inspect
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from pydantic import ValidationError

from . import detectors as d
from .audit import AuditLog
from .controls import controls_for
from .models import (
    ApprovalRequired,
    Decision,
    Finding,
    Severity,
    ToolCall,
    ToolCallBlocked,
    Verdict,
)
from .policy import Policy

Approver = Callable[[Decision], bool]

_MAX_LOGGED_CHARS = 400

# Checks that run on every call, so every logged decision is evidence for them,
# whether or not they found anything.
ALWAYS_APPLIED = ("allowlist", "schema", "audit")


def _merge(*lists: list[str]) -> list[str]:
    return list(dict.fromkeys(c for lst in lists for c in lst))


def _f(check: str, message: str, severity: Severity = Severity.BLOCK, arg: str | None = None) -> Finding:
    return Finding(check=check, message=message, severity=severity, arg=arg, controls=controls_for(check))


def _strings(value: Any, path: str):
    """Yield (path, string) for every string inside a (possibly nested) value."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")


def _redacted(value: Any) -> Any:
    if isinstance(value, str):
        v = d.redact(value)
        return v if len(v) <= _MAX_LOGGED_CHARS else v[:_MAX_LOGGED_CHARS] + f"… [+{len(v) - _MAX_LOGGED_CHARS} chars]"
    if isinstance(value, dict):
        return {k: _redacted(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redacted(v) for v in value]
    return value


class Guard:
    """Deterministic policy gate for agent tool calls.

    >>> guard = Guard.from_yaml(open("policy.yaml").read())
    >>> decision = guard.check("get_weather", {"city": "Köln", "days": 3})
    >>> decision.verdict
    <Verdict.ALLOW: 'allow'>
    """

    def __init__(self, policy: Policy, audit: AuditLog | None = None):
        self.policy = policy
        self.audit = audit if audit is not None else AuditLog()
        self._calls: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.pending: dict[str, Decision] = {}

    # --- construction ---------------------------------------------------------------
    @classmethod
    def from_yaml(cls, text: str, **kw: Any) -> "Guard":
        return cls(Policy.from_yaml(text), **kw)

    @classmethod
    def from_file(cls, path: str | Path, **kw: Any) -> "Guard":
        return cls(Policy.from_file(path), **kw)

    def set_policy(self, policy: Policy) -> None:
        """Swap the policy at runtime. Session counters and the audit log are kept."""
        self.policy = policy
        self.audit.append("policy", {"policy": policy.name, "tools": sorted(policy.tools),
                                     "controls": _merge(["AIA-Art9"], controls_for("audit"))})

    def reset_session(self, session: str = "default") -> None:
        self._calls.pop(session, None)

    # --- the check ---------------------------------------------------------------------
    def evaluate(self, call: ToolCall) -> Decision:
        """Decide without side effects: no counters, no audit entry."""
        t0 = time.perf_counter()
        findings = self._findings(call)
        rule = self.policy.tools.get(call.tool)
        risk = rule.risk if rule else "unknown"
        verdict = self._verdict(call, findings)
        return Decision(call=call, verdict=verdict, risk=risk, findings=findings,
                        latency_ms=round((time.perf_counter() - t0) * 1000, 3))

    def check(self, tool: str, args: dict[str, Any] | None = None, session: str = "default") -> Decision:
        """Decide, count the call against its budget, and write the decision to the audit log."""
        decision = self.evaluate(ToolCall(tool=tool, args=args or {}, session=session))
        if decision.verdict is not Verdict.DENY:
            self._calls[session][tool] += 1
            self._calls[session]["__total__"] += 1
        if decision.verdict is Verdict.REVIEW:
            self.pending[decision.id] = decision
        self.audit.append("decision", {
            "decision_id": decision.id,
            "session": session,
            "tool": tool,
            "args": _redacted(decision.call.args),
            "verdict": decision.verdict.value,
            "risk": decision.risk,
            "findings": [f"{f.check}: {f.message}" for f in decision.findings if f.severity is not Severity.INFO],
            "controls": _merge(decision.controls, *(controls_for(c) for c in ALWAYS_APPLIED)),
            "policy": self.policy.name,
        })
        return decision

    def approve(self, decision_id: str, reviewer: str, approved: bool = True, note: str = "") -> Verdict:
        """Record a human decision on a call that needed review (EU AI Act Art. 14)."""
        if not reviewer.strip():
            raise ValueError("a named reviewer is required")
        decision = self.pending.pop(decision_id, None)
        if decision is None:
            raise KeyError(f"no pending review with id {decision_id!r}")
        final = Verdict.ALLOW if approved else Verdict.DENY
        if not approved:  # a rejected call does not use up the budget
            self._calls[decision.call.session][decision.call.tool] -= 1
            self._calls[decision.call.session]["__total__"] -= 1
        self.audit.append("review", {
            "decision_id": decision_id,
            "session": decision.call.session,
            "tool": decision.call.tool,
            "reviewer": reviewer.strip(),
            "approved": approved,
            "note": note,
            "verdict": final.value,
            "controls": _merge(controls_for("approval"), controls_for("audit")),
        })
        return final

    # --- wrapping real tools ------------------------------------------------------------
    def protect(self, fn: Callable | None = None, *, name: str | None = None,
                approver: Approver | None = None, session: str = "default") -> Callable:
        """Decorator: the function only runs if the guard allows it.

        ``approver`` is called for calls that need review; return True to approve.
        Without an approver such calls raise ApprovalRequired.
        """
        def wrap(func: Callable) -> Callable:
            tool = name or func.__name__
            sig = inspect.signature(func)

            @functools.wraps(func)
            def inner(*a: Any, **kw: Any) -> Any:
                bound = sig.bind(*a, **kw)
                decision = self.check(tool, dict(bound.arguments), session=session)
                if decision.verdict is Verdict.DENY:
                    raise ToolCallBlocked(decision)
                if decision.verdict is Verdict.REVIEW:
                    if approver is None:
                        raise ApprovalRequired(decision)
                    ok = bool(approver(decision))
                    reviewer = getattr(approver, "reviewer", getattr(approver, "__name__", "approver"))
                    self.approve(decision.id, reviewer=str(reviewer), approved=ok)
                    if not ok:
                        raise ToolCallBlocked(decision)
                return func(*a, **kw)

            inner.decision_tool = tool  # type: ignore[attr-defined]
            return inner

        return wrap(fn) if fn is not None else wrap

    # --- internals --------------------------------------------------------------------------
    def _findings(self, call: ToolCall) -> list[Finding]:
        p = self.policy
        out: list[Finding] = []
        rule = p.tools.get(call.tool)

        # 1. allow-list
        if rule is None:
            sev = Severity.WARN if p.defaults.unknown_tools == "review" else Severity.BLOCK
            out.append(_f("allowlist", f"tool '{call.tool}' is not in the policy", sev))
            return out
        if not rule.enabled:
            out.append(_f("allowlist", f"tool '{call.tool}' is disabled by policy"))
            return out
        out.append(_f("risk_level", f"declared risk: {rule.risk}", Severity.INFO))

        # 2. budgets
        used = self._calls[call.session]
        if rule.rate_limit is not None and used[call.tool] >= rule.rate_limit:
            out.append(_f("rate_limit", f"'{call.tool}' already used {used[call.tool]}x this session (limit {rule.rate_limit})"))
        total_cap = p.defaults.max_calls_per_session
        if total_cap is not None and used["__total__"] >= total_cap:
            out.append(_f("rate_limit", f"session reached {total_cap} tool calls"))

        # 3. schema (strict Pydantic validation)
        valid = True
        try:
            p.arg_model(call.tool).model_validate(call.args)
        except ValidationError as e:
            valid = False
            for err in e.errors():
                loc = ".".join(str(x) for x in err["loc"]) or None
                msg = {
                    "extra_forbidden": f"unexpected argument '{loc}'",
                    "missing": f"missing required argument '{loc}'",
                }.get(err["type"], f"'{loc}': {err['msg']}")
                out.append(_f("schema", msg, arg=loc))

        # 4. semantic argument constraints
        for name, spec in rule.args.items():
            val = call.args.get(name)
            if not isinstance(val, str):
                continue
            if spec.path_within:
                hit = d.path_within(val, spec.path_within)
                if hit:
                    out.append(_f(hit.check, hit.message, arg=name))
            if spec.email_domains:
                dom = val.rsplit("@", 1)[-1] if "@" in val else ""
                if not d.domain_allowed(dom, spec.email_domains):
                    out.append(_f("egress", f"recipient domain '{dom or val}' is not allowed", arg=name))
            if spec.egress:
                for hit in d.check_urls(val, p.egress.allowed_domains, strict=True):
                    out.append(_f(hit.check, hit.message, Severity.BLOCK if hit.block else Severity.WARN, arg=name))
            if spec.sql_readonly:
                hit = d.sql_readonly(val)
                if hit:
                    out.append(_f(hit.check, hit.message, arg=name))

        # 5. content checks on every string argument
        if p.defaults.scan_arguments:
            for name, val in call.args.items():
                spec = rule.args.get(name)
                if spec is not None and not spec.scan:
                    continue
                # A precise path constraint replaces the generic "../" heuristic for that argument.
                skip = {"path_traversal"} if spec is not None and spec.path_within else set()
                for path, text in _strings(val, name):
                    for hit in d.scan_text(text, skip=skip):
                        out.append(_f(hit.check, hit.message, Severity.BLOCK if hit.block else Severity.WARN, arg=path))
                    if not (spec is not None and spec.egress):
                        for hit in d.check_urls(text, p.egress.allowed_domains, strict=False):
                            out.append(_f(hit.check, hit.message, Severity.BLOCK if hit.block else Severity.WARN, arg=path))

        # 6. human oversight
        blocked = any(f.severity is Severity.BLOCK for f in out)
        if valid and not blocked and (rule.requires_approval or rule.risk in p.defaults.approval_for_risk):
            out.append(_f("approval", f"{rule.risk}-risk tool: a person must approve this call", Severity.WARN))
        return _dedupe(out)

    def _verdict(self, call: ToolCall, findings: list[Finding]) -> Verdict:
        if any(f.severity is Severity.BLOCK for f in findings):
            return Verdict.DENY
        warn = [f for f in findings if f.severity is Severity.WARN]
        if self.policy.defaults.block_on_warnings and any(f.check != "approval" for f in warn):
            return Verdict.DENY
        if any(f.check in ("approval", "allowlist") for f in warn):
            return Verdict.REVIEW
        return Verdict.ALLOW


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.check, f.message, f.arg)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
