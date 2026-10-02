"""Core data types: the call an agent wants to make, and the guard's decision about it."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"  # allowed only after a human approves it
    DENY = "deny"


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    BLOCK = "block"


class ToolCall(BaseModel):
    """A tool call proposed by an agent, before anything is executed."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    session: str = "default"


class Finding(BaseModel):
    """One observation made by one check. Blocking findings turn the verdict into DENY."""

    check: str
    message: str
    severity: Severity
    arg: str | None = None
    controls: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    """The guard's answer for one tool call. This is what gets written to the audit log."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    call: ToolCall
    verdict: Verdict
    risk: str = "unknown"
    findings: list[Finding] = Field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    @property
    def controls(self) -> list[str]:
        seen: dict[str, None] = {}
        for f in self.findings:
            for c in f.controls:
                seen.setdefault(c, None)
        return list(seen)

    def summary(self) -> str:
        reasons = "; ".join(f.message for f in self.findings if f.severity is not Severity.INFO)
        return f"{self.verdict.value.upper()} {self.call.tool}" + (f" ({reasons})" if reasons else "")


class ToolCallBlocked(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.summary())
        self.decision = decision


class ApprovalRequired(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.summary())
        self.decision = decision
