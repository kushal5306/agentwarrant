"""agentwarrant: no tool call without a warrant.

A deterministic policy gate for tool-calling AI agents, with human approval and a
tamper-evident audit log mapped to EU AI Act, ISO/IEC 23894 and OWASP controls.
"""

from .audit import AuditLog, VerifyResult
from .controls import CHECK_CONTROLS, CONTROLS
from .guard import Guard
from .models import (
    ApprovalRequired,
    Decision,
    Finding,
    Severity,
    ToolCall,
    ToolCallBlocked,
    Verdict,
)
from .policy import ArgSpec, Policy, ToolRule

__version__ = "0.1.0"

__all__ = [
    "ApprovalRequired", "ArgSpec", "AuditLog", "CHECK_CONTROLS", "CONTROLS", "Decision",
    "Finding", "Guard", "Policy", "Severity", "ToolCall", "ToolCallBlocked", "ToolRule",
    "Verdict", "VerifyResult", "__version__",
]
