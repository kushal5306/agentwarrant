"""Catalogue of the governance controls each check provides evidence for.

The mapping is indicative. It shows which obligation or risk a technical control
supports; running agentwarrant does not by itself make a system compliant with
anything, and none of this is legal advice.
"""

from __future__ import annotations

CONTROLS: dict[str, dict[str, str]] = {
    # EU AI Act (Regulation (EU) 2024/1689)
    "AIA-Art9": {
        "framework": "EU AI Act",
        "title": "Art. 9 Risk management system",
        "why": "Each policy rule is a documented, testable risk treatment for a known hazard.",
    },
    "AIA-Art12": {
        "framework": "EU AI Act",
        "title": "Art. 12 Record-keeping",
        "why": "Every decision is logged automatically in a hash-chained, tamper-evident record.",
    },
    "AIA-Art14": {
        "framework": "EU AI Act",
        "title": "Art. 14 Human oversight",
        "why": "High-impact tools pause until a named person approves or rejects the call.",
    },
    "AIA-Art15": {
        "framework": "EU AI Act",
        "title": "Art. 15 Accuracy, robustness and cybersecurity",
        "why": "Manipulated inputs and adversarial arguments are rejected before execution.",
    },
    # ISO/IEC 23894:2023 AI risk management (clause 6, risk management process)
    "ISO23894-6.4": {
        "framework": "ISO/IEC 23894",
        "title": "6.4 Risk assessment",
        "why": "Each tool carries a declared risk level used to decide the level of control.",
    },
    "ISO23894-6.5": {
        "framework": "ISO/IEC 23894",
        "title": "6.5 Risk treatment",
        "why": "Blocking, approval and rate limits are concrete treatments applied at runtime.",
    },
    "ISO23894-6.6": {
        "framework": "ISO/IEC 23894",
        "title": "6.6 Monitoring and review",
        "why": "Decisions and findings are observable per session and can be reviewed later.",
    },
    "ISO23894-6.7": {
        "framework": "ISO/IEC 23894",
        "title": "6.7 Recording and reporting",
        "why": "The audit log can be verified and exported as evidence.",
    },
    # OWASP Top 10 for LLM Applications (2025)
    "OWASP-LLM01": {
        "framework": "OWASP LLM Top 10",
        "title": "LLM01 Prompt Injection",
        "why": "Injected instructions inside tool arguments are detected and blocked.",
    },
    "OWASP-LLM02": {
        "framework": "OWASP LLM Top 10",
        "title": "LLM02 Sensitive Information Disclosure",
        "why": "Secrets and data leaving to unapproved destinations are stopped.",
    },
    "OWASP-LLM05": {
        "framework": "OWASP LLM Top 10",
        "title": "LLM05 Improper Output Handling",
        "why": "Model output is validated before it reaches a shell, a database or a file system.",
    },
    "OWASP-LLM06": {
        "framework": "OWASP LLM Top 10",
        "title": "LLM06 Excessive Agency",
        "why": "The agent can only use allow-listed tools with constrained arguments.",
    },
    "OWASP-LLM10": {
        "framework": "OWASP LLM Top 10",
        "title": "LLM10 Unbounded Consumption",
        "why": "Per-tool and per-session call budgets stop runaway loops.",
    },
}

# Which controls each check provides evidence for.
CHECK_CONTROLS: dict[str, list[str]] = {
    "allowlist": ["OWASP-LLM06", "AIA-Art9", "ISO23894-6.5"],
    "schema": ["OWASP-LLM05", "AIA-Art15", "ISO23894-6.5"],
    "prompt_injection": ["OWASP-LLM01", "AIA-Art15"],
    "hidden_text": ["OWASP-LLM01", "AIA-Art15"],
    "path_traversal": ["OWASP-LLM05", "AIA-Art15"],
    "sensitive_path": ["OWASP-LLM02", "OWASP-LLM05", "AIA-Art15"],
    "shell_injection": ["OWASP-LLM05", "AIA-Art15"],
    "destructive_command": ["OWASP-LLM06", "OWASP-LLM05", "AIA-Art15"],
    "sql_injection": ["OWASP-LLM05", "AIA-Art15"],
    "sql_write": ["OWASP-LLM06", "ISO23894-6.5"],
    "secret_leak": ["OWASP-LLM02", "AIA-Art15"],
    "egress": ["OWASP-LLM02", "ISO23894-6.5"],
    "rate_limit": ["OWASP-LLM10", "ISO23894-6.5"],
    "approval": ["AIA-Art14", "ISO23894-6.5"],
    "risk_level": ["ISO23894-6.4"],
    "audit": ["AIA-Art12", "ISO23894-6.6", "ISO23894-6.7"],
}


def controls_for(check: str) -> list[str]:
    return list(CHECK_CONTROLS.get(check, []))
