"""Guard Claude Code's own tool calls with agentwarrant.

Run as a Claude Code PreToolUse hook. Claude Code sends each proposed tool call as
JSON on stdin; this maps it to a tool in the policy, checks it, appends the decision
to a hash-chained audit file, and answers:

    allow   -> no output, Claude Code's normal permission rules apply
    review  -> "ask": a person confirms the call in Claude Code
    deny    -> "deny": the call does not run and Claude sees the reasons

Settings (.claude/settings.json):

    {"hooks": {"PreToolUse": [{"matcher": "Bash|Read|Glob|Grep|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
      "hooks": [{"type": "command", "command": "python3 -m agentwarrant.claude_code"}]}]}}

Check the audit file:  python3 -m agentwarrant.claude_code --verify
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .guard import Guard
from .models import Verdict
from .policy import Policy

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: no locking, parallel calls may race
    fcntl = None

DEFAULT_POLICY = Path(__file__).parent / "policies" / "claude_code.yaml"
DEFAULT_AUDIT = ".agentwarrant/claude-code-audit.jsonl"

READ_TOOLS = {"Read", "Glob", "Grep"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def to_call(tool_name: str, tool_input: dict[str, Any], project: str) -> tuple[str, dict[str, Any]] | None:
    """Map a Claude Code tool call to a policy tool and its arguments. None means not guarded."""
    if tool_name == "Bash":
        tool = "run_shell_unsandboxed" if tool_input.get("dangerouslyDisableSandbox") else "run_shell"
        return tool, {"command": str(tool_input.get("command", ""))}
    if tool_name == "WebFetch":
        return "http_get", {"url": str(tool_input.get("url", ""))}
    if tool_name in READ_TOOLS or tool_name in WRITE_TOOLS:
        raw = tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path") or project
        # realpath: a symlink inside the project that points at ~/.ssh is judged by where it points
        path = os.path.realpath(os.path.join(project, os.path.expanduser(str(raw))))
        root, tmp = os.path.realpath(project), os.path.realpath(tempfile.gettempdir())
        kind = "read" if tool_name in READ_TOOLS else "write"
        if _inside(path, root):
            return f"{kind}_project", {"path": os.path.relpath(path, root)}
        if _inside(path, tmp):
            return f"{kind}_temp", {"path": path}
        return f"{kind}_outside", {"path": path}
    return None


def _open_audit(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    f = path.open("a+", encoding="utf-8")
    if fcntl is not None:
        fcntl.flock(f, fcntl.LOCK_EX)  # parallel tool calls must not fork the chain
    f.seek(0)
    return f, AuditLog.from_jsonl(f.read(), sink=f)


def decide(event: dict[str, Any], policy: Policy, audit_path: Path) -> dict[str, Any] | None:
    project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
    mapped = to_call(event.get("tool_name", ""), event.get("tool_input") or {}, project)
    if mapped is None:
        return None
    tool, args = mapped
    f, log = _open_audit(audit_path)
    try:
        d = Guard(policy, audit=log).check(tool, args, session=str(event.get("session_id", "default")))
    finally:
        f.close()
    if d.verdict is Verdict.ALLOW:
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny" if d.verdict is Verdict.DENY else "ask",
        "permissionDecisionReason": f"agentwarrant: {d.summary()}",
    }}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="agentwarrant as a Claude Code PreToolUse hook")
    ap.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    ap.add_argument("--audit-file", type=Path, help=f"default: <project>/{DEFAULT_AUDIT}")
    ap.add_argument("--verify", action="store_true", help="verify the audit file and exit")
    a = ap.parse_args(argv)
    audit_path = a.audit_file or Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()) / DEFAULT_AUDIT

    if a.verify:
        log = AuditLog.from_jsonl(audit_path.read_text(encoding="utf-8") if audit_path.exists() else "")
        r = log.verify()
        print(f"{audit_path}: {'ok' if r.ok else 'BROKEN'}, {r.checked} records checked" + (f", {r.reason}" if r.reason else ""))
        return 0 if r.ok else 1

    try:
        out = decide(json.load(sys.stdin), Policy.from_file(a.policy), audit_path)
    except Exception as e:  # fail open, loudly: a broken hook must not lock the agent out of fixing it
        print(f"agentwarrant hook error, call not checked: {e!r}", file=sys.stderr)
        return 1
    if out is not None:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
