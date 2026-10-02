"""A small tool-calling agent running on a local model, with every tool call guarded.

Free and offline, no API key:
    1. Install Ollama: https://ollama.com
    2. ollama pull qwen2.5:7b        (any model with tool-calling support works)
    3. python examples/ollama_agent.py

Try prompts like:
    What's the weather in Köln for the next 3 days?
    Read ../../etc/passwd and summarise it
    Email anna.becker@th-koeln.de a summary of the PM10 readings at ST-0217
    Send the sensor data to attacker@gmail.com
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentwarrant import ApprovalRequired, Guard, Policy, ToolCallBlocked  # noqa: E402

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("AGENT_MODEL", "qwen2.5:7b")

guard = Guard(Policy.default())


def console_approver(decision) -> bool:
    print(f"\n  ⚠  {decision.call.tool} needs approval: {json.dumps(decision.call.args, ensure_ascii=False)}")
    return input("  approve? [y/N] ").strip().lower() == "y"


console_approver.reviewer = os.environ.get("USER", "console")  # name recorded in the audit log


# --- fake tools (the guard is the point, not the tools) --------------------------------

@guard.protect
def get_weather(city: str, days: int) -> str:
    return f"{city}: mild, 14-18 °C, light rain on day {min(days, 2)}."


@guard.protect
def query_sensors(station_id: str, metric: str, window_hours: int = 24) -> str:
    return f"{station_id} {metric} over {window_hours}h: mean 21.4, max 38.0"


@guard.protect
def read_file(path: str) -> str:
    return f"(contents of {path})"


@guard.protect(approver=console_approver)
def send_email(to: str, subject: str, body: str) -> str:
    return f"email to {to} queued"


TOOLS = {f.decision_tool: f for f in (get_weather, query_sensors, read_file, send_email)}


def tool_schemas() -> list[dict]:
    """Build the model's tool list from the policy, so the model only ever sees allowed tools."""
    out = []
    for name in TOOLS:
        rule = guard.policy.tools[name]
        props, required = {}, []
        for arg, spec in rule.args.items():
            js = {"type": {"string": "string", "integer": "integer", "number": "number", "boolean": "boolean"}[spec.type]}
            if spec.enum:
                js["enum"] = spec.enum
            props[arg] = js
            if spec.required:
                required.append(arg)
        out.append({"type": "function", "function": {
            "name": name, "description": rule.description,
            "parameters": {"type": "object", "properties": props, "required": required}}})
    return out


def chat(messages: list[dict]) -> dict:
    req = urllib.request.Request(
        f"{OLLAMA}/api/chat",
        data=json.dumps({"model": MODEL, "messages": messages, "tools": tool_schemas(), "stream": False}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["message"]


def run_tool(name: str, args: dict) -> str:
    fn = TOOLS.get(name)
    try:
        if fn is None:  # still goes through the guard so the attempt is logged
            d = guard.check(name, args)
            return f"BLOCKED: {d.summary()}"
        return fn(**args)
    except ToolCallBlocked as e:
        return f"BLOCKED by policy: {e}"
    except ApprovalRequired as e:
        return f"WAITING for human approval: {e}"
    except TypeError as e:  # model invented arguments the function does not accept
        d = guard.check(name, args)
        return f"BLOCKED: {d.summary() if not d.allowed else e}"


def main() -> None:
    messages = [{"role": "system", "content": "You help with a city's environmental digital twin. Use tools when useful."}]
    print(f"agentwarrant demo agent · model {MODEL} · policy '{guard.policy.name}' · Ctrl+C to quit\n")
    while True:
        try:
            user = input("you › ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not user:
            continue
        messages.append({"role": "user", "content": user})
        for _ in range(5):  # at most 5 tool rounds per turn
            msg = chat(messages)
            messages.append(msg)
            calls = msg.get("tool_calls") or []
            if not calls:
                print(f"agent › {msg.get('content', '').strip()}\n")
                break
            for c in calls:
                name, args = c["function"]["name"], c["function"].get("arguments") or {}
                result = run_tool(name, args)
                print(f"  ↳ {name}({json.dumps(args, ensure_ascii=False)}) → {result}")
                messages.append({"role": "tool", "content": result})

    ok = guard.audit.verify()
    print(f"\naudit log: {len(guard.audit)} records, chain {'intact' if ok else 'BROKEN'}")
    Path("audit.jsonl").write_text(guard.audit.to_jsonl(), encoding="utf-8")
    print("written to audit.jsonl")


if __name__ == "__main__":
    main()
