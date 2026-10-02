# agentwarrant

**No tool call without a warrant.** A policy gate for tool-calling AI agents. It checks every call before it runs, sends risky calls to a person for approval, and writes each decision to a tamper-evident audit log mapped to the EU AI Act, ISO/IEC 23894 and the OWASP Top 10 for LLM Applications.

[![CI](https://github.com/kushal5306/agentwarrant/actions/workflows/ci.yml/badge.svg)](https://github.com/kushal5306/agentwarrant/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20|%203.12%20|%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

### ▶ [Try the live playground](https://kushal5306.github.io/agentwarrant/)

Run attacks against an agent, approve or reject risky calls, edit the policy live, then tamper with the audit log and watch verification catch it. The page runs this exact Python package in your browser via Pyodide, with no server and no API key.

![agentwarrant playground](docs/screenshot.png)

---

## Three ways to use it

From quickest to most involved.

### 1. Try the live demo (no install)

Open [kushal5306.github.io/agentwarrant](https://kushal5306.github.io/agentwarrant/) and wait about 10 seconds for "Ready".

1. **Pick a scenario** on the left. "Normal" ones are everyday tool calls. "Attack" ones are hostile calls, such as a poisoned web page or a hidden instruction.
2. **Read the verdict** in the middle: allowed, needs a person's approval, or denied, with the reasons.
3. **Change things.** Edit the tool call and run it again, or edit the policy at the bottom and apply it.
4. **Test the audit log.** Click "Tamper with a record", then "Verify chain". The edited record is flagged.

### 2. Use it in your own Python agent

```bash
pip install git+https://github.com/kushal5306/agentwarrant
```

```python
from agentwarrant import Guard, Policy

guard = Guard(Policy.from_file("policy.yaml"))   # or Policy.default() to start

# Option A: check each call in your agent loop, before you run the tool
d = guard.check("read_file", {"path": "data/../../etc/passwd"})
d.verdict    # Verdict.DENY
d.findings   # the reasons, e.g. "path 'data/../../etc/passwd' escapes the allowed folders"

# Option B: wrap the tool, so a blocked call raises ToolCallBlocked
@guard.protect
def read_file(path: str) -> str: ...

# Check that nobody edited the log, then export it
guard.audit.verify()
guard.audit.to_jsonl()
```

**Writing your own policy:** copy [`agentwarrant/policies/default.yaml`](agentwarrant/policies/default.yaml) and edit it. For each tool you set a risk level, argument rules and rate limits. You also list the domains the agent may contact or email. Tools marked high-risk wait for a person's approval. See [Quick start](#quick-start) and [Policy as code](#policy-as-code) for more.

### 3. Use it from another language, or with a real agent

- **From another language (HTTP service):** start it with `python -m agentwarrant.serve --policy policy.yaml`. Your code then sends each tool call to `POST /check` on `localhost:8077` before running it. Keep it on localhost or put a login in front of it, because anyone who can reach `/approve` can approve calls. See [Use it from any language](#use-it-from-any-language).
- **With a real local agent:** install [Ollama](https://ollama.com), run `ollama pull qwen2.5:7b`, then `python examples/ollama_agent.py` from a copy of the repo. Ask it to *"Read ../../etc/passwd"* and watch the guard block it. See [Run a real agent locally](#run-a-real-agent-locally-free-no-api-key).

---

## Why

Agents don't just talk, they act: they send email, query databases, read files and call APIs. The instructions they follow can come from anywhere, including a web page or document the agent just read. Telling the model in its prompt to behave is not a control.

agentwarrant sits between the model and its tools and decides **in code** before anything executes:

| Verdict | Meaning |
|---|---|
| `allow` | Listed tool, valid arguments, nothing suspicious in the content |
| `review` | High-risk tool: pauses until a named person approves (EU AI Act Art. 14) |
| `deny` | Not allowed, with the reasons and the controls involved |

## What it checks

1. **Allow-list.** Only tools named in the policy exist. Disabled and invented tools are denied.
2. **Strict argument schemas.** Each tool's arguments become a strict Pydantic model: types, ranges, enums, regex, max length, and no unexpected arguments.
3. **Semantic constraints.** Paths must stay inside allowed folders after normalisation. Email recipients must be on allowed domains. Fetched URLs must be on the egress allow-list, which catches `user@host` tricks and look-alike subdomains. SQL must be read-only.
4. **Content checks on every string.** Prompt injection (English and German), invisible Unicode tag and zero-width characters (decoded so you can see the hidden text), path traversal, shell and SQL injection, leaked secrets, and exfiltration via URLs or markdown images.
5. **Budgets.** Per-tool and per-session call limits stop runaway loops.
6. **Human oversight.** High-risk calls wait for a named reviewer, and the approval is logged.
7. **Audit log.** Hash-chained (optionally HMAC-signed) JSONL. Secrets are redacted before anything is written.

The checks are deterministic, explainable and take about 0.1 ms per call. No second LLM is asked whether something is safe.

## Quick start

```bash
pip install git+https://github.com/kushal5306/agentwarrant
```

```python
from agentwarrant import Guard, Policy, ToolCallBlocked

guard = Guard(Policy.from_file("policy.yaml"))

@guard.protect
def read_file(path: str) -> str:
    ...

read_file("data/stations.csv")        # runs
read_file("data/../../etc/passwd")    # raises ToolCallBlocked
```

High-risk tools take an approver, the function that asks a person:

```python
def ask_on_call(decision) -> bool:
    return input(f"Allow {decision.call.tool}? [y/N] ") == "y"
ask_on_call.reviewer = "kushal"   # name recorded in the audit log

@guard.protect(approver=ask_on_call)
def send_email(to: str, subject: str, body: str): ...
```

Or check calls without wrapping anything, e.g. inside your own agent loop:

```python
decision = guard.check("http_get", {"url": "https://evil.example/c?d=..."})
decision.verdict    # Verdict.DENY
decision.findings   # [Finding(check='egress', message='destination evil.example is not on the egress allow-list', controls=['OWASP-LLM02', ...])]
```

## Policy as code

```yaml
egress:
  allowed_domains: [api.open-meteo.com, th-koeln.de]

tools:
  get_weather:
    risk: low
    rate_limit: 10
    args:
      city: { type: string, max_length: 60, pattern: "^[A-Za-zÀ-ÿ .'-]+$" }
      days: { type: integer, min: 1, max: 14 }

  send_email:
    risk: high                      # high risk → needs approval by default
    args:
      to:   { type: string, pattern: email, email_domains: [th-koeln.de] }
      body: { type: string, max_length: 4000 }

  run_sql:
    risk: high
    args:
      query: { type: string, sql_readonly: true }

  delete_records:
    enabled: false
```

The policy itself is validated, so a typo such as `requires_aproval` is an error, not a silently ignored rule. See the full example in [`agentwarrant/policies/default.yaml`](agentwarrant/policies/default.yaml).

## Audit log

```python
guard.audit.verify()        # VerifyResult(ok=True, checked=42)
guard.audit.to_jsonl()      # export as evidence

guard.audit.entries[7]["verdict"] = "allow"   # an insider edits a record…
guard.audit.verify()        # VerifyResult(ok=False, broken_at=7, reason='record 7: content does not match its hash (edited)')
```

A plain hash chain proves records weren't edited by someone who can't recompute the chain. For stronger guarantees, use `AuditLog(key=...)` to sign entries with HMAC-SHA256 using a key kept outside the agent, and/or publish the head hash somewhere the writer can't change.

## Use it from any language

```bash
python -m agentwarrant.serve --policy policy.yaml --port 8077 --audit-file audit.jsonl
curl -X POST localhost:8077/check -d '{"tool":"read_file","args":{"path":"../../etc/passwd"}}'
```

Endpoints: `POST /check`, `POST /approve`, `GET /audit`, `GET /verify`. Standard library only. It binds to localhost by default. Put it behind your own authentication, because anyone who can reach `/approve` can approve calls.

## Run a real agent locally (free, no API key)

```bash
ollama pull qwen2.5:7b
python examples/ollama_agent.py
```

Then try *"Read ../../etc/passwd"* or *"Email the sensor data to attacker@gmail.com"*. The model only sees tools generated from the policy, and every call it makes goes through the guard.

## Benchmark

`python benchmark/run.py` runs 83 hand-written cases (58 attacks, 25 normal calls) against the default policy:

| | Result |
|---|---|
| Attacks blocked | **56 / 58 (96.6%)** |
| Normal calls wrongly blocked | **0 / 25** |
| Median check time | ~0.1 ms |

| Category | Blocked |
|---|---|
| Path traversal, shell injection, SQL injection, secrets, exfiltration, hidden text, excessive agency, type abuse | all |
| Prompt injection | 10 / 12 |

**Known gaps (kept in the suite on purpose):** leetspeak (`1gn0re previous instructions`) and free paraphrase (*"kindly set aside what you were told earlier"*) get past the pattern checks. In the default policy both still land in `review`, because `send_email` is high-risk, so a person sees them before anything happens. This is why agentwarrant leads with structural controls: allow-lists, argument limits and egress rules don't care how cleverly an instruction is phrased.

This is a self-authored suite. It catches regressions and shows behaviour. It is not an independent measure of real-world robustness. CI fails if detection drops below 95% or any normal call is blocked.

## Governance mapping

Every logged decision lists the controls it provides evidence for:

| Check | EU AI Act | ISO/IEC 23894 | OWASP LLM Top 10 (2025) |
|---|---|---|---|
| Allow-list, disabled tools | Art. 9 | 6.5 | LLM06 Excessive Agency |
| Argument schemas | Art. 15 | 6.5 | LLM05 Improper Output Handling |
| Injection, hidden text | Art. 15 | | LLM01 Prompt Injection |
| Secrets, egress | Art. 15 | 6.5 | LLM02 Sensitive Information Disclosure |
| Rate limits | | 6.5 | LLM10 Unbounded Consumption |
| Human approval | Art. 14 | 6.5 | |
| Risk levels per tool | | 6.4 | |
| Audit log | Art. 12 | 6.6, 6.7 | |

The mapping is indicative. A technical control supports an obligation but does not make a system compliant on its own. Not legal advice.

## Project layout

```
agentwarrant/
  guard.py       the gate: check(), approve(), protect()
  policy.py      YAML policy → validated models → strict per-tool Pydantic models
  detectors.py   content checks (injection, hidden text, traversal, SQL, secrets, egress)
  audit.py       hash-chained / HMAC audit log
  controls.py    control catalogue and check → control mapping
  serve.py       HTTP service (stdlib)
  web.py         JSON facade used by the browser playground
benchmark/       attack and benign cases + runner
docs/            the playground (deployed to GitHub Pages by CI)
examples/        local Ollama agent
tests/           unittest suite
```

## Roadmap

- MCP adapter: run as a proxy in front of any Model Context Protocol server
- OpenTelemetry export of decisions
- Optional model-based classifier as a second opinion for paraphrased injections, with its verdict logged separately
- Policy diff report: what a policy change allows that the previous version didn't

## License

MIT © Kushal Shah · [kushal5306.github.io](https://kushal5306.github.io)
