"""Run the guard as a small HTTP service so agents in any language can use it.

    python -m agentwarrant.serve --policy my_policy.yaml --port 8077

    POST /check    {"tool": "...", "args": {...}, "session": "..."}  -> decision
    POST /approve  {"decision_id": "...", "reviewer": "...", "approved": true, "note": ""}
    GET  /audit    audit log as JSON lines
    GET  /verify   integrity check of the audit log
    GET  /health

Uses only the standard library. Bind it to localhost or put it behind your own
authentication: anyone who can reach /approve can approve calls.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

from .audit import AuditLog
from .guard import Guard
from .policy import Policy


def make_handler(guard: Guard):
    lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "agentwarrant/0.1"

        def _send(self, code: int, body, ctype: str = "application/json") -> None:
            data = body.encode() if isinstance(body, str) else json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1_000_000:
                raise ValueError("request too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                return self._send(200, {"ok": True, "policy": guard.policy.name})
            if self.path == "/audit":
                return self._send(200, guard.audit.to_jsonl(), "application/x-ndjson")
            if self.path == "/verify":
                r = guard.audit.verify()
                return self._send(200, {"valid": r.ok, "checked": r.checked, "broken_at": r.broken_at,
                                        "reason": r.reason, "head": guard.audit.head})
            self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            try:
                body = self._json()
                with lock:
                    if self.path == "/check":
                        d = guard.check(body["tool"], body.get("args") or {}, session=str(body.get("session", "default")))
                        return self._send(200, json.loads(d.model_dump_json()) | {"allowed": d.allowed})
                    if self.path == "/approve":
                        v = guard.approve(body["decision_id"], reviewer=body.get("reviewer", ""),
                                          approved=bool(body.get("approved", True)), note=body.get("note", ""))
                        return self._send(200, {"verdict": v.value})
                self._send(404, {"error": "not found"})
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                self._send(400, {"error": str(e)})

        def log_message(self, fmt, *args):  # quieter default logging
            pass

    return Handler


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="agentwarrant policy gate over HTTP")
    ap.add_argument("--policy", type=Path, help="policy YAML (default: built-in example)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8077)
    ap.add_argument("--audit-file", type=Path, help="append the audit log to this JSONL file")
    a = ap.parse_args(argv)

    policy = Policy.from_file(a.policy) if a.policy else Policy.default()
    sink = a.audit_file.open("a", encoding="utf-8") if a.audit_file else None
    guard = Guard(policy, audit=AuditLog(sink=sink))
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(guard))
    print(f"agentwarrant: policy '{policy.name}' with {len(policy.tools)} tools on http://{a.host}:{a.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
