"""Tamper-evident audit log.

Each entry stores the hash of the previous entry, so changing, deleting or
reordering any record breaks every hash after it. A plain hash chain proves that
records were not edited *after the fact by someone who cannot recompute the
chain*. For stronger guarantees pass a secret ``key`` (entries are then signed
with HMAC-SHA256) and/or publish the latest head hash somewhere the writer cannot
change (a ticket, a commit, a timestamping service).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str = ""

    def __bool__(self) -> bool:  # allows `assert log.verify()`
        return self.ok


class AuditLog:
    def __init__(self, key: bytes | None = None, sink: Any = None):
        """``sink`` is an optional writable text file; each entry is appended as one JSON line."""
        self.entries: list[dict[str, Any]] = []
        self._key = key
        self._sink = sink

    # --- writing -----------------------------------------------------------------
    def _digest(self, body: dict[str, Any]) -> str:
        data = _canonical(body)
        if self._key:
            return hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = {
            "seq": len(self.entries),
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "kind": kind,
            **payload,
            "prev_hash": self.head,
        }
        entry = {**body, "hash": self._digest(body)}
        self.entries.append(entry)
        if self._sink is not None:
            self._sink.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            self._sink.flush()
        return entry

    # --- checking ------------------------------------------------------------------
    def verify(self) -> VerifyResult:
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("seq") != i:
                return VerifyResult(False, i, i, f"record {i}: sequence number is {entry.get('seq')}, expected {i}")
            if entry.get("prev_hash") != prev:
                return VerifyResult(False, i, i, f"record {i}: link to the previous record is broken")
            if not hmac.compare_digest(self._digest(body), str(entry.get("hash"))):
                return VerifyResult(False, i, i, f"record {i}: content does not match its hash (edited)")
            prev = entry["hash"]
        return VerifyResult(True, len(self.entries))

    # --- import / export -------------------------------------------------------------
    def to_jsonl(self) -> str:
        return "".join(json.dumps(e, ensure_ascii=False, default=str) + "\n" for e in self.entries)

    @classmethod
    def from_jsonl(cls, lines: str | Iterable[str], key: bytes | None = None) -> "AuditLog":
        log = cls(key=key)
        if isinstance(lines, str):
            lines = lines.splitlines()
        log.entries = [json.loads(line) for line in lines if line.strip()]
        return log

    def __len__(self) -> int:
        return len(self.entries)
