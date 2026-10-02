"""Content checks that run on every string argument of a tool call.

These are deterministic pattern checks: fast, explainable and easy to audit. They
catch the common, known attack shapes. They are not a complete defence against a
determined attacker, which is why the policy's allow-list and argument
constraints come first and these checks are a second line.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

# --- hidden / smuggled text ------------------------------------------------------

_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_TAG_START, _TAG_END = 0xE0000, 0xE007F


@dataclass
class Hit:
    check: str
    message: str
    block: bool = True


def reveal_hidden(text: str) -> tuple[str, list[str]]:
    """Return text with invisible characters removed, Unicode tag characters decoded
    into visible ASCII, and a list of what was found."""
    out, tags, kinds = [], [], set()
    for ch in text:
        cp = ord(ch)
        if _TAG_START <= cp <= _TAG_END:
            kinds.add("unicode-tag")
            if 0xE0020 <= cp <= 0xE007E:
                tags.append(chr(cp - 0xE0000))
            continue
        if cp in _ZERO_WIDTH:
            kinds.add("zero-width")
            continue
        if cp in _BIDI:
            kinds.add("bidi-override")
            continue
        out.append(ch)
    visible = "".join(out)
    if tags:
        visible = visible + " " + "".join(tags)
    return visible, sorted(kinds) + ([f"decoded: {''.join(tags)!r}"] if tags else [])


def normalize(text: str) -> str:
    visible, _ = reveal_hidden(text)
    visible = unicodedata.normalize("NFKC", visible)
    # Undo common URL encoding so %2e%2e/ and friends are seen as ../
    try:
        visible = unquote(visible)
    except Exception:  # pragma: no cover - unquote is very forgiving
        pass
    return visible


# --- pattern banks ---------------------------------------------------------------

_I = re.IGNORECASE | re.DOTALL

INJECTION = [
    (r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b.{0,40}\b(instructions?|rules|prompts?|guidelines|polic(?:y|ies)|guardrails)\b",
     "asks the model to drop its instructions"),
    (r"\byou are now\b|\bfrom now on,? you\b", "tries to re-assign the model's role"),
    (r"\bnew (?:system )?instructions?\b|\b(?:system|developer) prompt\b", "references system-level instructions"),
    (r"\bdeveloper mode\b|\bjailbreak\b|\bdo anything now\b|\bDAN mode\b", "known jailbreak phrase"),
    (r"<\|?(?:im_start|im_end|system|endoftext)\|?>|\[/?(?:INST|SYS)\]|<<SYS>>", "chat-template control tokens"),
    (r"\b(?:act|pretend|behave) as (?:if you (?:were|are) )?(?:an? |the )?(?:admin(?:istrator)?|root|developer|system|superuser)\b",
     "asks the model to assume elevated privileges"),
    (r"\b(?:send|forward|e-?mail|post|upload|exfiltrate|leak)\b.{0,50}\b(?:all|every|entire|full|whole)\b.{0,40}\b(?:data|records|files|database|history|conversation|credentials|passwords|contacts|emails)\b",
     "asks for bulk data to be sent somewhere"),
    (r"\b(?:do not|don't|never) (?:tell|inform|mention|show)\b.{0,30}\b(?:user|human|anyone)\b", "asks the model to hide actions from the user"),
    # German
    (r"\bignorier(?:e|en|t)?\b.{0,40}\b(?:vorherigen|bisherigen|alle|obigen|deine)\b.{0,40}\b(?:anweisungen|regeln|instruktionen|vorgaben)\b",
     "asks the model to drop its instructions (German)"),
    (r"\bdu bist (?:jetzt|nun|ab sofort)\b", "tries to re-assign the model's role (German)"),
]

PATH = [
    (r"(?:^|[\\/\s'\"=])\.\.(?:[\\/]|$)", "parent-directory traversal (../)"),
]

SENSITIVE_PATH = [
    (r"(?:^|[\s'\"=])(?:/etc/(?:passwd|shadow|sudoers)|/proc/self|/root/|~/?\.ssh|~/?\.aws)", "targets a sensitive system path"),
    (r"(?:^|[\\/\s'\"=])(?:\.env(?!\.(?:example|sample|template)\b)\b|\.netrc\b|\.ssh[\\/]|id_(?:rsa|ecdsa|ed25519)\b)",
     "targets a credentials file"),
    (r"[a-z]:\\windows\\system32|\\\\[a-z0-9.-]+\\[a-z$]+", "targets a Windows system path or network share"),
]

SHELL = [
    (r"(?:;|&&|\|\||\|)\s*(?:rm|curl|wget|bash|sh|zsh|nc|ncat|chmod|chown|python3?|perl|cat|scp|ssh|powershell|iex)\b", "chains a shell command"),
    (r"\$\([^)]*\)|`[^`]*\b(?:rm|curl|wget|bash|sh|cat|nc|id|whoami)\b[^`]*`", "command substitution"),
]

# Kept apart from SHELL so they still run on arguments that are meant to be shell
# commands, where chaining and substitution are expected.
DESTRUCTIVE = [
    (r"\brm\s+-[a-z]*[rf][a-z]*\s+/", "recursive delete"),
    (r">&?\s*/dev/tcp/|\bmkfifo\b|\bnc\s+-e\b", "reverse-shell pattern"),
]

SQL = [
    (r"'\s*(?:or|and)\s+'?[\w]*'?\s*=\s*'?[\w]*", "tautology injection (' OR '1'='1)"),
    (r"\bunion\s+(?:all\s+)?select\b", "UNION-based injection"),
    (r";\s*(?:drop|delete|truncate|alter|insert|update|grant|create)\b", "stacked query"),
    (r"'\s*;?\s*--|'\s*#", "comment-out injection"),
    (r"\bxp_cmdshell\b|\bpg_sleep\s*\(|\bwaitfor\s+delay\b|\bsleep\s*\(\s*\d+\s*\)|\bload_file\s*\(|\binto\s+outfile\b", "dangerous SQL function"),
]

SECRETS = [
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key"),
    (r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}", "API secret key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}", "GitHub token"),
    (r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[^\s'\"]{6,}", "credential assignment"),
]

_COMPILED = {
    "prompt_injection": [(re.compile(p, _I), m) for p, m in INJECTION],
    "path_traversal": [(re.compile(p, _I), m) for p, m in PATH],
    "sensitive_path": [(re.compile(p, _I), m) for p, m in SENSITIVE_PATH],
    "shell_injection": [(re.compile(p, _I), m) for p, m in SHELL],
    "destructive_command": [(re.compile(p, _I), m) for p, m in DESTRUCTIVE],
    "sql_injection": [(re.compile(p, _I), m) for p, m in SQL],
    "secret_leak": [(re.compile(p), m) for p, m in SECRETS],
}

CONTENT_CHECKS = frozenset(_COMPILED) | {"hidden_text"}

URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"<>)\]]+", re.IGNORECASE)
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*https?://", re.IGNORECASE)
DATA_URL_RE = re.compile(r"\bdata:[a-z]+/[a-z0-9.+-]+;base64,", re.IGNORECASE)
SHELL_EXPANSION_RE = re.compile(r"\$\(|\$\{|\$[A-Za-z_]|`")
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def scan_text(text: str, skip: set[str] | None = None) -> list[Hit]:
    """Run every content check on one string."""
    skip = skip or set()
    hits: list[Hit] = []

    _, hidden = reveal_hidden(text)
    if hidden and "hidden_text" not in skip:
        hits.append(Hit("hidden_text", "contains invisible characters (" + ", ".join(hidden) + ")"))

    norm = normalize(text)
    for check, bank in _COMPILED.items():
        if check in skip:
            continue
        for rx, msg in bank:
            if rx.search(norm):
                hits.append(Hit(check, msg))
                break  # one finding per check is enough to explain the decision

    if "secret_leak" not in skip and BASE64_BLOB_RE.search(norm):
        hits.append(Hit("secret_leak", "long base64 blob, possibly encoded data", block=False))
    return hits


# --- argument-level helpers ------------------------------------------------------

def domain_allowed(host: str, allowed: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    for d in allowed:
        d = d.lower().lstrip("*.").rstrip(".")
        if host == d or host.endswith("." + d):
            return True
    return False


def check_urls(text: str, allowed: list[str], strict: bool) -> list[Hit]:
    """Egress control. strict=True for arguments that are URLs the tool will fetch."""
    hits: list[Hit] = []
    norm = normalize(text)
    if DATA_URL_RE.search(norm):
        hits.append(Hit("egress", "embeds a data: URL"))
    if MD_IMAGE_RE.search(norm):
        hits.append(Hit("egress", "markdown image link, a common zero-click exfiltration channel"))
    urls = URL_RE.findall(norm)
    if strict and not urls:
        hits.append(Hit("egress", "expected an http(s) URL"))
    for u in urls:
        try:
            parts = urlsplit(u)
        except ValueError:
            hits.append(Hit("egress", "malformed URL"))
            continue
        host = parts.hostname or ""
        if parts.username or parts.password:
            hits.append(Hit("egress", f"URL hides credentials or a fake host ({host})"))
        if domain_allowed(host, allowed):
            continue
        # $(...), `...` and $VAR are filled in by a shell at run time, so a short URL can still carry a file
        carries_data = len(parts.query) > 24 or len(parts.path) > 80 or bool(SHELL_EXPANSION_RE.search(u))
        if strict:
            hits.append(Hit("egress", f"destination {host or '?'} is not on the egress allow-list"))
        elif carries_data:
            hits.append(Hit("egress", f"link to {host} carries data in the URL, possible exfiltration"))
        else:
            hits.append(Hit("egress", f"links to non-allow-listed domain {host}", block=False))
    return hits


def path_within(value: str, prefixes: list[str]) -> Hit | None:
    v = normalize(value).replace("\\", "/")
    if v.startswith("/") or re.match(r"^[a-zA-Z]:", v) or v.startswith("~"):
        return Hit("path_traversal", f"absolute path {value!r} is outside the allowed folders")
    norm = posixpath.normpath(v)
    if norm.startswith(".."):
        return Hit("path_traversal", f"path {value!r} escapes the allowed folders")
    for p in prefixes:
        base = posixpath.normpath(p.replace("\\", "/"))
        if base == ".":  # "." means anywhere inside the working folder
            return None
        if norm == base or norm.startswith(base.rstrip("/") + "/"):
            return None
    return Hit("path_traversal", f"path {value!r} is outside {', '.join(prefixes)}")


_SQL_STRINGS = re.compile(r"'(?:[^']|'')*'")
_SQL_WRITE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|merge|copy|attach|replace|vacuum|call|exec(?:ute)?)\b",
    re.IGNORECASE,
)


def sql_readonly(query: str) -> Hit | None:
    q = _SQL_STRINGS.sub("''", normalize(query)).strip()
    first = re.match(r"\s*(\w+)", q)
    if not first or first.group(1).lower() not in {"select", "with", "explain"}:
        return Hit("sql_write", "only read-only SELECT queries are allowed")
    m = _SQL_WRITE.search(q)
    if m:
        return Hit("sql_write", f"query contains a write operation ({m.group(1).upper()})")
    if ";" in q.rstrip().rstrip(";"):
        return Hit("sql_write", "multiple statements in one query")
    return None


def redact(text: str) -> str:
    """Mask secrets before anything is written to the audit log."""
    out = text
    for rx, label in _COMPILED["secret_leak"]:
        out = rx.sub(f"[REDACTED {label}]", out)
    return out
