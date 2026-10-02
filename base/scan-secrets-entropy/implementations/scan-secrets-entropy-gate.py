#!/usr/bin/env python3
"""Report high-entropy values assigned to secret-like keys and checked vendor tokens; the engine keeps the new ones."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

# The detectors and the chock_scan copy ship beside this script. A missing or broken copy raises
# here, and the runner treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from entropyscan import tokens, values

#: scan-secrets' waiver, honoured only where a person is the actor; at an agent's commit, write or
#: turn end it is ignored here, and a waived line already in HEAD is old through the baseline run.
PRAGMA = re.compile(r"pragma:\s*allowlist\s+secret")
PERSON_EVENTS = frozenset({"commit", "push", "ci"})
#: Languages where an unquoted value is never a string literal (shell, config and template files
#: are not among them: there a bare word is a string).
SOURCE_CODE = re.compile(
    r"(?i)\.(py|pyi|js|mjs|cjs|jsx|ts|tsx|mts|cts|go|java|kt|kts|scala|groovy|cs|fs|vb|rb|php|rs|swift"
    r"|c|h|cc|cpp|cxx|hpp|m|mm|dart|lua|jl|ex|exs|erl|clj)$"
)
EXIT_ASK = 3
EXIT_UNJUDGED = 2
MESSAGES = {
    "checksum": "{kind} token whose built-in checksum verifies (shaped like an issued credential)",
    "stripe-test": "Stripe test-mode {kind} key (a credential to the account's test data)",
    "vendor-format": "{kind} credential in its issued shape",
    "card-number": "card number with a network prefix that passes the Luhn check",
}


def _digest(value: str) -> str:
    """A fingerprint of the flagged value: a key reaches the engine and may be logged, so it never carries
    the value. It is a plain digest: a guessable value (a card number from its issuer prefix) can be
    recovered from it by trying candidates, so the findings document is not a place to keep secrets."""
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _row(path: str, line: int, rule: str, value: str, message: str) -> dict:
    return {"key": f"{rule}|{_digest(value)}", "path": path, "line": line, "message": message, "rule": rule}


def judge(path: str, text: str, *, waivable: bool) -> list[dict]:
    """Every finding in one file, in line order; a binary file is not judged.

    Text where NUL is at least a third of the characters is UTF-16 and is read with NULs dropped; a
    few stray NULs are dropped too. Text where NUL or the replacement character is over one in a
    hundred characters is binary (a deliberately NUL-padded text file is a stated miss).
    """
    if _binary(text):
        return []
    lines = values.split_lines(text.replace("\x00", ""))
    rows: list[tuple[int, dict]] = []
    taken: dict[int, list[str]] = {}
    for token in tokens.found(lines):
        message = MESSAGES[token.rule].format(kind=token.kind)
        rows.append((token.line, _row(path, token.line, token.rule, token.value, message)))
        taken.setdefault(token.line, []).append(token.value)
    code = SOURCE_CODE.search(path)
    for hit in values.hits(lines, language=code[1].lower() if code else None):
        if hit.value in taken.get(hit.line, []):
            continue
        how = f"{hit.assessment.bits:.1f} bits/char, {hit.assessment.charset}"
        message = f"high-entropy value ({how}) assigned to '{hit.key}'"
        rows.append((hit.line, _row(path, hit.line, "entropy", hit.value, message)))
    kept = [row for line, row in rows if not (waivable and PRAGMA.search(lines[line - 1]))]
    return sorted(kept, key=lambda row: row["line"])


def _binary(text: str) -> bool:
    """True for decoded binary content: NULs or replacement characters, but not the UTF-16 pattern."""
    nul = text.count("\x00")
    if 3 * nul >= len(text):
        return False
    return 100 * (nul + text.count("\ufffd")) > len(text)


def findings(payload: dict) -> list[dict]:
    """Every finding across the payload's writes; ValueError when the payload is not the gate's JSON."""
    writes = payload.get("writes")
    if not isinstance(writes, dict) or not all(isinstance(t, str) for t in writes.values()):
        msg = "writes is not a {path: text} object"
        raise ValueError(msg)
    waivable = payload.get("event") in PERSON_EVENTS
    found = []
    for path, text in sorted(writes.items()):
        found += judge(str(path).replace("\\", "/"), text, waivable=waivable)
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        found = findings(payload if isinstance(payload, dict) else {})
    except ValueError as exc:
        print(f"scan-secrets-entropy: cannot judge this input ({exc})", file=sys.stderr)
        return EXIT_UNJUDGED
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("scan-secrets-entropy: possible secrets (path:line; values are never printed):", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "Move the value to an environment variable or a secret store and reference it; rotate it if "
        "it was ever real. A person who has checked a test value keeps it with 'pragma: allowlist "
        "secret' on the same line; an agent asks a person and never writes the pragma.",
        file=sys.stderr,
    )
    return EXIT_ASK


if __name__ == "__main__":
    sys.exit(main())
