#!/usr/bin/env python3
"""Report git history, a long code block, a duplicate or a secret in an agent-memory file; the engine keeps the new."""

from __future__ import annotations

import hashlib
import json
import re
import sys

MEMORY_PATH = re.compile(r"(^|/)MEMORY\.md$|^CLAUDE\.local\.md$|^\.claude/memory/|^memory/.+\.md$")
# Absolute paths only: the gate's `outside_repo` globs (the manifest) are what lets one reach this script.
OUTSIDE_MEMORY = re.compile(
    r"^(/|[A-Za-z]:/)(.*/)?(\.claude/projects/[^/]+/memory/.|\.claude/CLAUDE\.md$)|^/memories/."
)
HISTORY = re.compile(
    r"^diff --git |^@@ -\d+(,\d+)? \+\d+(,\d+)? @@|^commit [0-9a-f]{40}$|^index [0-9a-f]{7,}\.\.[0-9a-f]{7,}"
)
# scan-secrets' content_pattern, verbatim; tests/policies/test_guard_memory_writes.py fails on drift.
SECRET = re.compile(
    r"""(?ix)
# v1 shapes, unchanged
(AKIA|ASIA)[0-9A-Z]{16}
|gh[oprsu]_[0-9A-Za-z]{36}
|github_pat_[0-9A-Za-z_]{22,}
|xox[bpas]-[0-9A-Za-z-]{10,}
|(sk|rk)_live_[0-9A-Za-z]{16,}
|sk-proj-[0-9A-Za-z_-]{20,}
|sk-ant-[0-9A-Za-z_-]{20,}
|sk-[0-9A-Za-z]{20,}
|AIza[0-9A-Za-z_-]{35}
|npm_[0-9A-Za-z]{36}
|SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}
|eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*
|api[_-]?key\s*=\s*["'][A-Za-z0-9_\-]{20,}["']
|secret[_-]?key\s*=\s*["'][A-Za-z0-9_\-]{20,}["']
|auth[_-]?token\s*=\s*["'][A-Za-z0-9_\-]{20,}["']
|password\s*=\s*["'][^"'\s]{12,}["']
|(api|secret|auth)[_-]?(key|token)\s*[=:]\s*[A-Za-z0-9_\-]{20,}
# v1 bare password, now silent on SOPS, vault:, Terraform references and environment lookups
|password\s*[=:]\s*(?!ENC\[|vault:|(?:var|local|data|module|each|self)\.|[\w.]*(?:env|getenv|environ)[.(\[])[^\s"'${}]{12,}
# private keys: any PEM label ending PRIVATE KEY (RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS8), PGP armor
|-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE\ KEY(?:\ BLOCK)?-----
# key, token, secret and password names, any case and separator, in JSON, YAML, env, HCL, Go, Ruby, PHP
|(?:api[_.-]?key|secret[_.-]?(?:access[_.-]?)?key|access[_.-]?key|(?:client|consumer|jwt)[_.-]?secret
   |(?:auth|access|refresh|api|bearer)[_.-]?token|private[_.-]?key|passw(?:or)?d|passphrase)
 ["'`]?\s*(?::=|=>|\?=|[:=])\s*(?!=)(?P<kv_quote>["'`])?
 (?!(?:\$|\{\{|%[({]|\#\{|<|\[\[|\*{3}|x{4}|\.\.\.|\.{1,2}/|~/|/(?:etc|home|usr|var|opt|run|tmp|srv|root|Users|secrets?|keys?|certs?|config)/
   |[a-z]:\\|file:|ENC\[|vault:|(?:var|local|data|module|each|self)\.|arn:aws:|projects/|@Microsoft\.KeyVault|secretKeyRef|[\w.]*(?:env|getenv|environ)[.(\[]
   |your|my[_-]|example|sample|dummy|fake|placeholder|change[_-]?me|replace[_-]?me|redacted|todo\b|none\b|null\b|insert|enter))
 (?(kv_quote)(?=[^"'`\s]*[^a-z._\-"'`\s])[^"'`\s]{12,}["'`]
   |(?=[A-Za-z0-9/+=_~-]*\d)(?![A-Za-z0-9/+=_~-]*(?-i:Key|Token|Secret|Passw|Type|Str|Bytes|Cred))
    [A-Za-z0-9/+=_~-]{16,}(?=[\s,;)\]}]|$))
# credentials in a URI: scheme://user:password@host, not localhost or example hosts, not a placeholder
|\b[a-z][a-z0-9+.-]{1,20}://(?P<uri_user>[^\s/:@'"]*):(?!(?P=uri_user)@)
 (?!(?:\$|\{|<|%|\*|\\|x{3}|\.\.\.|(?:pass(?:word|wd)?|pwd|secret|changeme|token|example|dummy|redacted|placeholder)@))
 [^\s/:@'"]{3,}@(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|(?:[\w-]+\.)*example(?:\.(?:com|org|net))?|host|hostname)(?:[:/\s'"]|$))
# Authorization header literals
|\bauthorization["'`]?\s*[:=,]\s*["'`]?(?!(?:bearer|token)\s+[A-Za-z._~+/-]+(?:["'`\s,;)]|$))
 (?:bearer|basic|token)\s+(?!(?:\$|\{|<|%|\*|x{3}|\.\.\.|your|example))[A-Za-z0-9._~+/-]{12,}
# passwords passed on a command line
|\bcurl\b.{0,200}\s(?:-u|--user)[=\s]+["']?[^\s:"']+:(?!(?:\$|\{|<|%|\*|\\|x{3}|\.\.\.|(?:pass(?:word|wd)?|pwd|secret|changeme|token)(?:["'`\s,;)]|$)))[^\s"'`]{3,}
|\b(?:docker|podman|oras)\s+login\b.{0,200}\s(?:-p|--password)[=\s]+["']?(?!(?:\$|\{|<|%|\*|\\|x{3}|\.\.\.|(?:pass(?:word|wd)?|pwd|secret|changeme)(?:["'`\s,;)]|$)))[^\s"'`]{3,}
|\bmysql(?:dump|admin|sh)?\b.{0,200}\s(?-i:-p)(?!(?:\$|\{|<|%|\*|\\|x{3}|\.\.\.|(?:pass(?:word|wd)?|pwd|secret|changeme)(?:["'`\s,;)]|$)))[^\s"'`]{3,}
|\bsshpass\s+(?-i:-p)\s*["']?(?!(?:\$|\{|<|%|\*|\\|x{3}|\.\.\.|(?:pass(?:word|wd)?|pwd|secret|changeme)(?:["'`\s,;)]|$)))[^\s"'`]{3,}
# vendor token shapes (case-sensitive)
|(?-i:\bgl(?:pat|dt|rtr?|cbt|ptt|ft|imt|agent|oas|soat|ffct|wt)-[0-9A-Za-z_-]{20,})
|(?-i:\bGR1348941[0-9A-Za-z_-]{20,})
|(?-i:\b(?:hf|api_org)_[A-Za-z0-9]{34}\b)
|(?-i:\bya29\.[0-9A-Za-z_-]{20,})
|(?-i:hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9]{8,}/[A-Za-z0-9/]{16,})
|(?-i:\bxox[er]-[0-9A-Za-z-]{10,}|\bxoxe\.xox[bp]-[0-9A-Za-z-]{10,}|\bxapp-\d-[0-9A-Za-z-]{10,})
|(?-i:\bSK[0-9a-f]{32}\b)
|(?-i:\bdapi[0-9a-f]{32}\b)
|(?-i:\bdp\.(?:pt|st|sa|said|ct|scim|audit)\.(?:[a-z0-9_-]{2,35}\.)?[0-9A-Za-z]{40,})
|(?-i:\bpul-[0-9a-f]{40}\b)
|(?-i:\bhv[sbr]\.[0-9A-Za-z_-]{24,})
|(?-i:\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b)
|(?-i:\bsntry[usai]_[0-9A-Za-z+/=_]{40,})
|(?-i:\bglsa_[0-9A-Za-z]{32}_[0-9a-fA-F]{8}\b|\bglc_[0-9A-Za-z+/]{32,})
|(?-i:\bdo[por]_v1_[0-9a-f]{64}\b)
|(?-i:\blin_(?:api|oauth)_[0-9A-Za-z]{40}\b)
|(?-i:\bntn_[0-9A-Za-z]{40,}|\bsecret_[0-9A-Za-z]{43}\b)
|(?-i:\bpplx-[0-9A-Za-z]{48}\b)
|(?-i:\bpscale_(?:tkn|oauth|pw)_[0-9A-Za-z_=.-]{32,})
|(?-i:\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b)
|(?-i:\bHRKU-[0-9A-Za-z_-]{36,})
|(?-i:\bpypi-[0-9A-Za-z_-]{85,})
|(?-i:\brubygems_[0-9a-f]{48}\b)
|(?-i:\bsk-(?:svcacct|admin)-[0-9A-Za-z_-]{20,})"""
)
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
BULLET = re.compile(r"^([-*+]|\d+[.)])\s+")
MAX_BLOCK_LINES = 20


def fenced_blocks(lines: list[str]) -> tuple[set[int], list[tuple[int, int]]]:
    """(line numbers inside any fence, [(opening line, body length)] for each block)."""
    inside: set[int] = set()
    blocks: list[tuple[int, int]] = []
    opener: tuple[int, str] | None = None
    for number, line in enumerate(lines, 1):
        match = FENCE.match(line)
        if opener is None:
            if match:
                opener = (number, match.group(1))
                inside.add(number)
        elif match and match.group(1)[0] == opener[1][0] and len(match.group(1)) >= len(opener[1]):
            blocks.append((opener[0], number - opener[0] - 1))
            inside.add(number)
            opener = None
        else:
            inside.add(number)
    if opener:
        blocks.append((opener[0], len(lines) - opener[0]))
    return inside, blocks


def normalize(line: str) -> str:
    return BULLET.sub("", " ".join(line.split()))


def duplicates(lines: list[str], skip: set[int]) -> list[tuple[int, int]]:
    """(later line, first line) for each repeated entry; headings, blanks and fenced code ignored."""
    first: dict[str, int] = {}
    repeats = []
    for number, line in enumerate(lines, 1):
        key = normalize(line)
        if number in skip or key.startswith("#") or not any(c.isalnum() for c in key):
            continue
        if key in first:
            repeats.append((number, first[key]))
        else:
            first[key] = number
    return repeats


def _row(reason: str, path: str, number: int, fingerprint: str, message: str) -> dict:
    """One finding; its key is the reason and a fingerprint of what was flagged, never a line number."""
    return {"key": f"{reason}|{fingerprint}", "path": path, "line": number, "message": message}


def judge(path: str, text: str) -> list[dict]:
    """Every finding in one memory file, in line order; the engine keeps the ones a change adds."""
    lines = text.splitlines()
    inside, blocks = fenced_blocks(lines)
    found: dict[int, dict] = {}
    for number, line in enumerate(lines, 1):
        if HISTORY.search(line):
            found[number] = _row("history", path, number, normalize(line), "pasted git history")
        elif SECRET.search(line):
            # Hashed: a key is printed and logged, and it must never carry the flagged text itself.
            digest = hashlib.sha256(normalize(line).encode("utf-8")).hexdigest()[:16]
            found[number] = _row("secret", path, number, digest, "secret")
    for start, length in blocks:
        if length > MAX_BLOCK_LINES:
            message = f"fenced code block of {length} lines (limit {MAX_BLOCK_LINES})"
            body = "\n".join(normalize(line) for line in lines[start : start + length])
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
            fingerprint = f"{normalize(lines[start - 1])}|{digest}"
            found.setdefault(start, _row("long-block", path, start, fingerprint, message))
    for number, original in duplicates(lines, inside):
        repeat = _row("duplicate", path, number, normalize(lines[number - 1]), f"duplicates line {original}")
        found.setdefault(number, repeat)
    return [row for _, row in sorted(found.items())]


def findings(payload: dict) -> list[dict]:
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        if MEMORY_PATH.search(norm) or OUTSIDE_MEMORY.match(norm):
            found += judge(norm, text)
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("guard-memory-writes: stdin is not the gate JSON", file=sys.stderr)
        return 2
    found = findings(payload)
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("guard-memory-writes: memory must not hold this (path:line):", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "Keep memory to short, non-derivable facts: link to a commit or file instead of pasting "
        "it, drop duplicates, never store a secret (rotate any that was written). No waiver exists.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
