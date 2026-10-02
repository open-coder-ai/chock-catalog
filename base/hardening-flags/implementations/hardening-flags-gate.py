#!/usr/bin/env python3
"""Report each added hardening-weakening flag in build, Cargo, Go release and kernel config files; the engine keeps the new ones."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

# The detectors and the data table ship beside this script. A missing or broken copy raises here,
# and the runner treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_scan.data_table import TableError
from hardflags import rules
from hardflags.agent import agent_commit
from hardflags.blank import split
from hardflags.logical import JOINED, logical_lines

#: (name or path pattern, kind). The first match wins; every other file is not scanned.
KINDS = (
    (re.compile(r"(^|/)(CMakeLists\.txt|[^/]+\.cmake)$"), "cmake"),
    (re.compile(r"(^|/)((GNUmakefile|[Mm]akefile)(\.(am|in|inc|local|common|config))?|[^/]+\.mk)$"), "make"),
    (re.compile(r"(^|/)meson\.build$"), "meson"),
    (re.compile(r"(^|/)configure\.ac$"), "autoconf"),
    (re.compile(r"(^|/)(Cargo\.toml|\.cargo/config(\.toml)?)$"), "toml"),
    (re.compile(r"(^|/)build\.rs$"), "rust"),
    (re.compile(r"(^|/)(\.?goreleaser(\.[\w-]+)?\.ya?ml)$"), "yaml"),
    (re.compile(r"(?i)(^|/)((Docker|Container)file(\.[\w.-]+)?|[^/]+\.(Docker|Container)file)$"), "docker"),
    (re.compile(r"(^|/)[^/]+\.(sh|bash)$"), "shell"),
    (re.compile(r"(^|/)(defconfig|[^/]*_defconfig|[^/]*\.config)$"), "kernel"),
)
#: The languages whose settings each kind of file can carry (a Makefile or script may drive any compiler).
LANGS = {
    "cmake": {"c"},
    "meson": {"c"},
    "autoconf": {"c"},
    "toml": {"rust", "c"},
    "rust": {"rust", "c"},
    "kernel": {"kernel"},
}
BUILD_LANGS = {"c", "go", "rust"}
WAIVER = re.compile(r"pragma:\s*allowlist\s+hardening-flag")
HINT = (
    "Keep the hardening setting: build with the compiler's or kernel's default, or enable the protection "
    "(stack protector, FORTIFY_SOURCE, PIE, full RELRO, a non-executable stack, CET). A reviewed exception "
    "needs a person to add 'pragma: allowlist hardening-flag' in a comment on the same line and commit from "
    "their own shell; in the agent only a setting already committed in HEAD counts."
)


def kind_of(path: str) -> str | None:
    for pattern, kind in KINDS:
        if pattern.search(path):
            return kind
    return None


def waivable(event: str, root: Path) -> bool:
    """A waiver counts only where a person staged the text, and never for a commit an agent marked as its own."""
    return event in {"commit", "ci"} and not agent_commit(root)


def hits_in(entries: list[rules.Entry], kind: str, text: str) -> Counter[tuple[str, int]]:
    """How many times each entry matches on each physical line, reading a continuation both ways."""
    code = split(kind, text)[0]
    langs = frozenset(LANGS.get(kind, BUILD_LANGS))
    best: Counter[tuple[str, int]] = Counter()
    for bare in (False, True) if kind in JOINED else (False,):
        found: Counter[tuple[str, int]] = Counter()
        section = ""
        for line, owners in logical_lines(kind, code, text, bare=bare):
            section = rules.section_of(line, section) if kind == "toml" else ""
            for entry, offset in rules.hits(entries, langs, line, section):
                found[entry.id, owners[offset]] += 1
        best |= found
    return best


def findings(payload: dict, entries: list[rules.Entry]) -> list[dict]:
    """Every weakening setting in a write, keyed by entry id (the engine compares counts per file with the baseline)."""
    waive = waivable(str(payload.get("event", "")), Path(str(payload.get("repo_root") or ".")))
    by_id = {entry.id: entry for entry in entries}
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        kind = kind_of(norm)
        if kind is None:
            continue
        notes = split(kind, text)[1].split("\n")
        lines = text.split("\n")
        for (entry_id, number), count in sorted(hits_in(entries, kind, text).items(), key=lambda kv: kv[0][::-1]):
            if waive and WAIVER.search(notes[number - 1]):
                continue
            entry = by_id[entry_id]
            message = f"{entry.tier}: {entry.what}: {lines[number - 1].strip()[:120]}"
            found += [{"key": entry_id, "path": norm, "line": number, "message": message}] * count
    return found


def verdict(found: list[dict], entries: list[rules.Entry]) -> int:
    """1 when any finding is a block entry, else 3 (ask) when there are findings, else 0."""
    tiers = {entry.id: entry.tier for entry in entries}
    if any(tiers[item["key"]] == "block" for item in found):
        return 1
    return 3 if found else 0


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        entries = rules.load()
    except (json.JSONDecodeError, RecursionError):
        print("hardening-flags: stdin is not the gate JSON", file=sys.stderr)
        return 2
    except (TableError, OSError) as exc:
        print(f"hardening-flags: the flag table cannot be used ({exc}); refusing rather than allowing", file=sys.stderr)
        return 2
    writes = payload.get("writes", {}) if isinstance(payload, dict) else None
    if not isinstance(writes, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in writes.items()):
        print("hardening-flags: the gate JSON has no writes map of text", file=sys.stderr)
        return 2
    try:
        found = findings(payload, entries)
    except (ValueError, OSError, RecursionError):
        print("hardening-flags: the gate JSON could not be judged; refusing rather than allowing", file=sys.stderr)
        return 2
    print(json.dumps({"findings": found}))
    code = verdict(found, entries)
    if code:
        print("hardening-flags: a write weakens a build or kernel hardening setting:", file=sys.stderr)
        for item in found:
            print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
        print(HINT, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
