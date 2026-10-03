#!/usr/bin/env python3
"""Refuse an Edit or Write to agent configuration, and ask about instruction files under docs/; a link is judged by what it names."""

from __future__ import annotations

import json
import os
import posixpath
import sys
from pathlib import Path

# The path modules ship beside this script. A missing or broken copy raises here, and the runner
# treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pathlink import follow
from pathset import ASK, BLOCK, normalise, verdict

# What the engine itself writes during a turn: its session log would fail the turn's-end walk. The shell guard still protects them.
ENGINE_OWN = (".chock/state", ".chock/log")
BLOCKED = (
    "This path is agent configuration or enforcement (instruction files, permission files, the dependency allowlist, "
    "vendored gates, policy implementations, whole agent folders). An agent must not edit its own guardrails through "
    "the Edit or Write tools. Propose the change to a human -- say which file and what should change and why -- and "
    "wait for approval; regenerate managed files with `chock sync`. A person edits these files from their own shell."
)
ASKED = (
    "This is an instruction file under docs/: documentation about a guardrail file, but the same name is read as "
    "instructions where it sits. A person decides: say which file should change, what and why, and let them approve "
    "the edit or make it from their own shell."
)


def relative(root: Path, path: str) -> str:
    """The path from the repository folder, `..` folded and Windows separators read as slashes."""
    folded = posixpath.normpath(path.replace("\\", "/"))
    if folded.startswith("/") and (here := os.path.relpath(folded, root)) and not here.startswith(".."):
        return here
    return folded


def engine_own(rel: str) -> bool:
    """Whether a path is something the engine writes itself."""
    normal = normalise(rel)
    return any(normal == own or normal.startswith(own + "/") for own in ENGINE_OWN)


def judge(root: Path, path: str) -> str:
    """`block`, `ask` or an empty string: the strictest verdict of the path as written, folded, and followed through its links."""
    rel = relative(root, path)
    if engine_own(rel):
        return ""
    real = os.path.realpath(root)
    followed = follow(real, path.replace("\\", "/"))  # a `..` after a link is read as written, not folded
    if followed is None:
        return BLOCK
    named = [path, rel, *(os.path.relpath(f, real) if f.startswith(real + "/") else f for f in followed)]
    kinds = {verdict(name, real) for name in named}
    return BLOCK if BLOCK in kinds else ASK if ASK in kinds else ""


def main() -> int:
    material = json.load(sys.stdin)
    root = Path(material["repo_root"])
    kinds = {path: judge(root, path) for path in sorted(material["writes"])}
    blocked = [p for p, kind in kinds.items() if kind == BLOCK]
    asked = [p for p, kind in kinds.items() if kind == ASK]
    if blocked:
        print("\n".join([BLOCKED, *(f"  - {p}: forbidden path" for p in blocked)]), file=sys.stderr)
        return 1
    if asked:
        print("\n".join([ASKED, *(f"  - {p}: instruction file under docs/" for p in asked)]), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
