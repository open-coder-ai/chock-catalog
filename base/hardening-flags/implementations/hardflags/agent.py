"""Whether the commit is an agent's: the engine's own test (runner.agent_signal), which this script cannot import."""

from __future__ import annotations

import os
import re
from pathlib import Path

HUMAN = {"0", "false", "no", "off"}


def configured_agent_env(root: Path) -> list[str]:
    """Names under `agent_commit_env:` in `.chock/config.yaml`: an inline list, one name, or `- NAME` lines."""
    try:
        lines = (root / ".chock" / "config.yaml").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    raw: list[str] = []
    block = False
    for line in lines:
        item = re.match(r"^[ \t]+-[ \t]*([^\s#]+)", line) if block else None
        if item:
            raw.append(item.group(1))
            continue
        if block and (not line.strip() or line.lstrip().startswith("#")):
            continue
        key = re.match(r"^agent_commit_env:[ \t]*([^#\n]*)", line)
        block = bool(key) and not key.group(1).strip()
        if key:
            raw.extend(part for part in key.group(1).strip().strip("[]").split(",") if part.strip())
    names = (name.strip().strip("'\"") for name in raw)
    return [name for name in names if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)]


def agent_commit(root: Path) -> bool:
    """True for an explicit CHOCK_AGENT_COMMIT, CLAUDECODE=1, AI_AGENT or a configured variable; a person's value wins."""
    explicit = os.environ.get("CHOCK_AGENT_COMMIT", "").strip().lower()
    if explicit in HUMAN:
        return False
    return bool(
        explicit
        or os.environ.get("CLAUDECODE") == "1"
        or os.environ.get("AI_AGENT", "").strip()
        or any(os.environ.get(name) for name in configured_agent_env(root))
    )
