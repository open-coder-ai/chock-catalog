"""What a run knows about the repository: whether an agent made the commit, and which sibling gates are installed.

A form another gate already reads on one line is left to that gate only when the gate is installed
here (`.chock/compiled/<id>/`) and its scope covers the path; otherwise this bundle reports it, so a
missing or narrower sibling never turns a deferral into a miss.
"""

from __future__ import annotations

import os
import re
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

HUMAN = {"0", "false", "no", "off"}
FETCH_EXEC_GATE = "block-fetch-exec-in-files"
PINS_GATE = "block-unpinned-agent-components"
AGENTIC_GATE = "agentic-code-security"
#: block-fetch-exec-in-files 0.0.1 `applies_to.paths` for container builds (fnmatchcase, as the engine matches).
FETCH_EXEC_PATHS = (
    "Dockerfile*",
    "*/Dockerfile*",
    "*.Dockerfile",
    "*.dockerfile",
    "Containerfile*",
    "*/Containerfile*",
)
#: agentic-code-security reads NODE_TLS_REJECT_UNAUTHORIZED in files of its "dockerfile" kind.
AGENTIC_DOCKERFILE = re.compile(r"^dockerfile(?:\..*)?$", re.IGNORECASE)
AGENT_ENV_KEY = re.compile(r"^agent_commit_env:[ \t]*([^#\n]*)")
AGENT_ENV_ITEM = re.compile(r"^[ \t]+-[ \t]*([^\s#]+)")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def configured_agent_env(root: Path) -> list[str]:
    """Names under `agent_commit_env:` in `.chock/config.yaml`: an inline list, one name, or `- NAME` lines."""
    try:
        lines = (root / ".chock" / "config.yaml").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    raw: list[str] = []
    block = False
    for line in lines:
        item = AGENT_ENV_ITEM.match(line) if block else None
        if item:
            raw.append(item.group(1))
            continue
        if block and (not line.strip() or line.lstrip().startswith("#")):
            continue
        key = AGENT_ENV_KEY.match(line)
        block = bool(key) and not key.group(1).strip()
        if key:
            raw.extend(part for part in key.group(1).strip().strip("[]").split(",") if part.strip())
    names = (name.strip().strip("'\"") for name in raw)
    return [name for name in names if NAME.fullmatch(name)]


def agent_commit(root: Path) -> bool:
    """The engine's test for an agent's commit (runner.agent_signal), which a script cannot import."""
    explicit = os.environ.get("CHOCK_AGENT_COMMIT", "").strip().lower()
    if explicit in HUMAN:
        return False
    return bool(
        explicit
        or os.environ.get("CLAUDECODE") == "1"
        or os.environ.get("AI_AGENT", "").strip()
        or any(os.environ.get(name) for name in configured_agent_env(root))
    )


class Repo:
    """The repository a run judges, and the sibling gates installed in it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        compiled = root / ".chock" / "compiled"
        self.installed = {d.name for d in compiled.iterdir() if d.is_dir()} if compiled.is_dir() else set()

    def fetch_exec_reads(self, path: str) -> bool:
        return FETCH_EXEC_GATE in self.installed and any(fnmatchcase(path, glob) for glob in FETCH_EXEC_PATHS)

    def pins_reads(self) -> bool:
        return PINS_GATE in self.installed

    def node_tls_reads(self, path: str) -> bool:
        return AGENTIC_GATE in self.installed and bool(AGENTIC_DOCKERFILE.match(PurePosixPath(path).name))
