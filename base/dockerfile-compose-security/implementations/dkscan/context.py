"""What a run knows about the repository: whether an agent made the commit, and which sibling gates are installed.

A form another gate already reads on one line is left to that gate only when its compiled gate file here
(`.chock/compiled/<id>/**/gate.json`) is readable and blocks, and its scope covers the path; a bare folder or a
gate that only warns never counts. Otherwise this bundle reports it, so a missing or weaker sibling never turns
a deferral into a miss.
"""

from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

HUMAN = {"0", "false", "no", "off"}
GATE_LIMIT = 1 << 20
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


def blocking_gate(compiled: Path, sibling: str) -> dict | None:
    """The `params` of a sibling's compiled gate file when it blocks; None for a bare folder, a symlink, an unreadable file or any other action."""
    folder = compiled / sibling
    try:
        if folder.is_symlink() or not folder.is_dir():
            return None
        files = [*folder.glob("gate.json"), *folder.glob("*/gate.json")]
        for gate in sorted(files):
            if gate.is_symlink() or not gate.is_file() or gate.stat().st_size > GATE_LIMIT:
                continue
            doc = json.loads(gate.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and doc.get("action") == "block":
                params = doc.get("params")
                return params if isinstance(params, dict) else {}
    except (OSError, ValueError, RecursionError):
        return None
    return None


def compile_pattern(params: dict) -> re.Pattern[str] | None:
    """The content_pattern a sibling's gate carries, compiled; None when it is absent, empty or not a pattern."""
    text = params.get("content_pattern")
    if not isinstance(text, str) or not text:
        return None
    try:
        return re.compile(text)
    except re.error:
        return None


class Repo:
    """The repository a run judges, and the sibling gates installed in it (a compiled gate file at action block)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        compiled = root / ".chock" / "compiled"
        self.gates = {
            name: params
            for name in (FETCH_EXEC_GATE, PINS_GATE, AGENTIC_GATE)
            if (params := blocking_gate(compiled, name)) is not None
        }

    def fetch_exec_pattern(self, path: str) -> re.Pattern[str] | None:
        """The pattern block-fetch-exec-in-files blocks with, when it covers `path`."""
        params = self.gates.get(FETCH_EXEC_GATE)
        covers = any(fnmatchcase(path, glob) for glob in FETCH_EXEC_PATHS)
        return compile_pattern(params) if params is not None and covers else None

    def pins_reads(self) -> bool:
        return PINS_GATE in self.gates

    def node_tls_reads(self, path: str) -> bool:
        return AGENTIC_GATE in self.gates and bool(AGENTIC_DOCKERFILE.match(PurePosixPath(path).name))
