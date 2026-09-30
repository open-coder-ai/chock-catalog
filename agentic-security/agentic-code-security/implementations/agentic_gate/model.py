"""What a rule reports, the file text it reads, and how a rule and a pack are declared."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import NamedTuple

ALLOW = "allow"
DENY = "deny"
VERDICTS = (ALLOW, DENY)

#: Which language or config family a path belongs to. A rule names the kinds it reads.
_SUFFIX_KINDS = {
    ".py": "python",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "js",
    ".tsx": "js",
    ".mts": "js",
    ".cts": "js",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".sh": "shell",
}
_MCP_FILES = frozenset({".mcp.json", "mcp.json", "claude_desktop_config.json"})
_TEST_PART = re.compile(r"(^|/)(tests?|__tests__|e2e)/|(^|/)test_[^/]*\.py$|_test\.py$|\.(test|spec)\.[cm]?[jt]sx?$")


class Hit(NamedTuple):
    """One construct a scan found: the 1-based line and what is wrong there."""

    line_no: int
    detail: str
    #: Other lines the finding depends on, so a change to one of them is a change to it.
    related: tuple[int, ...] = ()
    #: The finding is itself a comparison with HEAD, so it stands whatever lines the change touched.
    by_diff: bool = False


@dataclass(frozen=True)
class Finding:
    """One refused construct, carrying the rule's identity so a refusal names its evidence."""

    rule_id: str
    path: str
    line_no: int
    line: str
    message: str
    cwe: tuple[str, ...] = ()
    asi: tuple[str, ...] = ()
    related: tuple[int, ...] = ()
    by_diff: bool = False

    def render(self) -> str:
        """One line a human reads in a hook's output. The matched line is never echoed."""
        tags = ", ".join((*self.cwe, *self.asi))
        return f"{self.path}:{self.line_no}: [deny: {self.rule_id}{' ' + tags if tags else ''}] {self.message}"


@dataclass(frozen=True)
class FileText:
    """A revision of one file as a rule sees it: its whole text, its text at HEAD, its neighbours.

    `head` is the file as last committed (None for a new file, and for the baseline scan of the
    committed text itself); `others` are the texts of the other files written in the same change.
    """

    path: str
    text: str
    head: str | None = None
    others: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "text", self.text.removeprefix("﻿"))

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name

    @property
    def kind(self) -> str:
        """python, js, json, yaml, toml, shell, dockerfile, env or other."""
        name = self.name.lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            return "dockerfile"
        if name == ".env" or name.startswith(".env."):
            return "env"
        return _SUFFIX_KINDS.get(PurePosixPath(name).suffix, "other")

    @property
    def is_mcp_config(self) -> bool:
        """The agent and MCP client config files whose servers are read structurally."""
        path = PurePosixPath(self.path.lower())
        name, parent = path.name, path.parent.name
        if self.kind == "json":
            return name in _MCP_FILES or "mcp" in name or (parent == ".gemini" and name == "settings.json")
        return self.kind == "toml" and parent == ".codex" and name == "config.toml"

    @property
    def is_test(self) -> bool:
        return bool(_TEST_PART.search(self.path.replace("\\", "/")))

    def holds(self, *needles: str) -> bool:
        lowered = self.text.lower()
        return any(n.lower() in lowered for n in needles)


Scan = Callable[[FileText], Iterator[Hit]]


@dataclass(frozen=True)
class Pack:
    """A category of rules an adopter switches as one."""

    id: str
    title: str
    covers: str
    asi: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    """One refusable construct: the files it reads, the scan that finds it, and its evidence."""

    id: str
    pack: str
    title: str
    why: str
    kinds: tuple[str, ...]
    scan: Scan
    fix: str
    refuses: str
    silent_on: str
    cwe: tuple[str, ...] = ()
    asi: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    #: What the rule does when a selection is silent: a noisy heuristic starts as allow.
    default: str = DENY

    def reads(self, text: FileText) -> bool:
        return text.kind in self.kinds
