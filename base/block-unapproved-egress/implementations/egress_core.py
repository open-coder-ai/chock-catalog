"""The egress allowlist (the policy's data file or the project's `.chock/egress-allowlist.txt`), host judging, verdicts."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import NamedTuple

from chock_scan.hostmatch import Entry, matches, parse_allowlist
from chock_scan.hosts import Host, UnparseableError
from chock_scan.safe_read import UnreadableError, read_text
from chock_scan.urls import parse_url

BLOCK, ASK = 1, 3
Verdict = tuple[int, str] | None
DEFAULT_FILE = Path(__file__).resolve().parent / "data" / "egress-allowlist.txt"
PROJECT_FILE = os.path.join(".chock", "egress-allowlist.txt")
# The parser ends a word at an unquoted '(' or backtick, so `$(cmd)` reaches a guard as a trailing '$'.
COMMAND_SUBST = re.compile(r"\$\(|\$$|`")
VARIABLE = re.compile(r"\$\{?[A-Za-z_0-9?@!]")
WHOLE_VARIABLE = re.compile(r"\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})")
ASK_PERSON = "Ask the person: they extend .chock/egress-allowlist.txt or run it themselves."


class Allowlist(NamedTuple):
    """`entries` judge hosts; a non-empty `problem` means the project file cannot be trusted and nothing is allowed."""

    entries: tuple[Entry, ...]
    problem: str = ""


def refuse(text: str) -> Verdict:
    return BLOCK, f"BLOCKED: {text}"


def confirm(text: str) -> Verdict:
    return ASK, f"CONFIRM: {text}"


def project_root(start: Path) -> Path | None:
    """The nearest directory at or above `start` holding .git, else the nearest holding .chock (a nested .chock cannot win)."""
    chain = (start, *start.parents)
    return next((d for d in chain if (d / ".git").exists()), None) or next(
        (d for d in chain if (d / ".chock").is_dir()), None
    )


def load_allowlist(start: Path) -> Allowlist:
    """The project's allowlist file when there is one, else the built-in default; unusable file = nothing allowed."""
    root = project_root(start)
    path = root / PROJECT_FILE if root else None
    if path is None or not os.path.lexists(path):
        return Allowlist(parse_allowlist(read_text(DEFAULT_FILE)))
    try:
        entries = parse_allowlist(read_text(path))
    except (UnreadableError, UnparseableError) as exc:
        return Allowlist((), f"{PROJECT_FILE} is unusable ({exc})")
    return Allowlist(entries, "" if entries else f"{PROJECT_FILE} lists no host")


def host_of(text: str) -> Host | None:
    """The host of a URL, `//host/path`, `user@host:port` or bare `host/path`; None when it cannot be read one way."""
    try:
        return parse_url(text if "://" in text or text.startswith("//") else f"//{text}").host
    except UnparseableError:
        return None


def permitted(allow: Allowlist, text: str) -> bool:
    host = host_of(text)
    return host is not None and any(matches(host, entry) for entry in allow.entries)


def label(text: str) -> str:
    """The authority of a target for a message: no scheme, path or credentials."""
    body = text.split("://", 1)[-1].lstrip("/")
    return body.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1][:80]


def unapproved(allow: Allowlist, what: str, target: str) -> Verdict:
    """The block for sending data to `target`, or None when its host is allowlisted."""
    if allow.problem:
        return refuse(
            f"{what} is refused because {allow.problem}. Ask the person to fix it; nothing is allowed until then."
        )
    if permitted(allow, target):
        return None
    return refuse(
        f"{what} '{label(target)}' is outside the egress allowlist (or its host cannot be read one way). "
        f"Send data only to an approved host. {ASK_PERSON}"
    )
