"""The allowlist of approved MCP servers (`.chock/mcp-allowlist.json`): a closed schema, read from where an agent cannot grow it."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from chock_scan import hostmatch, jsonc, safe_read
from chock_scan.hosts import UnparseableError
from chock_scan.urls import parse_url

from mcpcheck.entry import Server

PATH = ".chock/mcp-allowlist.json"
#: Events a person's commit reaches. Any other event, a name never seen included, is an agent's: it reads HEAD's allowlist.
PERSON_EVENTS = frozenset({"commit", "push", "ci"})
KEYS = frozenset({"name", "launcher", "spec", "url_host"})
LIMIT = 1 << 20
MAX_ENTRIES = 500
GIT = shutil.which("git") or "git"


class AllowlistError(ValueError):
    """The allowlist cannot be read; every server is then unlisted, and the message says why."""


@dataclass(frozen=True)
class Allowed:
    """One approved server: a stdio one by `launcher` and `spec` (its arguments, single-space joined), a remote one by host."""

    name: str
    launcher: str
    spec: str
    host: hostmatch.Entry | None
    host_text: str = ""


def _entry(item: object) -> Allowed:
    if not isinstance(item, dict) or not item.keys() <= KEYS or not all(isinstance(v, str) for v in item.values()):
        msg = "each server must be an object of text with only name, launcher, spec and url_host"
        raise AllowlistError(msg)
    name, launcher, spec, host = (item.get(key, "") for key in ("name", "launcher", "spec", "url_host"))
    if not name or bool(host) == bool(launcher) or ("spec" in item and not launcher):
        msg = "each server needs a name and either launcher with spec, or url_host"
        raise AllowlistError(msg)
    try:
        return Allowed(name, launcher, spec, hostmatch.parse_entry(host) if host else None, host)
    except UnparseableError as exc:
        msg = f"url_host {host!r}: {exc}"
        raise AllowlistError(msg) from None


def parse(text: str) -> tuple[Allowed, ...]:
    """The allowlist a text holds; AllowlistError for bad JSON, unknown keys, duplicates or a wrong shape."""
    try:
        document = jsonc.loads(text, LIMIT)
    except jsonc.JsoncError as exc:
        msg = f"not valid JSON ({exc})"
        raise AllowlistError(msg) from None
    value = document.value
    if document.duplicates or not isinstance(value, dict) or value.keys() != {"servers"}:
        msg = 'the file must be one object with a "servers" list and no repeated key'
        raise AllowlistError(msg)
    servers = value["servers"]
    if not isinstance(servers, list) or len(servers) > MAX_ENTRIES:
        msg = f"servers must be a list of at most {MAX_ENTRIES}"
        raise AllowlistError(msg)
    return tuple(_entry(item) for item in servers)


def head_text(repo_root: Path) -> str | None:
    """The allowlist as HEAD holds it, or None when there is no HEAD, no such file or it is too large."""
    try:
        done = subprocess.run(  # noqa: S603 -- read-only git with a fixed argument list
            [GIT, "--no-replace-objects", "show", f"HEAD:./{PATH}"],
            cwd=repo_root,
            capture_output=True,
            timeout=20,
            check=False,
            env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0 or len(done.stdout) > LIMIT:
        return None
    return done.stdout.decode("utf-8", errors="replace")


def disk_text(repo_root: Path) -> str | None:
    """The allowlist file in the working tree, or None when it is missing; AllowlistError when it cannot be read."""
    path = repo_root / PATH
    if not path.exists() and not path.is_symlink():
        return None
    try:
        return safe_read.read_text(path, LIMIT)
    except (safe_read.UnreadableError, OSError) as exc:
        msg = f"unreadable ({exc})"
        raise AllowlistError(msg) from None


def load(repo_root: Path, event: str) -> tuple[tuple[Allowed, ...], str | None]:
    """(entries, the text they came from). A missing file is an empty allowlist: every server is then unlisted."""
    text = disk_text(repo_root) if event in PERSON_EVENTS else head_text(repo_root)
    return (parse(text), text) if text is not None else ((), None)


def matches(server: Server, allowed: Allowed) -> bool:
    """Whether a server (already named like `allowed`) is the approved one: same launcher and arguments, or an approved url host."""
    if allowed.host is None:
        return not server.urls and server.launcher == allowed.launcher and " ".join(server.args) == allowed.spec
    if server.launcher or not server.urls:
        return False
    try:
        return all(hostmatch.matches(parse_url(url).host, allowed.host) for url in server.urls)
    except UnparseableError:
        return False
