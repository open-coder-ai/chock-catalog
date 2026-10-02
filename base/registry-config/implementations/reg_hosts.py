"""The allowed registry hosts: the shipped public-registry table plus the repository's reviewed allowlist file."""

from __future__ import annotations

import subprocess
from pathlib import Path

from chock_scan.data_table import load
from chock_scan.hostmatch import Entry, parse_allowlist, parse_entry
from chock_scan.hosts import UnparseableError

TABLE = Path(__file__).resolve().parent / "data" / "registry-hosts.json"
#: The repository's own allowlist, one host (or '*.' and a domain) per line, '#' comments.
REPO_LIST = ".chock/registry-hosts.txt"
GIT_TIMEOUT = 10


def _check(doc: dict) -> list[str]:
    problems = []
    for ecosystem, hosts in doc["hosts"].items():
        if not isinstance(hosts, list) or not hosts:
            problems.append(f"hosts.{ecosystem} must be a non-empty list")
            continue
        for host in hosts:
            try:
                parse_entry(host)
            except (UnparseableError, TypeError) as exc:
                problems.append(f"hosts.{ecosystem}: {exc}")
    return problems


def table() -> tuple[Entry, ...]:
    """The shipped hosts; TableError when the table is missing, malformed or holds an unparseable host."""
    doc = load(TABLE, kind="curated", schema=1, keys=("hosts", "use"), check=_check)
    return tuple(parse_entry(host) for hosts in doc["hosts"].values() for host in hosts)


def committed(root: str) -> str:
    """The allowlist file as HEAD holds it; '' when there is none. Never the working tree: an edit an
    agent made there and did not commit must not widen what is allowed. `cat-file blob` runs no filter."""
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, read-only
            ["git", "-C", root, "cat-file", "blob", f"HEAD:{REPO_LIST}"],  # noqa: S607 -- git from PATH, as the runner uses it
            capture_output=True,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else ""


def repo_entries(text: str) -> tuple[Entry, ...]:
    """The repository's entries; none (so nothing extra is allowed) when the file cannot be read."""
    try:
        return parse_allowlist(text)
    except UnparseableError:
        return ()
