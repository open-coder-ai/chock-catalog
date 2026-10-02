"""Who may waive a finding: a reviewed pragma beside it, or an entry in the closed-schema sidecar."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path

from iamscan.model import Finding

SIDECAR = ".chock/iam-policy-scan.json"
VERSION = 1
PRAGMA = re.compile(r"(?:^|\s)(?:#|//)[^\n]*pragma:\s*allowlist\s+broad-privilege")
COMMENT_ONLY = re.compile(r"\s*(?:#|//)")
KEY_ONLY = re.compile(r"[\w\"']\s*:\s*(?:(?:#|//).*)?$")
TOP_KEYS = frozenset({"version", "waive"})
ENTRY_KEYS = frozenset({"path", "rule", "id", "reason"})
#: Events where a person reviews what is staged. Everywhere else the text is the agent's own.
HUMAN_EVENTS = frozenset({"commit", "push", "ci"})


class SidecarError(ValueError):
    """A sidecar that does not say, unambiguously, what it waives."""


def committed(root: Path) -> Callable[[str], str | None]:
    """A path's text at HEAD, read from git in `root`; None when there is none."""

    def read(path: str) -> str | None:
        rel = Path(path)
        if rel.is_absolute():
            try:
                rel = rel.resolve().relative_to(root.resolve())
            except ValueError:
                return None
        try:
            proc = subprocess.run(  # noqa: S603 -- a fixed git argv; the path is an argument, never a shell word
                ["git", "show", f"HEAD:{rel.as_posix()}"],  # noqa: S607 -- git from PATH, as the runner's own
                cwd=root,
                capture_output=True,
                check=False,
            )
        except OSError:
            return None
        return proc.stdout.decode("utf-8-sig", errors="replace") if proc.returncode == 0 else None

    return read


def parse_sidecar(raw: str) -> set[tuple[str, str, str]]:
    """The (path, rule, id) triples a sidecar waives; SidecarError for anything it does not read with certainty."""
    try:
        document = json.loads(raw)
    except ValueError as exc:
        msg = f"{SIDECAR} is not valid JSON: {exc}"
        raise SidecarError(msg) from exc
    if not isinstance(document, dict) or set(document) - TOP_KEYS or document.get("version") != VERSION:
        msg = f"{SIDECAR} must be an object with only 'version' ({VERSION}) and 'waive'"
        raise SidecarError(msg)
    entries = document.get("waive", [])
    if not isinstance(entries, list):
        msg = f"{SIDECAR}: 'waive' must be a list"
        raise SidecarError(msg)
    waived = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - ENTRY_KEYS or not {"path", "rule", "id"} <= set(entry):
            msg = f"{SIDECAR}: each waiver is an object with 'path', 'rule', 'id' and optionally 'reason' only"
            raise SidecarError(msg)
        if not all(isinstance(entry[k], str) and entry[k] for k in ("path", "rule", "id")):
            msg = f"{SIDECAR}: 'path', 'rule' and 'id' must be non-empty strings"
            raise SidecarError(msg)
        waived.add((entry["path"], entry["rule"], entry["id"]))
    return waived


def sidecar_waivers(event: str, writes: dict[str, str], read: Callable[[str], str | None]) -> set[tuple[str, str, str]]:
    """What the sidecar waives: the staged one when a person commits it, otherwise the one already at HEAD."""
    raw = writes.get(SIDECAR) if event in HUMAN_EVENTS else None
    raw = raw if raw is not None else read(SIDECAR)
    return parse_sidecar(raw) if raw is not None else set()


def pragma_waived(finding: Finding, text: str, event: str, head: Callable[[str], str | None]) -> bool:
    """Whether a reviewed pragma sits on a line the finding names, or on the comment-only line above one.

    A person's commit trusts the text it commits. Anywhere else the pragma line must already be in HEAD's copy of the file.
    """
    lines = text.splitlines()
    waiver_lines = _pragma_lines(lines, finding.anchors)
    if not waiver_lines:
        return False
    if event in HUMAN_EVENTS:
        return True
    before = head(finding.path)
    old = {line.strip() for line in before.splitlines()} if before is not None else set()
    return any(lines[n - 1].strip() in old for n in waiver_lines)


def _pragma_lines(lines: list[str], anchors: Iterable[int]) -> list[int]:
    """Lines with the pragma that count for a finding.

    On an anchor, on the key line just above a value that starts on the next line, or in the comment-only
    lines directly above either.
    """
    found = []
    for n in anchors:
        starts = [n]
        if 1 < n <= len(lines) + 1 and KEY_ONLY.search(lines[n - 2]):
            starts.append(n - 1)
        for start in starts:
            if 1 <= start <= len(lines) and PRAGMA.search(lines[start - 1]):
                found.append(start)
            above = start - 1
            while above >= 1 and COMMENT_ONLY.match(lines[above - 1]):
                if PRAGMA.search(lines[above - 1]):
                    found.append(above)
                above -= 1
    return found
