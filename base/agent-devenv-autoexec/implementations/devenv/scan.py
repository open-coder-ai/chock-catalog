"""Judge a write: each file by its surface, then commands across files, agent spawns and symlinks."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

from devenv.core import BLOCK, MAX_COMMAND, Collector, Finding, digest, norm
from devenv.parse import UnreadableError
from devenv.paths import SPAWN_ONLY, handler_for, normalized
from devenv.spawn import spawns

#: Agent and editor config folders: a command in one that runs a script kept in another is the keyv-worm shape.
AGENT_DIRS = frozenset(
    {
        ".claude",
        ".cursor",
        ".codex",
        ".gemini",
        ".windsurf",
        ".kiro",
        ".roo",
        ".continue",
        ".vscode",
        ".devcontainer",
        ".idea",
        ".zed",
        ".devin",
        ".grok",
        ".junie",
        ".amazonq",
    }
)
_TOKEN = re.compile(r"[^\s`;|&()<>=,]+")
_ROOTED = re.compile(r"(?:\$\{?[A-Za-z_]\w*\}?|\.{1,2})/")
_RELATIVE = re.compile(r"[\w.@+-]+(?:/[\w.@+-]+)+")


def paths_in(command: str) -> list[str]:
    """Relative paths a command names, after `$VAR/`, `${VAR}/`, `./` and `../` prefixes; linear in its length."""
    if len(command) > MAX_COMMAND:
        return []
    found = []
    for token in _TOKEN.findall(command.replace('"', "").replace("'", "")):
        at = 0
        while (prefix := _ROOTED.match(token, at)) is not None:
            at = prefix.end()
        if _RELATIVE.fullmatch(token, at):
            found.append(token[at:])
    return found


def judge_file(path: str, text: str) -> Collector | None:
    """The findings of one written file, or None when it is not a surface this gate reads."""
    handler = handler_for(path)
    spawn_only = handler is None and SPAWN_ONLY.search(normalized(path))
    if handler is None and not spawn_only:
        return None
    c = Collector(text)
    if handler is not None:
        try:
            handler(c)
        except UnreadableError as exc:
            digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]
            c.found = [
                Finding("dev-unparseable", 1, f"unreadable#{digest}", f"cannot be read, so it is refused: {exc}", BLOCK)
            ]
    spawns(c)
    return c


def cross_references(collectors: dict[str, Collector], added: dict[str, str]) -> None:
    """A command that runs a file this change writes, or a script kept in another agent's folder.

    `added` maps each normalized path the change writes to its text; the key carries a digest of it,
    so editing a script a reviewed hook already runs is new whenever the change also writes the hook.
    """
    for path, c in collectors.items():
        home = normalized(path).split("/")
        own = next((part for part in home if part in AGENT_DIRS), None)
        for where, command, line in c.commands:
            for token in paths_in(command):
                target = normalized(token)
                first = target.split("/", 1)[0]
                if target in added and target != normalized(path):
                    message = f"command at {where} runs {token}, which this change writes"
                elif first in AGENT_DIRS and own is not None and first != own:
                    message = f"command at {where} in {own} runs a script kept in {first}"
                else:
                    continue
                content = f"#{digest(added[target])}" if target in added else ""
                c.add("dev-cross-reference", f"{where}->{target}{content}", message, line=line)


_GIT_CONFIGS = re.compile(r"(?:^|/)(?:\.gitmodules|[^/]*\.gitconfig)$")
_LONE_CR = re.compile(rb"\r(?!\n)")


def raw_cr(root: Path, event: str, writes: dict[str, str]) -> dict[str, Collector]:
    """At commit, push and CI the engine hands over text with line breaks normalized, which turns a lone
    carriage return (the CVE-2025-48384 trick) into a line break; read those two files' raw blobs instead."""
    if event not in ("commit", "agent-commit", "push", "ci"):
        return {}
    out: dict[str, Collector] = {}
    for path in sorted(p for p in writes if _GIT_CONFIGS.search(normalized(p))):
        spec = f":./{path}" if event in ("commit", "agent-commit") else f"HEAD:./{path}"
        raw = _git_bytes(root, "show", spec)
        if raw is None and writes[path]:
            message = "its raw blob cannot be read to check for a lone carriage return, so it is refused"
            out.setdefault(path, Collector("")).add("dev-unparseable", "raw-unreadable", message)
        elif raw and _LONE_CR.search(raw):
            rule = "dev-gitmodules-untrusted" if normalized(path).endswith(".gitmodules") else "dev-gitconfig-exec"
            out.setdefault(path, Collector("")).add(
                rule, "carriage-return", "a carriage return inside a line (CVE-2025-48384)"
            )
    return out


def _git_bytes(root: Path, *args: str) -> bytes | None:
    """git's stdout, or None when git cannot run or fails."""
    try:
        proc = subprocess.run(  # noqa: S603 -- a fixed git argv; paths are arguments, never shell words
            ["git", *args],  # noqa: S607 -- git from PATH, as the runner's own
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 -- a fixed git argv; paths are arguments, never shell words
            ["git", *args],  # noqa: S607 -- git from PATH, as the runner's own
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return ""
    return proc.stdout.decode("utf-8", "surrogateescape") if proc.returncode == 0 else ""


def symlinks(root: Path, event: str, writes: dict[str, str]) -> dict[str, str]:
    """Each written path that is a symlink, with its target: the index at commit, HEAD at push/ci, and the disk
    always, so a git that cannot answer (a wrong repo_root) still leaves the links on disk judged."""
    paths = sorted(writes)
    links: dict[str, str] = {}
    if paths and event in ("commit", "agent-commit", "push", "ci"):
        index = event in ("commit", "agent-commit")
        args = ["ls-files", "-s", "-z", "--", *paths] if index else ["ls-tree", "-z", "HEAD", "--", *paths]
        for record in _git(root, *args).split("\0"):
            meta, _, name = record.partition("\t")
            if meta.startswith("120000"):
                links[name] = writes.get(name, "")
    for path in paths:
        if path not in links and (root / path).is_symlink():
            links[path] = os.readlink(root / path)
    return links


def link_findings(links: dict[str, str]) -> dict[str, Collector]:
    """A link that leaves the repository, points into .git, or stands where a config is read, refuses."""
    out: dict[str, Collector] = {}
    for path, target in links.items():
        joined = os.path.normpath(PurePosixPath(path).parent / target.replace("\\", "/"))
        escapes = target.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", target) or joined.startswith("..")
        into_git = ".git" in normalized(joined).split("/")
        config = handler_for(path) is not None
        if escapes or into_git or config:
            why = (
                "leaves the repository"
                if escapes
                else "points into .git"
                if into_git
                else "stands where a tool reads its config"
            )
            c = out.setdefault(path, Collector(""))
            c.add("dev-symlink-escape", f"link->{norm(target)}", f"symlink {why}")
    return out


def untracked(root: Path) -> dict[str, str]:
    """Files on disk git does not track yet (at tool use, what this turn wrote before this write), by path."""
    names = [p for p in _git(root, "ls-files", "-o", "--exclude-standard", "-z").split("\0") if p]
    return {normalized(p): _disk_text(root / p) for p in names}


def _disk_text(path: Path) -> str:
    """A file's text for its digest (first 1 MiB); a file that cannot be read is keyed as such."""
    try:
        with path.open("rb") as handle:
            return handle.read(1 << 20).decode("utf-8", "replace")
    except OSError:
        return "<unreadable>"
