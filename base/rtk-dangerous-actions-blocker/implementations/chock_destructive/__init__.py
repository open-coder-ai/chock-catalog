"""Destructive-command verdicts from one table, shared byte for byte by block-destructive-commands and rtk."""

import os
import re
import shlex
from collections.abc import Callable

from chock_shellparse import POWERSHELL_REMOVERS, Cmd, commands, positionals

from .files import HOST_RULES, keys, mkfs, powershell_remove
from .infra import DOCKER_VALUES, KUBECTL_VALUES, RAW_RULES, RULES
from .table import ASK, BLOCK, TABLE, TABLE_VERSION
from .vcs import git

__all__ = ["ASK", "BLOCK", "TABLE", "TABLE_VERSION", "Extra", "Verdict", "check", "raw_command"]

Verdict = tuple[int, str] | None
#: A policy's own rows, given (command, inside a container exec); judged beside the table's.
Extra = Callable[[Cmd, bool], Verdict]
_EXEC_VALUES = frozenset(("-e", "-u", "-w", "--env", "--user", "--workdir", "--env-file"))


def _verdict(hit: tuple[str, str] | None) -> Verdict:
    if hit is None:
        return None
    row = TABLE[hit[0]]
    return row.verdict, ("BLOCKED: " if row.verdict == BLOCK else "CONFIRM: ") + row.text.format(hit[1])


def _host(cmd: Cmd, raw: str) -> tuple[str, str] | None:
    """Rows about paths on this machine; a container exec's paths are the container's, so they are skipped there."""
    rule = HOST_RULES.get(cmd.name) or (mkfs if cmd.name.startswith("mkfs.") else None)
    removal = powershell_remove(cmd) if cmd.name in POWERSHELL_REMOVERS else None
    return keys(cmd, raw) or removal or (rule(cmd) if rule else None)


def judge(cmd: Cmd, raw: str, *, container: bool) -> Verdict:
    """One simple command's verdict from the table, or None."""
    hit = None if container else _host(cmd, raw)
    if hit is None and cmd.name == "git":
        hit = git(cmd)
    if hit is None and cmd.name in RULES:
        hit = RULES[cmd.name](cmd)
    if hit is None and cmd.name in RAW_RULES:
        hit = RAW_RULES[cmd.name](cmd, raw)
    return _verdict(hit)


def inner_command(cmd: Cmd) -> list[str]:
    """The words of the command a `docker exec` or `kubectl exec` runs inside its container, or []."""
    if cmd.name == "kubectl" and positionals(cmd.args, KUBECTL_VALUES)[:1] == ["exec"] and "--" in cmd.args:
        return cmd.args[cmd.args.index("--") + 1 :]
    if cmd.name != "docker" or positionals(cmd.args, DOCKER_VALUES)[:1] != ["exec"]:
        return []
    words, skip, named = [], False, False
    for arg in cmd.args[cmd.args.index("exec") + 1 :]:
        if named:
            words.append(arg)
        elif skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in _EXEC_VALUES
        else:
            named = True
    return words


def judge_all(cmds: list[Cmd], raw: str, *, container: bool, extra: Extra | None) -> Verdict:
    """A block wins over an ask; the first ask wins over the rest."""
    asked: Verdict = None
    for cmd in cmds:
        words = inner_command(cmd)
        inner = judge_all(commands(shlex.join(words)), raw, container=True, extra=extra) if words else None
        own = extra(cmd, container) if extra else None
        for verdict in (own, judge(cmd, raw, container=container), inner):
            if verdict and verdict[0] == BLOCK:
                return verdict
            asked = asked or verdict
    return asked


def unreadable(raw: str) -> bool:
    """The engine could not split the command (CHOCK_ARGV_FALLBACK=1), or shlex cannot here either."""
    try:
        shlex.split(raw)
    except ValueError:
        return True
    return os.environ.get("CHOCK_ARGV_FALLBACK") == "1"


def raw_command(argv: list[str]) -> str:
    """CHOCK_RAW_COMMAND, else argv: re-joined as typed under the fallback (its words still hold their quotes)."""
    if raw := os.environ.get("CHOCK_RAW_COMMAND"):
        return raw
    return " ".join(argv) if os.environ.get("CHOCK_ARGV_FALLBACK") == "1" else shlex.join(argv)


def check(raw: str, extra: Extra | None = None) -> Verdict:
    """The verdict for a command line. One that cannot be split is also read with every quote and backslash dropped,
    and the stricter reading wins: a command whose quoting is unknown is never let through on one guess."""
    readings = [raw, re.sub(r"[\"'\\]", " ", raw)] if unreadable(raw) else [raw]
    found = [judge_all(commands(text), text, container=False, extra=extra) for text in readings]
    return next((v for v in found if v and v[0] == BLOCK), None) or next((v for v in found if v), None)
