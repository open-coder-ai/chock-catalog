#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a shell command that reads a credential store or prints a token; ask before an environment dump.
# Exit 1 refuses, exit 3 asks (the first line printed is the prompt), exit 0 stays silent.
# Friction, not a boundary: scripts, variables the parser cannot see and indirect reads are out of reach.

import os
import shlex
import sys
from collections.abc import Iterator
from itertools import takewhile

import secret_paths as store
import secret_printers as printers
import secret_readers as readers
from chock_shellparse import Cmd, commands, flags_of, operands

BLOCK, ASK = 1, 3
Verdict = tuple[int, str] | None
FIND_EXEC = frozenset(("-exec", "-execdir", "-ok", "-okdir"))


def refuse(what: str) -> Verdict:
    return BLOCK, (
        f"BLOCKED: {what} would put a credential into the agent's context. Ask the person for the one value "
        "you need, or have them run the command themselves."
    )


def confirm(what: str) -> Verdict:
    return ASK, f"CONFIRM: {what} prints every secret it holds. Name the one variable you need, or confirm the dump."


def verdict(found: store.Hit) -> Verdict:
    label, action = found
    return confirm(label) if action == "ask" else refuse(f"reading {label}")


class Guard:
    """Judges commands in order, following `cd` so relative paths resolve where the shell would."""

    def __init__(self, table: store.Table) -> None:
        self.table = table
        self.cwd: tuple[str, ...] | None = None

    def path_hit(self, path: str, cmd: Cmd, *, walk: bool = False) -> store.Hit | None:
        words = store.braces(path)
        if words is None:
            return "a path with a brace list too large to judge", "block"
        for word in words:
            found = store.find(store.resolve(word, cmd.env, self.cwd), self.table, walk=walk)
            if found:
                return found
        return None

    def first(self, paths: list[str], cmd: Cmd, *, walk: bool = False) -> store.Hit | None:
        return next(filter(None, (self.path_hit(path, cmd, walk=walk) for path in paths)), None)

    def reads(self, cmd: Cmd) -> store.Hit | None:
        """A redirect or a reader's operand that is a store; a verb that walks trees also matches a parent dir."""
        mode = self.table.readers.get(cmd.name)
        walks = self.table.recursive.get(cmd.name)
        walk = walks is True or bool(walks and flags_of(cmd.args) & set(walks))
        return self.first(cmd.reads, cmd) or self.first(readers.candidates(cmd, mode) if mode else [], cmd, walk=walk)

    def script(self, cmd: Cmd) -> store.Hit | None:
        """A store named in interpreter code, a heredoc fed to one, or a sed or awk program."""
        if cmd.name.rstrip("0123456789.") in self.table.interpreters:
            return store.scan_text("\n".join([*cmd.args, cmd.doc]), cmd.env, self.table, strict=False)
        if self.table.readers.get(cmd.name) == "program-first":
            return store.scan_text(readers.program(cmd), cmd.env, self.table, strict=True)
        return None

    def find_exec(self, cmd: Cmd) -> store.Hit | None:
        """`find ~/.ssh -exec cat {} ;` reads everything under the start paths."""
        runs = [cmd.args[i + 1] for i, arg in enumerate(cmd.args[:-1]) if arg in FIND_EXEC]
        if cmd.name != "find" or not any(run.rsplit("/", 1)[-1] in self.table.readers for run in runs):
            return None
        return self.first(list(takewhile(lambda arg: arg[:1] not in ("-", "(", "!"), cmd.args)), cmd, walk=True)

    def chdir(self, cmd: Cmd) -> None:
        there = store.resolve((operands(cmd.args) or ["~"])[0], cmd.env, self.cwd)
        self.cwd = None if "-" in cmd.args or there[0].startswith("$") else there

    def judge_all(self, raw: str) -> Verdict:
        return strongest([self.judge(cmd) for cmd in flatten(commands(raw))])

    def judge(self, cmd: Cmd) -> Verdict:
        if cmd.name in ("cd", "pushd"):
            self.chdir(cmd)
            return None
        if found := self.reads(cmd) or self.script(cmd) or self.find_exec(cmd):
            return verdict(found)
        what = printers.printer(cmd, self.table.printers)
        return (
            (
                BLOCK,
                f"BLOCKED: {what} prints a credential into the agent's context. Ask the person to run it themselves.",
            )
            if what
            else None
        )


def flatten(cmds: list[Cmd]) -> Iterator[Cmd]:
    """Each command, then the commands of a heredoc fed to a shell."""
    for cmd in cmds:
        yield cmd
        if cmd.doc and cmd.name in printers.SHELLS:
            yield from flatten(commands(cmd.doc))


def strongest(found: list[Verdict]) -> Verdict:
    """A block beats an ask; the first of each kind wins."""
    return next((v for v in found if v and v[0] == BLOCK), None) or next(filter(None, found), None)


def check(raw: str) -> Verdict:
    """The verdict for a command line, read as written and with backslash paths read as slashes (Windows)."""
    table = store.load()
    found = [Guard(table).judge_all(text) for text in dict.fromkeys((raw, raw.replace("\\", "/")))]
    return strongest([*found, confirm(printers.DUMP) if printers.dump(raw) else None])


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        result = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-secret-store-reads: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if result:
        print(result[1], file=sys.stderr)
    return result[0] if result else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
