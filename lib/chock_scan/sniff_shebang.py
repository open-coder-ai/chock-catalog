"""The command a `#!` line runs, and whether it is a shell, for the content sniffer."""

from __future__ import annotations

import re
from collections import deque

SHELL = re.compile(r"(?:a|ba|da|k|mk|pdk|lk|ok|lok|o|z|ya|po|rba|c|tc|fi|hu|bo|j)?sh(?:[-.\d][\w.-]*+)?")
MULTICALL = frozenset({"busybox", "toybox"})
ENV_VALUE = frozenset("uCP")
ENV_QUOTES = re.compile(r"""["']""")
#: The kernel reads 256 bytes of a #! line (BINPRM_BUF_SIZE); the cap keeps the env walk cheap.
KERNEL_MAX = 256
SHEBANG_MAX = 4096


def shell(text: str, command: tuple[str, ...]) -> tuple[bool, str] | None:
    """(True, signal) when the #! command is a shell; (False, signal) when a shell may run the file; else None."""
    if command and _is_shell(command):
        return True, f"#! {' '.join(command[:2])}"
    window = text[:KERNEL_MAX].encode("utf-8", "replace")[:KERNEL_MAX]
    line, newline, _ = window.partition(b"\n")
    name = line[2:].lstrip(b" \t")
    if not name or (not newline and len(window) == KERNEL_MAX and not set(name) & {0x20, 0x09}):
        return False, "the kernel cannot run this #! line, so a shell runs the file"
    if any(SHELL.fullmatch(_base(word).lower()) for word in command[1:]):
        return False, "a shell named later in the #! line"
    if any("$" in word or "\\" in word for word in command):
        return False, "a #! word it cannot read (env expands $ and \\ at run time)"
    return None


def interpreter(text: str) -> tuple[str, ...]:
    """The command a `#!` first line runs, through `env` and its options (`-S` included), and its words."""
    first = text[:SHEBANG_MAX].split("\n", 1)[0].rstrip("\r")
    if not first.startswith("#!"):
        return ()
    words = first[2:].split()
    if not words:
        return ()
    if _base(words[0]) != "env":
        return (_base(words[0]), *words[1:])
    return _after_env(words[1:])


def _after_env(words: list[str]) -> tuple[str, ...]:
    """The command env runs: options, their values and NAME=VALUE pairs skipped; `-S` splits on.

    Quotes and `\\_` are dropped and `\\c` ends the line first, as `env -S` would.
    """
    line = " ".join(words).split("\\c", 1)[0]
    queue = deque(ENV_QUOTES.sub("", line).replace("\\_", " ").split())
    while queue:
        word = queue.popleft()
        if word == "--":
            break
        if word.startswith("--"):
            _long_option(word, queue)
        elif word.startswith("-"):
            _short_options(word[1:], queue)
        elif "=" not in word:
            return (_base(word), *queue)
    return (_base(queue.popleft()), *queue) if queue else ("env",)


def _long_option(word: str, queue: deque[str]) -> None:
    name, eq, value = word.partition("=")
    if name == "--split-string" and eq:
        queue.appendleft(value)
    elif name in ("--unset", "--chdir") and not eq and queue:
        queue.popleft()


def _short_options(flags: str, queue: deque[str]) -> None:
    for at, flag in enumerate(flags):
        if flag in ENV_VALUE:
            if at + 1 == len(flags) and queue:
                queue.popleft()
            return
        if flag == "S":
            if at + 1 < len(flags):
                queue.appendleft(flags[at + 1 :])
            return


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def _is_shell(command: tuple[str, ...]) -> bool:
    name = command[1] if command[0] in MULTICALL and len(command) > 1 else command[0]
    return SHELL.fullmatch(_base(name).lower()) is not None
