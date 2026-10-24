"""Passes over the raw line the parser cannot give: substitution bodies, /dev/tcp sockets, find -exec."""

from __future__ import annotations

import re

from chock_shellparse import Cmd
from egress_core import Allowlist, Verdict, unapproved

SOCKET = re.compile(r"/dev/(?:tcp|udp)/([^/\s'\"`;&|)]+)", re.IGNORECASE)
HERE_STRING = re.compile(r"<<<\s*(?:'([^']*)'|\"([^\"]*)\")")
BACKTICKED = re.compile(r"`([^`]*)`")
PIPE_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|ash)\b(?!\s+-\w*c)")
QUOTED = re.compile(r"'([^']*)'|\"([^\"]*)\"")
HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)\n\s*\1\b", re.DOTALL)
SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "ash"))
EXEC_FLAGS = frozenset(("-exec", "-execdir", "-ok", "-okdir"))


def substitutions(raw: str) -> list[str]:
    """Bodies of every $( ... ) (balanced, quoted or not), backtick pair and here-string: each is a command line."""
    bodies = [a or b for a, b in HERE_STRING.findall(raw)] + BACKTICKED.findall(raw)
    if PIPE_SHELL.search(raw):
        bodies += [a or b for a, b in QUOTED.findall(raw)] + [body for _, body in HEREDOC.findall(raw)]
    start = raw.find("$(")
    while start >= 0:
        depth, end = 1, start + 2
        while end < len(raw) and depth:
            depth += (raw[end] == "(") - (raw[end] == ")")
            end += 1
        bodies.append(raw[start + 2 : end - 1 if depth == 0 else end])
        start = raw.find("$(", start + 2)
    return bodies


def dev_sockets(raw: str, allow: Allowlist) -> Verdict:
    """A redirect to /dev/tcp/host/port or /dev/udp/host/port is a socket to that host."""
    return next(
        (v for m in SOCKET.finditer(raw) if (v := unapproved(allow, "a /dev/tcp connection to", m.group(1)))), None
    )


def find_exec(cmd: Cmd) -> list[Cmd]:
    """The commands `find -exec ... ;` runs, as commands of their own."""
    if cmd.name != "find":
        return []
    found: list[Cmd] = []
    args = cmd.args
    for index, arg in enumerate(args):
        if arg in EXEC_FLAGS:
            argv = []
            for word in args[index + 1 :]:
                if word in (";", "+"):
                    break
                argv.append(word)
            if argv:
                found.append(Cmd(argv[0].rsplit("/", 1)[-1].lower(), argv[1:], {}, [], [], ""))
    return found
