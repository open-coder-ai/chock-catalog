"""The script text a producer (`echo`, `printf`, `cat <<DOC`) hands a shell, and whether the line shows all of it (stdlib only)."""

from __future__ import annotations

import re
from collections import deque

from chock_shellparse.parse import Cmd
from pathescape import decode

_DIRECTIVE = re.compile(r"%(?:%|[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[A-Za-z])")
_ECHO_FLAGS = re.compile(r"-[neE]+")
_ECHO_ESCAPES = re.compile(r"-[nE]*e[neE]*")
# A string that can hold a command: a bare word cannot write anything.
_SCRIPTLIKE = re.compile(r"[\s;&|<>$()`]")


def render(fmt: str, args: list[str]) -> tuple[str, bool]:
    """What `printf FORMAT ARGS` prints (the format applied over again while arguments are left), and whether every escape was known."""
    out: list[str] = []
    queue = deque(args)
    sure = True
    while True:
        used, at = False, 0
        for found in _DIRECTIVE.finditer(fmt):
            piece = decode(fmt[at : found.start()], "fmt")
            out.append(piece.text)
            sure &= piece.known
            at = found.end()
            if found[0] == "%%":
                out.append("%")
                continue
            used = True
            arg = queue.popleft() if queue else ""
            if not found[0].endswith("b"):
                out.append(arg)
                continue
            piece = decode(arg, "b")
            out.append(piece.text)
            sure &= piece.known
            if piece.stop:  # `\c` in a `%b` argument ends all output
                return "".join(out), sure
        piece = decode(fmt[at:], "fmt")
        out.append(piece.text)
        sure &= piece.known
        if not (used and queue):
            return "".join(out), sure


def _echoed(text: str) -> tuple[list[str], bool]:
    """The texts `echo -e` can print: bash reads an octal escape only as a zero and up to three digits, other shells' echo any `NNN` too."""
    strict, loose = decode(text, "echo"), decode(text, "b")
    return list(
        dict.fromkeys([text, strict.text, loose.text])
    ), strict.known and loose.known and strict.text == loose.text


def shown(cmd: Cmd, docs: dict[str, str]) -> tuple[list[str], bool]:
    """The text one producer prints, and whether that is exactly the script: literal words, nothing else in the command."""
    if cmd.name == "cat":
        named = [a for a in cmd.args if not a.startswith("-")]
        return [docs[r] for r in cmd.reads if r in docs], bool(cmd.reads) and not named and all(
            r in docs for r in cmd.reads
        )
    exact = not (cmd.writes or any("$" in a or "`" in a for a in cmd.args))
    if cmd.name == "printf":
        words = cmd.args[cmd.args[:1] == ["--"] :]
        if words[:1] == ["-v"]:
            return [], exact  # `printf -v x ...` assigns; it prints nothing
        if not words:
            return [], exact
        text, sure = render(words[0], words[1:])
        return [text], exact and sure
    words = [a for a in cmd.args if not _ECHO_FLAGS.fullmatch(a)]
    text = " ".join(words)
    if not any(_ECHO_ESCAPES.fullmatch(a) for a in cmd.args):
        return [text], exact
    found, sure = _echoed(text)
    return found, exact and sure


def strings(cmds: list[Cmd], docs: dict[str, str]) -> list[str]:
    """Every literal string of a producer the line does not reduce to one `echo` or `printf`: the words of each command and each here-document."""
    found = [*(a for c in cmds for a in c.args), *(docs[r] for c in cmds for r in c.reads if r in docs)]
    return [s for s in found if _SCRIPTLIKE.search(s)]
