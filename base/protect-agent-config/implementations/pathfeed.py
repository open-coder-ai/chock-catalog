"""The script text a producer (`echo`, `printf`, `cat <<DOC`) hands a shell, and whether the line shows all of it (stdlib only)."""

from __future__ import annotations

import codecs
import re

from chock_shellparse.parse import Cmd

_DIRECTIVE = re.compile(r"%(?:%|[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[A-Za-z])")
_ECHO_FLAGS = re.compile(r"-[neE]+")
_ECHO_ESCAPES = re.compile(r"-[nE]*e[neE]*")
# A string that can hold a command: a bare word cannot write anything.
_SCRIPTLIKE = re.compile(r"[\s;&|<>$()`]")


def decode(text: str) -> str:
    """Backslash escapes as `printf` and `echo -e` read them."""
    return codecs.decode(text, "unicode_escape", "replace")


def render(fmt: str, args: list[str]) -> str:
    """What `printf FORMAT ARGS` prints: the format applied to the arguments, over again while arguments are left."""
    out: list[str] = []
    queue = list(args)
    while True:
        used, at = False, 0
        for found in _DIRECTIVE.finditer(fmt):
            out.append(decode(fmt[at : found.start()]))
            at = found.end()
            if found[0] == "%%":
                out.append("%")
                continue
            used = True
            arg = queue.pop(0) if queue else ""
            out.append(decode(arg) if found[0].endswith("b") else arg)
        out.append(decode(fmt[at:]))
        if not (used and queue):
            return "".join(out)


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
        return ([render(words[0], words[1:])] if words else []), exact
    words = [a for a in cmd.args if not _ECHO_FLAGS.fullmatch(a)]
    text = " ".join(words)
    return ([text, decode(text)] if any(_ECHO_ESCAPES.fullmatch(a) for a in cmd.args) else [text]), exact


def strings(cmds: list[Cmd], docs: dict[str, str]) -> list[str]:
    """Every literal string of a producer the line does not reduce to one `echo` or `printf`: the words of each command and each here-document."""
    found = [*(a for c in cmds for a in c.args), *(docs[r] for c in cmds for r in c.reads if r in docs)]
    return [s for s in found if _SCRIPTLIKE.search(s)]
