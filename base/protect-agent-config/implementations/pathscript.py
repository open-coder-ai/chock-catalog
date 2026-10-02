"""The parts of the path walk that run a script text in place: wrappers, here-documents, pipes into a shell (stdlib only)."""

from __future__ import annotations

import codecs
import os
import re
import shlex
from collections.abc import Callable

from chock_shellparse.parse import Cmd, _parse
from pathmatch import DYNAMIC
from pathtext import scan
from pathwords import PRODUCERS
from pathwrap import unwrap
from pathwriters import interpreter

_STDIN = re.compile(r"/dev/(?:stdin|fd/\d+)|/proc/self/fd/\d+")


def isdir(base: str, path: str) -> bool:
    """Whether a lowercased path below `base` is a directory on disk, matching each name without regard to case."""
    here = base
    for part in path.split("/"):
        if part in ("", "."):
            continue
        try:
            found = next((n for n in os.listdir(here) if n.lower() == part), None)
        except OSError:
            return False
        if found is None:
            return False
        here = os.path.join(here, found)
    return os.path.isdir(here)


class Scripts:
    """Methods of `_Walk` that judge a script a command runs or is fed."""

    cwd: str | None
    stack: list[str | None]
    depth: int
    blind: bool
    docs: dict[str, str]
    prev: Cmd | None
    base: str
    text: str
    ps: bool
    outputs: list[str]
    unseen: bool
    hit: Callable[[str], bool]
    resolve: Callable[[str], str | None]

    def sub(self, text: str) -> bool:
        """Whether a script that runs here, in the same directory, is refused."""
        saved = self.cwd, list(self.stack), self.depth
        refused = self.script(text, self.depth + 1)
        self.cwd, self.stack, self.depth = saved[0], saved[1], saved[2]
        return refused

    def loose(self, text: str) -> bool:
        """Whether a script that runs in a directory the guard cannot name is refused."""
        saved, self.cwd = self.cwd, None
        refused = self.sub(text)
        self.cwd = saved
        return refused

    def is_dir(self, token: str, env: dict[str, str]) -> bool:
        """Whether a path is, or may be, a directory (a name the guard cannot read may be one)."""
        path, loose = self._path(token, env)
        return loose or bool(DYNAMIC.search(path)) or isdir(self.base, path)

    def outside(self, token: str, env: dict[str, str]) -> bool:
        """Whether a path is plainly outside the repository (absolute, below some other folder)."""
        return self._path(token, env)[0].startswith("/")

    def wrapped(self, cmd: Cmd) -> bool:
        """A command that runs another (su -c, flock, strace, trap ...): the inner command is judged where it runs."""
        scripts, unsure = unwrap(cmd.name, cmd.args) or ([], False)
        if unsure and any(self.reaches(a, cmd.env, parents=True) for a in cmd.args):
            return True  # an option it does not know may take the word that starts the command
        lead = "".join(f"{k}={shlex.quote(v)}; " for k, v in cmd.env.items())
        return any(self.sub(lead + text) for text in scripts)

    def produced(self, prev: Cmd | None) -> list[str]:
        """The script text a command writes to the shell after it, when it is plain text."""
        if prev is None or prev.name not in PRODUCERS:
            return []
        if prev.name == "cat":
            return [self.docs[r] for r in prev.reads if r in self.docs]
        words = [a for a in prev.args if not re.fullmatch(r"-[neE]+", a)]
        text = words[0] if prev.name == "printf" and words else " ".join(words)
        return [codecs.decode(text, "unicode_escape", "replace") if prev.name == "printf" else text]

    def stdin(self, cmd: Cmd) -> bool:
        """A shell, `source` or `.` that reads its script from standard input (or a process substitution)."""
        files = [a for a in cmd.args if not a.startswith("-")]
        if cmd.name in ("source", "."):
            return not files or _STDIN.fullmatch(files[0]) is not None
        return "-s" in cmd.args or not files or _STDIN.fullmatch(files[0]) is not None

    def fed(self, cmd: Cmd, prev: Cmd | None, nxt: Cmd | None = None) -> bool:
        """A shell that reads its script from standard input: here-string, here-document, or the command before it
        (`<(cmd)` shows as the command after); a script the line does not show is refused when it names a protected path."""
        scripts = [self.docs[r] for r in cmd.reads if r in self.docs] or self.produced(prev)
        scripts = scripts or (self.produced(nxt) if "<(" in self.text else [])
        if not scripts:
            self.blind = True
            return self.hit(self.text)
        return any(self.sub(text) for text in scripts)

    def literal(self, body: str) -> list[str] | None:
        """The text a substitution body prints when it is one `echo`, `printf` or `cat <<DOC` the line shows."""
        scanned = scan(body, self.resolve)
        self.docs.update(scanned.docs)
        cmds = _parse(scanned.outer, {}, ps=self.ps, depth=0)[0]
        if len(cmds) == 1 and not cmds[0].writes and cmds[0].name in PRODUCERS:
            return self.produced(cmds[0])
        return None

    def computed(self) -> bool:
        """A command named by a substitution (`eval "$(echo ...)"`, `bash -c "$(cat <<E ...)"`): its text is judged
        as a script when the line shows it, and refused when a substitution it may be hides a protected name."""
        return any(self.sub(text) for text in self.outputs) or (self.unseen and self.hit(self.text))

    def code(self, cmd: Cmd) -> bool:
        scripts = [self.docs[r] for r in cmd.reads if r in self.docs] or self.produced(self.prev)
        return interpreter(self, cmd.args, cmd.env, scripts)
