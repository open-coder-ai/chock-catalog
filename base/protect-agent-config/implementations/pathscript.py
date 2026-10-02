"""The parts of the path walk that run a script text in place: wrappers, here-documents, pipes into a shell (stdlib only)."""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Callable

from chock_shellparse.parse import Cmd, _parse
from pathfeed import shown, strings
from pathmatch import DYNAMIC
from pathtext import matching, scan
from pathwords import PRODUCERS
from pathwrap import unwrap
from pathwriters import interpreter

_GROUP = re.compile(r"[})]\s*\|")
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

    def produced(self, prev: Cmd | None) -> tuple[list[str], bool]:
        """The script text the command before a shell prints, and whether the line shows exactly that text."""
        if prev is None or prev.name not in PRODUCERS:
            return [], True
        return shown(prev, self.docs)

    def stdin(self, cmd: Cmd) -> bool:
        """A shell, `source` or `.` that reads its script from standard input (or a process substitution)."""
        files = [a for a in cmd.args if not a.startswith("-")]
        if cmd.name in ("source", "."):
            return not files or _STDIN.fullmatch(files[0]) is not None
        return "-s" in cmd.args or not files or _STDIN.fullmatch(files[0]) is not None

    def fed(self, cmd: Cmd, prev: Cmd | None) -> bool:
        """A shell that reads its script from standard input: a here-string or here-document, the command before it, each `<(cmd)`.

        Only one plain `echo`, `printf` or `cat <<DOC` is read as the script. Any other producer (a list, a group, a
        command the line does not show) has every literal string judged as a script, and the line is refused when it names a
        protected path anywhere: a decoy command before the real text must not hide it.
        """
        scripts = [self.docs[r] for r in cmd.reads if r in self.docs]
        found, exact = self.produced(prev)
        if found and _GROUP.search(self.text):
            exact = False  # `{ echo real; echo decoy; } | sh`: the command before the pipe is not the whole producer
        scripts += found
        for text, sure in self.process_bodies():
            scripts += text
            exact &= sure
        if scripts and exact:
            return any(self.sub(text) for text in scripts)
        self.blind = True
        return any(self.sub(text) for text in scripts) or self.hit(self.text)

    def process_bodies(self) -> list[tuple[list[str], bool]]:
        """What each `<(...)` of the line prints."""
        found, at = [], self.text.find("<(")
        while at >= 0:
            end = matching(self.text, at + 1)
            found.append(self.shown(self.text[at + 2 : end].removesuffix(")")))
            at = self.text.find("<(", at + 2)
        return found

    def shown(self, body: str) -> tuple[list[str], bool]:
        """The text a substitution body prints: exact for one `echo`, `printf` or `cat <<DOC`, else its literal strings."""
        scanned = scan(body, self.resolve)
        cmds = _parse(scanned.outer, {}, ps=self.ps, depth=0)[0]
        if len(cmds) == 1 and not cmds[0].writes and cmds[0].name in PRODUCERS:
            return shown(cmds[0], scanned.docs)
        return strings(cmds, scanned.docs), False

    def computed(self) -> bool:
        """A command named by a substitution (`eval "$(echo ...)"`, `bash -c "$(cat <<E ...)"`): its text is judged
        as a script when the line shows it, and refused when a substitution it may be hides a protected name."""
        return any(self.sub(text) for text in self.outputs) or (self.unseen and self.hit(self.text))

    def code(self, cmd: Cmd) -> bool:
        scripts = [self.docs[r] for r in cmd.reads if r in self.docs] or self.produced(self.prev)[0]
        return interpreter(self, cmd.args, cmd.env, scripts)
