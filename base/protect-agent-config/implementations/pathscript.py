"""The parts of the path walk that run a script text in place: wrappers, here-documents, pipes into a shell (stdlib only)."""

from __future__ import annotations

import codecs
import os
import re
import shlex
from typing import Any

from chock_shellparse.parse import Cmd
from pathmatch import DYNAMIC
from pathwords import PRODUCERS
from pathwrap import unwrap
from pathwriters import interpreter


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

    def script(self, text: str, depth: int) -> bool:
        raise NotImplementedError

    def reaches(self, token: str, env: dict[str, str], **kwargs: Any) -> bool:
        raise NotImplementedError

    def _path(self, token: str, env: dict[str, str]) -> tuple[str, bool]:
        raise NotImplementedError

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

    def fed(self, cmd: Cmd, prev: Cmd | None) -> bool:
        """A shell that reads its script from standard input: here-string, here-document or the command before it."""
        scripts = [self.docs[r] for r in cmd.reads if r in self.docs] or self.produced(prev)
        self.blind |= not scripts
        return any(self.sub(text) for text in scripts)

    def code(self, cmd: Cmd) -> bool:
        scripts = [self.docs[r] for r in cmd.reads if r in self.docs] or self.produced(self.prev)
        return interpreter(self, cmd.args, cmd.env, scripts)
