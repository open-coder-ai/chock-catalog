"""Judge a shell command by the paths it resolves to: working directory, `..`, variables, globs, whole directories (stdlib only)."""

from __future__ import annotations

import itertools
import os
import posixpath
import re
from collections.abc import Callable

from chock_shellparse import flags_of
from chock_shellparse.parse import _SHELLS, _WINPATH, Cmd, _parse, _Scan, is_powershell
from pathconf import route
from pathgit import git
from pathmatch import DRIVE, DYNAMIC, FRESH, expand, values
from pathreach import Reach
from pathscript import Scripts
from pathsubst import PWD, bindings, resolver
from pathtext import SUBST, scan
from pathwin import mklink, windows
from pathwords import (
    CD,
    CHILDREN,
    DELETERS,
    DEST,
    POP,
    PUSH,
    REMOVERS,
    WINDOWS,
    ancestors,
    bound,
    is_interpreter,
    writes,
)
from pathwrap import WRAP, env_scripts, nested
from pathwriters import OUTPUT, awk, dest, find, output, sed

Normalise = Callable[[str], str]
_DEPTH = 3
# A Windows path the shell reads as an escape: a `\` that closes a folder name before a space, or follows `%VAR%`.
_CLOSING = re.compile(r"(?<=[^\s\\])\\(?=\s)|(?<=%)\\(?=\S)")
_QUOTED_END = re.compile(r'\\(?=")')  # `"C:\build\"`: the `\` closes the folder, it does not escape the quote
_CD_SWITCH = frozenset(("/d",))
_DRIVE_IN = re.compile(r"[A-Za-z]:\\")
_DEVICE_PATH = re.compile(
    r"(?<![\w\\])\\\\[?.]\\(?=[A-Za-z]:)"
)  # `\\?\C:\x` before a drive letter: the bash-style reading would eat it


class _Walk(Reach, Scripts):
    """One command line, run in order against a virtual working directory."""

    def __init__(
        self,
        protected: tuple[str, ...],
        hit: Callable[[str], bool],
        normalise: Normalise,
        start: str,
        *,
        ps: bool,
    ) -> None:
        self.hit, self.normal, self.ps, self.text = hit, normalise, ps, ""  # the setter reads the bindings of the text
        self.base = next((d for d in ancestors(start) if os.path.exists(os.path.join(d, ".git"))), start)
        self.root = self.normal(self.base)
        self.stack: list[str | None] = []
        self.docs: dict[str, str] = {}
        self.unsure: set[str] = set()
        self.prev: Cmd | None = None
        self.depth, self.blind, self.wrote = 0, False, False
        self.outputs: list[str] = []  # what each substitution of the line prints, when the line shows it
        self.unseen = False  # a substitution whose output the line does not show
        entries = [self.normal(entry).strip("/") for entry in (*protected, ".agents/policies/\0/implementations")]
        self.entries = entries
        self.files = [
            *entries,
            *(f"{e}{s}" for e in entries if e.endswith("/settings") for s in (".json", ".local.json")),
        ]
        self.dirs = sorted({"/".join(e.split("/")[:i]) for e in entries for i in range(1, e.count("/") + 1)})
        self.names = sorted({b for f in self.files if "." in (b := posixpath.basename(f))} | CHILDREN)
        self.kids = [*self.names, "config"]  # what can sit just below a folder the line names with an unknown variable
        parts = self.root.split("/")
        self.spots = [
            *("/".join(parts[:k]) or "/" for k in range(1, len(parts) + 1)),
            *(".", *("/".join([".."] * k) for k in range(1, len(parts)))),
            *("/".join([".."] * k + parts[-k:]) for k in range(1, len(parts))),
        ]
        self.here = [".", self.root]
        self.cwd = self._within(self.normal(start))
        self.history, self.resolve = [self.cwd], resolver(self.root)
        self.handlers: dict[str, Callable[[Cmd], bool]] = {
            **dict.fromkeys(REMOVERS, self._remove),
            **dict.fromkeys(DEST - WINDOWS, lambda c: dest(self, c.name, c.args, c.env)),
            **dict.fromkeys(WINDOWS - {"mklink"}, lambda c: windows(self, c.name, c.args, c.env)),
            "mklink": lambda c: mklink(self, c.args, c.env),
            **dict.fromkeys(OUTPUT, lambda c: output(self, c.name, c.args, c.env)),
            **dict.fromkeys(("awk", "gawk", "mawk", "nawk"), lambda c: awk(self, c.args, c.env)),
            **dict.fromkeys(("sed", "yq"), lambda c: sed(self, c.args, c.env)),
            "git": lambda c: git(self, c.args, c.env),
            "find": lambda c: find(self, c.args, c.env),
            "dd": self._dd,
            "uniq": self._uniq,
        }

    @property
    def text(self) -> str:
        """The command line being judged; setting it reads where each variable is bound, once."""
        return self._text

    @text.setter
    def text(self, value: str) -> None:
        self._text, self.bound = value, bindings(value)

    def git_refuses(self, args: list[str], env: dict[str, str]) -> bool:
        """Whether `git ARGS` is refused: an alias body is judged as the git command it will run."""
        return git(self, args, env)

    def _chdir(self, cmd_name: str, args: list[str], env: dict[str, str]) -> None:
        if cmd_name in PUSH:
            self.stack.append(self.cwd)
        words = [
            a for a in args if a.lower() not in _CD_SWITCH
        ]  # `cd /d DIR`: /d switches the drive, it is not the target
        target = expand(next((a for a in words if a == "-" or not a.startswith("-")), ""), env) or "~"
        self.cwd = None if target == "-" or DYNAMIC.search(target) else self._path(target, env)[0]

    def _unknown(self, args: list[str], env: dict[str, str]) -> bool:
        """A command named by a variable or substitution: judged on the plain paths it is given and on what the line assigned."""
        plain = [a for a in values(args) if "/" in a or not DYNAMIC.search(expand(a, env))]
        return any(self.reaches(t, env, parents=True) for t in plain) or any(
            self.reaches(v, {}, parents=True) for v in env.values()
        )

    def _remove(self, cmd: Cmd) -> bool:
        flags = flags_of(cmd.args)
        recursive = bool(flags & {"-r", "-R"}) or any(a.lower().startswith("-rec") for a in cmd.args)
        whole = cmd.name in DELETERS or recursive
        return any(self.reaches(t, cmd.env, parents=True, whole=whole) for t in values(cmd.args))

    def _dd(self, cmd: Cmd) -> bool:
        return any(a.startswith("of=") and self.reaches(a[3:], cmd.env) for a in cmd.args)

    def _uniq(self, cmd: Cmd) -> bool:
        return any(self.reaches(t, cmd.env) for t in values(cmd.args)[1:2])

    def command(self, cmd: Cmd) -> bool:
        """Whether one simple command may write, delete, move or link a protected path."""
        name, args, env = cmd.name, cmd.args, cmd.env
        if any(self.reaches(t, env) for t in cmd.writes) or route(env):  # route: git config keys set in the environment
            return True
        if "$" in name:
            self.blind = True
            return self._unknown(args, env) or (SUBST in name and self.computed())
        if name in WRAP:
            return self.wrapped(cmd)
        handler = self.handlers.get(name) or (self.code if is_interpreter(name) else None)
        return handler is not None and handler(cmd)

    def step(self, cmd: Cmd, prev: Cmd | None, *, unparsed: bool) -> bool:
        if nested(cmd):  # a script the reader did not unwrap: it cannot be judged, so it is refused
            return True
        if cmd.name in CD:
            self._chdir(cmd.name, cmd.args, cmd.env)
        elif cmd.name in POP:
            self.cwd = self.stack.pop() if self.stack else None
        elif (cmd.name in _SHELLS or cmd.name in (".", "source")) and self.stdin(cmd):
            return self.fed(cmd, prev)
        else:
            return self.command(cmd) or (unparsed and writes(cmd.name, cmd.writes))
        return False

    def run(self, text: str, *, ps: bool) -> bool:
        """Walk the commands of one script in order, tracking cd, pushd and popd."""
        unparsed, prev = _Scan(text).run() is None, None
        if any(self.loose(payload) for payload in env_scripts(text)):
            return True
        cmds = _parse(text, {}, ps=ps, depth=0)[0]
        for cmd in cmds:
            self.prev = prev
            self.unsure.update(bound(cmd))
            if any(self.step(c, prev, unparsed=unparsed) for c in self.variants(cmd)):
                return True
            self.wrote |= writes(cmd.name, cmd.writes)
            self.history.append(self.cwd)
            prev = cmd
        return False

    def variants(self, cmd: Cmd) -> list[Cmd]:
        """The command with `$PWD` bound and each variable that is no longer a fresh mktemp path made unknown.

        A value that holds `$PWD` was read where the line was, which may be any directory it has been in: one command each.
        """
        bound = self.bound
        env = {
            k: SUBST
            if k in bound.hidden or k in bound.refs or ((v.startswith(FRESH) or "$" in v) and bound.rebound(k))
            else v
            for k, v in cmd.env.items()
        }
        late = cmd.name not in CD and cmd.name not in POP and any(PWD.search(v) for v in env.values())
        where = dict.fromkeys([self.cwd, *self.history] if late else [self.cwd])
        return [cmd._replace(env={**self.pinned(at), **env}) for at in where]

    def pinned(self, cwd: str | None) -> dict[str, str]:
        """`PWD` as the virtual directory, when the guard knows it."""
        if cwd is None:
            return {}
        return {"PWD": self.root if cwd == "." else cwd if cwd.startswith("/") else f"{self.root}/{cwd}"}

    def _may_write(self, text: str) -> bool:
        """Whether a script holds a redirection or a command the guard judges by name."""
        cmds = _parse(text, {}, ps=self.ps, depth=0)[0]
        return any(writes(c.name, c.writes) or c.name in self.handlers or is_interpreter(c.name) for c in cmds)

    def script(self, text: str, depth: int) -> bool:
        """Whether a script, and each substitution in it, writes a protected path or may."""
        if depth > _DEPTH:
            return True
        self.depth, scanned = depth, scan(text, self.resolve)
        self.docs.update(scanned.docs)
        for body in scanned.bodies:
            result = self.shown(body)
            self.outputs += result[0]
            self.unseen = self.unseen or not result[1]
        start, stack = self.cwd, list(self.stack)
        if self.run(scanned.outer, ps=self.ps):
            return True
        after = self.cwd, self.stack
        # A substitution runs wherever the line has got to: judge it from the start and from where the line ends.
        for body, (cwd, held) in itertools.product(scanned.bodies, ((start, stack), after)):
            self.cwd, self.stack = cwd, list(held)
            if depth < _DEPTH and self.script(body, depth + 1):
                return True
            if depth >= _DEPTH and self._may_write(body):
                return True  # too deep to judge: refused when it holds anything that could change a file
        self.cwd, self.stack = after
        self.depth = depth
        return False


def _closed(raw: str) -> str:
    """The line with each Windows folder-closing `\\` read as a separator, as Windows reads it."""
    raw = _DEVICE_PATH.sub("", raw)
    closed = _CLOSING.sub("/", _QUOTED_END.sub("/", raw) if _DRIVE_IN.search(raw) else raw)
    return _WINPATH.sub("/", closed)


def refuses(raw: str, protected: tuple[str, ...], hit: Callable[[str], bool], normalise: Normalise) -> bool:
    """Whether a command line writes, deletes, moves or links a protected path or a directory holding one, or may."""
    start = os.environ.get("CHOCK_HOOK_CWD") or os.getcwd()
    start = start if DRIVE.match(start) else os.path.abspath(start)
    ps = is_powershell(raw)
    views = (
        [raw.replace("\\", "/").replace("`", "")]
        if ps
        else list(dict.fromkeys([raw, _WINPATH.sub("/", raw), _closed(raw)]))
    )
    for view in views:
        walk = _Walk(protected, hit, normalise, start, ps=ps)
        walk.text = view
        if walk.script(view, 0) or (walk.blind and walk.wrote):
            return True
    return False
