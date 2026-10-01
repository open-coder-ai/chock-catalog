"""Judge a shell command by the paths it resolves to: working directory, `..`, variables, globs, whole directories (stdlib only)."""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Callable, Iterator
from itertools import takewhile

from chock_shellparse import flags_of, git_parts
from chock_shellparse.parse import _WINPATH, _parse, _Scan, is_powershell

Normalise = Callable[[str], str]
_CD = frozenset(("cd", "chdir", "pushd", "set-location", "sl", "push-location"))
_PUSH = frozenset(("pushd", "push-location"))
_POP = frozenset(("popd", "pop-location"))
_REMOVERS = frozenset(
    (
        *("tee", "rm", "chmod", "chown", "truncate", "patch", "ed", "ex", "touch", "shred", "unlink", "rmdir"),
        *("set-content", "add-content", "out-file", "new-item", "clear-content", "remove-item", "move-item"),
        *("rename-item", "set-item", "tee-object", "sc", "ac", "ni", "ri", "mi", "rni", "del", "erase", "rd", "ren"),
    )
)
_DEST = frozenset(("cp", "install", "ln", "mv", "rsync", "scp", "copy-item", "copy", "cpi"))
_INTERPRETERS = ("python", "perl", "ruby", "node", "php")
_CODE_FLAGS = frozenset(("-c", "-e", "--eval", "-i", "--in-place", "-pi", "-ni", "-ne"))
_EXEC_FLAGS = frozenset(("-exec", "-execdir", "-ok"))
_HEREDOC = re.compile(r"(?<!<)<<(-?[ \t]*)(['\"]?)(\w+)\2([^\n]*)\n.*?\n[ \t]*\3[ \t]*(?=\n|$)", re.DOTALL)
_BACKTICKS = re.compile(r"`((?:[^`\\]|\\.)*)(?:`|$)")
_DYNAMIC = re.compile(r"[*?\[$]")
_VARIABLE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
_PIECE = re.compile(r"\$(?:\{[^}]*\}|\w+)")
_SUBST = "$__subst__"
_DEPTH = 3
_GUARD_DIRS = re.compile(r"(?:^|/)\.agents(?:/policies(?:/[^/]+)?)?$")


def _ancestors(path: str) -> Iterator[str]:
    while True:
        yield path
        parent = os.path.dirname(path)
        if parent == path:
            return
        path = parent


def _heredocs_removed(text: str) -> str:
    """The bodies of here-documents are data, not commands."""
    return _HEREDOC.sub(lambda m: f"<<{m[1]}{m[2]}{m[3]}{m[2]}{m[4]}\n{m[3]}", text)


def _close(text: str, start: int) -> int:
    depth, at = 1, start
    while at < len(text) and depth:
        depth += (text[at] == "(") - (text[at] == ")")
        at += 1
    return at


def _split(text: str) -> tuple[str, list[str]]:
    """The text with each `$(...)` and backtick substitution replaced by a placeholder word, and the bodies cut out."""
    out, bodies, at, quote = [], [], 0, ""
    while at < len(text):
        char = text[at]
        step, piece = 1, char
        if char == "\\" and quote != "'":
            step, piece = 2, text[at : at + 2]
        elif char in "'\"" and quote in ("", char):
            quote = "" if quote else char
        elif quote != "'" and text.startswith("$(", at):
            end = _close(text, at + 2)
            bodies.append(text[at + 2 : end].removesuffix(")"))
            step, piece = end - at, _SUBST
        elif quote != "'" and char == "`" and (found := _BACKTICKS.match(text, at)):
            bodies.append(found[1])
            step, piece = found.end() - at, _SUBST
        out.append(piece)
        at += step
    return "".join(out), bodies


def _expand(token: str, env: dict[str, str]) -> str:
    """Replace `$X` and `${X}` that an earlier assignment in the same command line set to a plain value."""

    def value(found: re.Match[str]) -> str:
        known = env.get(found[1] or found[2])
        return found[0] if known is None or _DYNAMIC.search(known) else known

    return _VARIABLE.sub(value, token)


def _bracket(body: str) -> str:
    negated = body[:1] in ("!", "^")
    return (
        "[" + ("^" if negated else "") + (body[1:] if negated else body).replace("\\", "\\\\").replace("[", "\\[") + "]"
    )


def _regex(pattern: str, *, loose: bool) -> re.Pattern[str]:
    """A glob (`*` `?` `[..]`, never matching `/` or a leading dot) and unknown variable text (anything) as a regex."""
    out, at = ["(?:.*/)?" if loose else ""], 0
    while at < len(pattern):
        char = pattern[at]
        if char in "*?[" and (at == 0 or pattern[at - 1] == "/"):
            out.append(r"(?!\.)")
        piece = _PIECE.match(pattern, at) if char == "$" else None
        close = pattern.find("]", at + 2) if char == "[" else -1
        if piece:
            out.append(".*")
            at = piece.end()
        elif close > 0:
            out.append(_bracket(pattern[at + 1 : close]))
            at = close + 1
        else:
            out.append({"*": "[^/]*", "?": "[^/]"}.get(char) or re.escape(char))
            at += 1
    try:
        return re.compile("".join(out), re.DOTALL)
    except re.error:
        return re.compile(".*")


def _values(args: list[str]) -> list[str]:
    """Path-like words of an argument list: operands, and the value of `--opt=x` or `-Path:x`."""
    found = []
    for arg in args:
        if not arg.startswith("-"):
            found.append(arg)
        elif "=" in arg or ":" in arg:
            found.append(re.split("[=:]", arg, maxsplit=1)[1])
    return found


def _literals(arg: str) -> list[str]:
    return [arg, *re.findall(r"""['"]([^'"\s]+)['"]""", arg)]


def _writes(name: str, redirects: list[str]) -> bool:
    return bool(redirects) or name in _REMOVERS | _DEST | {"dd"}


class _Walk:
    """One command line, run in order against a virtual working directory."""

    def __init__(
        self, protected: tuple[str, ...], hit: Callable[[str], bool], normalise: Normalise, where: str
    ) -> None:
        self.hit, self.normal = hit, normalise
        self.root = self.normal(where)
        self.stack: list[str | None] = []
        entries = [self.normal(entry).strip("/") for entry in (*protected, ".agents/policies/x/implementations")]
        self.entries = entries
        self.files = [path for e in entries for path in (e, f"{e}/x", f"{e}.json")]
        self.dirs = sorted({"/".join(e.split("/")[:i]) for e in entries for i in range(1, e.count("/") + 1)})
        self.cwd = self._within(self.normal(os.getcwd()))

    def _within(self, path: str) -> str:
        if path == self.root:
            return "."
        return path[len(self.root) + 1 :] if path.startswith(self.root + "/") else path

    def _path(self, token: str, env: dict[str, str]) -> tuple[str, bool]:
        """The token as a repo-relative, normalised path, and whether the directory it is relative to is unknown."""
        token = _expand(token, env).replace("\\", "/")
        if token.startswith("/"):
            return self._within(self.normal(posixpath.normpath(token))), False
        return self.normal(posixpath.normpath(posixpath.join(self.cwd or "", token))), self.cwd is None

    def _parent(self, path: str) -> bool:
        """Whether a path is a directory that holds a protected path."""
        parts = path.split("/")
        tails = ("/".join(parts[-k:]) for k in range(1, len(parts) + 1))
        return any(e == t or e.startswith(f"{t}/") for t in tails for e in self.entries) or bool(
            _GUARD_DIRS.search(path)
        )

    def reaches(self, token: str, env: dict[str, str], *, parents: bool = False) -> bool:
        """Whether a token, read as a path (or a glob, or text with variables), is protected, or holds a protected path."""
        if not token:
            return False
        path, loose = self._path(token, env)
        if not (loose or _DYNAMIC.search(path)):
            return self.hit(path) or (parents and self._parent(path))
        rx = _regex(path, loose=loose)
        prefixes = ("",) if self.cwd in (None, ".") else ("", f"{self.cwd}/")
        return any(rx.fullmatch(p + c) for c in (*self.files, *(self.dirs if parents else ())) for p in prefixes)

    def _chdir(self, cmd_name: str, args: list[str], env: dict[str, str]) -> None:
        if cmd_name in _PUSH:
            self.stack.append(self.cwd)
        target = _expand(next((a for a in args if a == "-" or not a.startswith("-")), ""), env) or "~"
        self.cwd = None if target == "-" or _DYNAMIC.search(target) else self._path(target, env)[0]

    def _dest(self, cmd_name: str, args: list[str], env: dict[str, str]) -> bool:
        """cp, mv, ln, install, rsync, scp: the destination is written, and a directory that holds a protected path is not a safe one."""
        operands = [a for a in args if not a.startswith("-")]
        into = next((a.split("=", 1)[1] for a in args if a.startswith("--target-directory=")), "")
        into = into or (args[args.index("-t") + 1] if "-t" in args[:-1] else "")
        sources = [a for a in operands if a != into] if into else operands[:-1]
        dest = into or (operands[-1] if operands else "")
        if cmd_name == "mv" and any(self.reaches(s, env, parents=True) for s in sources):
            return True
        if not dest or not self.reaches(dest, env, parents=True):
            return False
        if self.reaches(dest, env):
            return True
        flags = flags_of(args)
        whole = cmd_name in ("mv", "ln") or bool(flags & {"-r", "-R", "-a", "--recursive", "--archive"})
        if whole and not (into or dest.endswith("/")):
            return True
        names = [posixpath.basename(s.rstrip("/")) for s in sources]
        return any(n in ("", ".", "..") or self.reaches(posixpath.join(dest, n), env) for n in names)

    def _git(self, args: list[str], env: dict[str, str]) -> bool:
        sub, _, rest = git_parts(args)
        if sub not in ("checkout", "restore", "rm", "mv") or ("--staged" in rest and sub == "restore"):
            return False
        paths = rest[rest.index("--") + 1 :] if "--" in rest else []
        static = [t for t in _values(rest) if sub in ("rm", "mv") or t in paths or not _DYNAMIC.search(t)]
        return any(self.reaches(t, env, parents=True) for t in static)

    def _sed(self, args: list[str], env: dict[str, str]) -> bool:
        if not any(re.fullmatch(r"-[A-Za-z]*i.*|--in-place.*", a) for a in args):
            return False
        scripted = any(a in ("-e", "-f") for a in args)
        skip = {i + 1 for i, a in enumerate(args) if a in ("-e", "-f")}
        words = [a for i, a in enumerate(args) if not a.startswith("-") and i not in skip]
        return any(self.reaches(w, env) for w in (words if scripted else words[1:]))

    def _interpreter(self, args: list[str], env: dict[str, str]) -> bool:
        """The code may write any path it names as a string: plain literals only, never a guess at a glob."""
        code = bool(_CODE_FLAGS & set(args)) or any(re.fullmatch(r"-(?:pi|i)\..*", a) for a in args)
        words = [w for a in args for w in _literals(a) if not _DYNAMIC.search(w)]
        return code and any(self.reaches(w, env) for w in words)

    def _find(self, args: list[str], env: dict[str, str]) -> bool:
        given = set(args)
        if "-delete" not in given and not (given & _EXEC_FLAGS and given & (_REMOVERS | {"mv"})):
            return False
        starts = takewhile(lambda arg: not arg.startswith(("-", "(", "!")), args)
        return any(self.reaches(s, env, parents=True) for s in starts)

    def _unknown(self, args: list[str], env: dict[str, str]) -> bool:
        """A command named by a variable or substitution: judged on the plain paths it is given and on what the line assigned."""
        plain = [a for a in _values(args) if not _DYNAMIC.search(_expand(a, env))]
        return any(self.reaches(t, env, parents=True) for t in plain) or any(
            self.reaches(v, {}, parents=True) for v in env.values()
        )

    def command(self, name: str, args: list[str], writes: list[str], env: dict[str, str]) -> bool:
        """Whether one simple command may write, delete, move or link a protected path."""
        if any(self.reaches(t, env) for t in writes):
            return True
        if "$" in name:
            return self._unknown(args, env)
        if name in _REMOVERS:
            return any(self.reaches(t, env, parents=True) for t in _values(args))
        if name in _DEST:
            return self._dest(name, args, env)
        if name == "dd":
            return any(a.startswith("of=") and self.reaches(a[3:], env) for a in args)
        checks = {"git": self._git, "sed": self._sed, "find": self._find}
        check = checks.get(name) or (self._interpreter if name.startswith(_INTERPRETERS) else None)
        return check is not None and check(args, env)

    def run(self, text: str, *, ps: bool) -> bool:
        """Walk the commands of one script in order, tracking cd, pushd and popd."""
        unparsed = _Scan(text).run() is None
        for cmd in _parse(text, {}, ps=ps, depth=0)[0]:
            if cmd.name in _CD:
                self._chdir(cmd.name, cmd.args, cmd.env)
            elif cmd.name in _POP:
                self.cwd = self.stack.pop() if self.stack else None
            elif self.command(cmd.name, cmd.args, cmd.writes, cmd.env) or (unparsed and _writes(cmd.name, cmd.writes)):
                return True
        return False


def refuses(raw: str, protected: tuple[str, ...], hit: Callable[[str], bool], normalise: Normalise) -> bool:
    """Whether a command line writes, deletes, moves or links a protected path or a directory holding one, or may."""
    where = next((d for d in _ancestors(os.getcwd()) if os.path.exists(os.path.join(d, ".git"))), os.getcwd())
    ps = is_powershell(raw)
    views = [raw.replace("\\", "/").replace("`", "")] if ps else list(dict.fromkeys([raw, _WINPATH.sub("/", raw)]))
    queue = [(view, 0) for view in views]
    while queue:
        text, depth = queue.pop()
        outer, bodies = _split(_heredocs_removed(text))
        queue += [(body, depth + 1) for body in bodies if depth < _DEPTH]
        if _Walk(protected, hit, normalise, where).run(outer, ps=ps):
            return True
    return False
