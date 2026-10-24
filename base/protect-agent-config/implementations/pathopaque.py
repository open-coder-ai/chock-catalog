"""Backstop: a line that runs script text the guard cannot read, and names a protected path anywhere (stdlib only)."""

from __future__ import annotations

import re
from collections.abc import Callable

from chock_shellparse.args import taken
from chock_shellparse.parse import _ASSIGN, _base, _Clause, _crude, _Scan, script_at
from chock_shellparse.wrappers import WRAPPERS as _WRAPPERS
from pathescape import decode
from pathtext import scan
from pathwrap import WRAPPERS

_DEPTH = 4
_DYNAMIC = re.compile(
    r"[$`]|<\("
)  # a variable, a substitution (the guard's `$__subst__` stands for one) or a process substitution
_NAMED = re.compile(r"\$\{|\$[^/]*$|`")  # a word that is a variable or a substitution, not a path below one
_BARE = str.maketrans("", "", "'\"\\`$(){}")  # the characters that can split a name without changing it
_DQ_ESCAPE = re.compile(r"\\([$\\\"`])")  # what a double-quoted word shows the shell it runs: `\$` is `$`, `\\` is `\`
_STDIN = re.compile(r"/dev/(?:stdin|fd/\d+)|/proc/self/fd/\d+")
_LEAD = frozenset(("do", "then", "else", "elif", "if", "while", "until", "!", "{", "time"))

# What runs a script the line may not show. Each row: a label, the command names, and how its script is given.
SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh", "mksh", "rbash", "yash"))
EVALS = frozenset(("eval", "iex", "invoke-expression"))
SOURCES = frozenset((".", "source"))
# interpreter name prefix -> the short letters and long options that give it a program on the command line
ONE_LINERS = {
    "python": ("c", ()),
    "pypy": ("c", ()),
    "perl": ("eE", ()),
    "ruby": ("e", ()),
    "node": ("ep", ("--eval", "--print")),
    "php": ("r", ()),
    "lua": ("e", ()),
    "bun": ("e", ("--eval", "--print")),
    "deno": ("", ("eval",)),
    "rscript": ("e", ()),
    "julia": ("eE", ("--eval", "--print")),
    "groovy": ("e", ()),
    "osascript": ("e", ()),
    "tclsh": ("", ()),
    "sqlite3": ("", ()),
    "gdb": ("", ("-ex", "-iex", "--eval-command", "--init-eval-command")),
}
# Commands that run the commands in their words, or text fed to them: any later word may be the command.
LAUNCHERS = frozenset((*_WRAPPERS, *WRAPPERS, "find", "parallel", "xargs", "busybox"))
FEEDERS = frozenset(("xargs", "find", "parallel"))  # the text of the command comes from input or from files found


def _dynamic(words: list[str]) -> bool:
    return any(_DYNAMIC.search(w) for w in words)


def _command_flag(args: list[str]) -> int | None:
    return next((k for k, a in enumerate(args) if a == "--command" or re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a)), None)


def _script_at(args: list[str], flag: int) -> int:
    """Where the script of `-c` is: after it, past the options and the `--` that end the options."""
    return flag + 1 + script_at(args[flag + 1 :], skip=taken(args[flag]))


def _shell(args: list[str]) -> bool:
    """Whether a shell reads a script it is not given as a literal: a `-c` with a variable or substitution or no script,
    standard input (no script file, `-s`, `/dev/stdin`), or a here-string or here-document (which leave no file)."""
    flag = _command_flag(args)
    if flag is not None:
        at = _script_at(args, flag)
        return at >= len(args) or _dynamic([args[at]])
    files = [a for a in args if not a.startswith("-")]
    return "-s" in args or not files or _STDIN.fullmatch(files[0]) is not None


def _literal(args: list[str]) -> str:
    """The script of `bash -c SCRIPT`, when there is a literal one."""
    flag = _command_flag(args)
    return args[_script_at(args, flag)] if flag is not None and _script_at(args, flag) < len(args) else ""


def _runtime(name: str, args: list[str]) -> tuple[bool, bool]:
    """Whether a language runtime has its program on the command line, and whether it reads it from standard input."""
    found = next(((short, long) for prefix, (short, long) in ONE_LINERS.items() if name.startswith(prefix)), None)
    if found is None:
        return False, False
    short, long = found
    flags = [a for a in args if a.startswith("-") and not a.startswith("--") and len(a) > 1]
    on_line = any(c in short for a in flags for c in a[1:]) or any(a.split("=")[0] in long for a in args)
    return on_line, not on_line and not [a for a in args if not a.startswith("-")]


# Commands that only read what they are given: a protected name in their words is read, not changed.
READS = frozenset(("cat", "grep", "egrep", "fgrep", "ls", "head", "tail", "wc", "diff", "cmp", "stat", "file"))
_EXPANDS = re.compile(r"[$`]")


def _literal_doc(clause: _Clause, docs: dict[str, str]) -> str | None:
    """The text of the here-document or here-string a clause reads, when it is the only input and the shell expands nothing in it."""
    texts = [docs.get(r) for r in clause.reads]
    if len(texts) != 1 or texts[0] is None or _EXPANDS.search(texts[0]):
        return None
    return texts[0]


def _plain_read(clause: _Clause) -> bool:
    """A command that only reads: a reader's own name, no output redirection, no assignment before it."""
    words = clause.words
    return bool(words) and not clause.writes and not _ASSIGN.match(words[0]) and _base(words[0]) in READS


class _Look:
    """One pass over a line and the scripts and substitutions in it: whether a construct runs unreadable text."""

    def __init__(self) -> None:
        self.found = False
        self.texts: list[str] = []  # every piece of text the line shows, for the protected-path test
        self.fed: list[str] = []  # each interpreter fed a literal here-document: its words, redirections and script
        self.rest: list[str] = []  # each other clause that is not a plain read
        self.judged = False  # the clause being read is an interpreter in `fed`

    def run(self, text: str, depth: int = 0) -> None:
        scanned = scan(text)
        self.texts += [scanned.outer, *scanned.docs.values()]
        for clause in _Scan(scanned.outer).run() or _crude(scanned.outer):
            own = " ".join([*clause.words, *clause.writes, *clause.reads, clause.doc])
            self.texts.append(own)
            doc = _literal_doc(clause, scanned.docs)
            self.judged = False
            self.clause(list(clause.words), depth, None if doc is None else f"{own} {doc}")
            if not self.judged and not _plain_read(clause):
                self.rest.append(own)
        for body in scanned.bodies if depth < _DEPTH else []:
            self.run(body, depth + 1)

    def clause(self, words: list[str], depth: int, shown: str | None = None) -> None:
        while words and (_ASSIGN.match(words[0]) or words[0] in _LEAD):
            words.pop(0)
        if not words:
            return
        if _NAMED.match(words[0]):
            self.found = True  # `$SH -c ...`, `"$x" ...`, `${cmd} ...`: the command is whatever the variable holds
            return
        name = _base(words[0])
        launcher = name in LAUNCHERS
        fed = name in FEEDERS
        self.found |= name == "env" and any(a in ("-S", "--split-string") or a.startswith("-S") for a in words[1:])
        for at in range(len(words) if launcher else 1):
            inner = _base(words[at])
            args = words[at + 1 :]
            fed |= inner in FEEDERS
            if at == 0 or inner in SHELLS | EVALS | SOURCES | ONE_LINERS.keys() or inner.startswith(tuple(ONE_LINERS)):
                self.invoke(inner, args, fed=fed, depth=depth, shown=shown)

    def invoke(self, name: str, args: list[str], *, fed: bool, depth: int, shown: str | None = None) -> None:
        if name in SHELLS:
            self.found |= fed or _shell(args)
            if depth < _DEPTH and (script := _literal(args)):
                self.run(script, depth + 1)
        elif name in EVALS:
            args = args[args[:1] == ["--"] :]
            self.found |= _dynamic(args)
            if depth < _DEPTH:
                self.run(" ".join(args), depth + 1)
        elif name in SOURCES:
            self.found |= not args or _dynamic(args) or _STDIN.fullmatch(args[0]) is not None
        elif name == "trap":
            words = args[args[:1] == ["--"] :]  # `trap -p`, `trap -l` and `trap - SIGNAL` set no body
            self.found |= bool(words) and words[0] not in ("-", "-p", "-l")
        else:
            on_line, stdin = _runtime(name, args)
            if stdin and not fed and shown is not None:
                self.fed.append(shown)  # the script is the here-document: it is read, and judged by what it names
                self.judged = True
            else:
                self.found |= on_line or stdin


def _spellings(raw: str) -> list[str]:
    """The text as written, with its backslash escapes decoded as bash decodes them, and with its quotes taken out."""
    spelled = [raw, *(decode(raw, mode).text for mode in ("b", "echo", "fmt", "ansi"))]
    fresh = spelled
    for _ in range(
        _DEPTH
    ):  # a script inside a double-quoted script is spelled with escapes that come off one level at a time
        fresh = [
            new
            for new in dict.fromkeys(decode(_DQ_ESCAPE.sub(r"\1", text), "ansi").text for text in fresh)
            if new not in spelled
        ]
        spelled = [*spelled, *fresh]
    return [*spelled, *(text.translate(_BARE) for text in spelled)]  # a `$'\x2e'` in a quoted script reads `.`


def refuses(raw: str, hit: Callable[[str], bool]) -> bool:
    """Whether a line runs script text the guard cannot read (eval of computed text, a shell fed from a variable, a pipe or a
    here-document, a variable as the command, `trap`, `xargs sh`, an interpreter one-liner) and names a protected path anywhere.

    An interpreter fed a here-document that expands nothing is not blind to it: that clause and every clause that is not a
    plain read (`cat`, `grep`, `ls` ...) are tested alone, so a read of a protected file elsewhere on the line does not count.

    The line is tested as written, with its backslash escapes decoded as bash decodes them, and as each part of it reads."""
    decoded = _spellings(raw)
    if not any(hit(text) for text in decoded):
        return False  # no path of the line is protected, as written, decoded or with its quotes taken out
    look = _Look()
    look.run(raw)
    if look.found and any(hit(text) for text in [*decoded, *look.texts]):
        return True
    return bool(look.fed) and any(hit(text) for text in _spellings("\n".join([*look.fed, *look.rest])))
