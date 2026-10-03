"""How each writer names the paths it changes: cp and mv, git, sed, awk, find, interpreters, output flags (stdlib only)."""

from __future__ import annotations

import posixpath
import re
import shlex
from fnmatch import fnmatchcase
from itertools import pairwise, takewhile
from typing import Any

from chock_shellparse import abbreviates, flags_of
from chock_shellparse.parse import _SHELLS, _WRAPPERS
from pathmatch import DYNAMIC, literals
from pathwords import is_interpreter
from pathwrap import WRAP

_SHORT = 2
_RECURSIVE = frozenset(("-r", "-R", "-a", "--recursive", "--archive"))
_LINKING = (
    "--link",
    "--symbolic-link",
)  # `cp -l` makes a hard link and `cp -s` a symlink, as `ln` does (GNU takes any unambiguous prefix)
_CODE = re.compile(r"-[A-Za-z]*[ceEpir]|--(?:eval|print|in-place)|eval")
_EXEC = frozenset(("-exec", "-execdir", "-ok", "-okdir"))
_FPRINT = frozenset(("-fprint", "-fprint0", "-fprintf", "-fls"))
_NO_FILTER = frozenset(("!", "-not", "-o", "-or", "-regex", "-iregex"))
_NAMED = {"-name": False, "-iname": False, "-path": True, "-ipath": True, "-wholename": True, "-iwholename": True}
_ENTRY = "found-entry"  # what `{}` stands for when the body is judged without a found path
_STRING = re.compile(r"""['"]([^'"\s]+)['"]""")
# Programs `find -exec` may run on a protected file without changing it; any other program there is judged as a writer.
READERS = frozenset(
    (
        *("cat", "grep", "egrep", "fgrep", "rg", "ls", "file", "stat", "head", "tail", "wc", "diff", "cmp"),
        *("md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "echo", "printf", "test", "["),
        *("realpath", "readlink", "basename", "dirname", "du", "true", "false"),
    )
)
_AWK_RUN = (
    re.compile(r'system\(\s*"((?:[^"\\]|\\.)*)"'),
    re.compile(r'\|\s*"((?:[^"\\]|\\.)*)"'),
    re.compile(r'"((?:[^"\\]|\\.)*)"\s*\|\s*getline'),
)
_SED_RUN = re.compile(r"(?:^|[;{}\n])\s*(?:[\d$]+(?:,[\d$]+)?|/[^/]*/)?!?\s*e\s+([^;}\n]+)")
# Writers that take an output file or directory by option: name -> (options, run only when extracting).
OUTPUT = {
    "sort": ("-o --output", False),
    "shuf": ("-o --output", False),
    "pandoc": ("-o --output", False),
    "curl": ("-o --output --output-dir", False),
    "wget": ("-O --output-document -P --directory-prefix", False),
    "unzip": ("-d", False),
    "tar": ("-C --directory", True),
}


def _into(name: str, args: list[str]) -> tuple[str, list[str]]:
    """The directory named by `-t DIR`, `-tDIR`, `-rt DIR` or `--target-directory[=]DIR`, and the other arguments."""
    if name == "rsync":
        return "", args
    for at, arg in enumerate(args):
        fused = re.fullmatch(r"-[A-Za-z]*t=?([./~$].*)", arg)
        if arg.startswith("--target-directory="):
            return arg.split("=", 1)[1], args[:at] + args[at + 1 :]
        if fused:
            return fused[1], args[:at] + args[at + 1 :]
        if (arg == "--target-directory" or re.fullmatch(r"-[A-Za-z]*t", arg)) and at + 1 < len(args):
            return args[at + 1], args[:at] + args[at + 2 :]
    return "", args


def _lands_in(w: Any, target: str, sources: list[str], env: dict[str, str]) -> bool:
    """Whether a file copied into the directory `target` takes a protected name (`cp /tmp/x/CLAUDE.md src/`)."""
    names = [posixpath.basename(s.rstrip("/")) for s in sources]
    return any(n not in ("", ".", "..") and w.reaches(posixpath.join(target, n), env) for n in names)


def _into_dir(w: Any, name: str, args: tuple[str, str, list[str]], env: dict[str, str], *, linking: bool) -> bool:
    """Whether the sources are removed (mv), linked from (ln, `cp -l`, `cp -s`) or land in a directory under a protected name."""
    target, into, sources = args
    if name == "mv" and any(w.reaches(s, env, parents=True, whole=True) for s in sources):
        return True
    if linking and any(w.reaches(s, env, parents=True) for s in sources):
        return True
    dirlike = into or target.endswith("/") or w.is_dir(target, env)
    return (
        bool(target)
        and name != "rsync"
        and not w.outside(target, env)
        and dirlike
        and _lands_in(w, target, sources, env)
    )


def dest(w: Any, name: str, args: list[str], env: dict[str, str]) -> bool:
    """cp, mv, ln, install, rsync: what is written is the destination; mv also removes its sources."""
    into, rest = _into(name, args)
    operands = [a for a in rest if not a.startswith("-")]
    sources = operands if into else operands[:-1]
    target = into or (operands[-1] if operands else "")
    flags = flags_of(rest)
    links = name == "ln" or (
        name == "cp" and any(f in ("-l", "-s") or abbreviates(f, full, 3) for f in flags for full in _LINKING)
    )
    if _into_dir(w, name, (target, into, sources), env, linking=links):
        return True
    if not target or not w.reaches(target, env, parents=True, root=True):
        return False
    if w.reaches(target, env) or (name == "rsync" and any(f.startswith("--delete") for f in flags)):
        return True
    whole = name in ("mv", "ln") or bool(flags & _RECURSIVE)
    if whole and not (into or target.endswith("/") or w.at_root(target, env)):
        return True
    names = ["" if name == "rsync" and s.endswith("/") else posixpath.basename(s.rstrip("/")) for s in sources]
    return any(n in ("", ".", "..") or w.reaches(posixpath.join(target, n), env, parents=True) for n in names)


def sed(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """`sed -i` (and `yq -i`) edits its files; a `w file` command or `s///w file` flag writes one; `e cmd` runs one."""
    wrote = (m[1] for a in args for m in re.finditer(r"(?:^|\W)[wW]\s*([^\s;}]+)", a))
    if any(not DYNAMIC.search(t) and w.reaches(t, env) for t in wrote):
        return True
    if any(w.sub(m[1]) for a in args for m in _SED_RUN.finditer(a)):  # the `e command` command runs one
        return True
    if not any(re.fullmatch(r"-[A-Za-z]*i.*|--in-?place.*", a) for a in args):
        return False
    scripted = any(a in ("-e", "-f") for a in args)
    skip = {i + 1 for i, a in enumerate(args) if a in ("-e", "-f")}
    words = [a for i, a in enumerate(args) if not a.startswith("-") and i not in skip]
    return any(w.reaches(t, env) for t in (words if scripted else words[1:]))


def awk(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """A program that prints into a quoted file name or runs a quoted command, or `-i inplace` over its files."""
    named = [m for a in args for m in re.findall(r'>>?\s*"([^"\n]+)"', a)]
    operands = [a for a in args if not a.startswith("-") and a != "inplace"]
    inplace = "inplace" in args and "-i" in args
    if any(w.reaches(t, env) for t in named + (operands[1:] if inplace else [])):
        return True
    if any(w.sub(m) for a in args for rx in _AWK_RUN for m in rx.findall(a)):
        return True
    # system() of a command the guard cannot read: any protected path named in the program counts.
    words = re.findall(r"[^\s\"'();|<>&,]+", " ".join(args))
    return any("system(" in a for a in args) and any(
        w.reaches(t, env, parents=True) for t in words if not DYNAMIC.search(t)
    )


def interpreter(w: Any, args: list[str], env: dict[str, str], scripts: list[str]) -> bool:
    """The code may write or remove any path it names as a string: plain literals only, never a guess at a glob."""
    code = bool(scripts) or any(_CODE.match(a) for a in args)
    words = [t for a in args for t in literals(a)] + [t for s in scripts for t in _STRING.findall(s)]
    return code and any(w.reaches(t, env, parents=True) for t in words if not DYNAMIC.search(t))


def output(w: Any, name: str, args: list[str], env: dict[str, str]) -> bool:
    """`sort -o FILE`, `curl -o FILE`, `unzip -d DIR`, `tar -x -C DIR`: the value of an output option is written."""
    options, extracting = OUTPUT[name]
    if extracting and not (flags_of(args) & {"-x", "--extract"} or re.match(r"[A-Za-z]*x", args[0] if args else "")):
        return False
    flags = options.split()
    found = []
    for at, arg in enumerate(args):
        if arg in flags and at + 1 < len(args):
            found.append(args[at + 1])
        found += [arg.split("=", 1)[1] for f in flags if f.startswith("--") and arg.startswith(f + "=")]
        found += [
            arg[2:] for f in flags if len(f) == _SHORT and arg.startswith(f) and len(arg) > _SHORT and arg[1] != "-"
        ]
    return any(w.reaches(t, env, parents=True) for t in found)


def _filter(preds: list[str]) -> Any:
    """Whether a path can pass the `-name` and `-path` tests of a find; no test, or any `-o`, `!` or `-regex`, passes all."""
    if _NO_FILTER & set(preds):
        return lambda _path: True
    tests = [(_NAMED[p], preds[k + 1].lower()) for k, p in enumerate(preds[:-1]) if p in _NAMED]

    def keep(path: str) -> bool:
        path = path.lower()
        return all(
            fnmatchcase(path, pat) or fnmatchcase(f"./{path}", pat)
            if whole
            else fnmatchcase(path.rsplit("/", 1)[-1], pat)
            for whole, pat in tests
        )

    return keep


def find(w: Any, args: list[str], env: dict[str, str]) -> bool:
    """find: `-fprint` targets; `-delete` and each `-exec` body judged against the protected paths below its start."""
    given = args[sum(1 for _ in takewhile(lambda a: a in ("-L", "-H", "-P"), args)) :]
    starts = list(takewhile(lambda a: not a.startswith(("-", "(", "!")), given))
    preds = given[len(starts) :]
    if any(w.reaches(t, env) for p, t in pairwise(preds) if p in _FPRINT):
        return True
    bodies, at = [], 0
    while at < len(preds):
        if preds[at] in _EXEC:
            end = next((j for j in range(at + 1, len(preds)) if preds[j] in (";", "+")), len(preds))
            bodies.append(preds[at + 1 : end])
            at = end
        at += 1
    if "-delete" not in preds and not bodies:
        return False
    keep = _filter(preds)
    found = [c for s in starts or ["."] for c in w.under(s, env) if w.reaches(s, env, parents=True) or keep(c)]
    if "-delete" in preds and found:
        return True
    for body in bodies:
        program = posixpath.basename(body[0]).lower() if body else ""
        if program in READERS:
            continue
        alone = not any("{}" in a for a in body)
        # The body is judged once with `{}` as a plain unknown name too: a filter that finds nothing leaves it unread otherwise.
        texts = (
            [shlex.join(body)] if alone else [shlex.join(a.replace("{}", c) for a in body) for c in (_ENTRY, *found)]
        )
        if any(w.sub(text) for text in texts) or (found and not alone and not _known(w, program)):
            return True
    return False


def _known(w: Any, program: str) -> bool:
    """Whether a program run by `find -exec` is one the guard judges by name (a writer, shell or wrapper); an interpreter is not."""
    return "$" not in program and (
        (program in w.handlers or program in _SHELLS or program in _WRAPPERS or program in WRAP)
        and not is_interpreter(program)
    )
