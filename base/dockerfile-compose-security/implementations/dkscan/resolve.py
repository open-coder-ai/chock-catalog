"""Which word of a command is the program it runs, and which inline scripts it carries.

Skipped before the program: keywords (if, then, do, function, coproc, ...), `case WORD in PATTERN)`,
assignments, redirections (`>/dev/null`, `2> log`) and wrappers that run the rest of the line,
with their options, option values and positional arguments (`sudo -u app`, `gosu root`,
`chroot /`, `flock /l`, `timeout 10`). Inline scripts are the strings a command hands to a shell:
`sh -c`, `bash -ec`, `eval ...`, `su -c`, `env -S`, `flock -c`.
"""

from __future__ import annotations

import posixpath
import re
from typing import NamedTuple

ASSIGNMENT = re.compile(r"[A-Za-z_]\w*\+?=")
REDIRECT = re.compile(r"(?:\d+|&)?(?:>>?|<<?|>&|<&|&>>?|>\|)(.*)", re.DOTALL)
LEADERS = frozenset(
    {
        "{",
        "}",
        "!",
        "(",
        "then",
        "do",
        "else",
        "if",
        "elif",
        "while",
        "until",
        "time",
        "-p",
        "function",
        "coproc",
        "select",
        "for",
        "in",
        "done",
        "fi",
        "esac",
    }
)
INLINE_FLAG = re.compile(r"-[A-Za-z]*c[A-Za-z]*")


class Wrapper(NamedTuple):
    values: frozenset[str]
    positional: int = 0


WRAPPERS = {
    "sudo": Wrapper(frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"})),
    "doas": Wrapper(frozenset({"-u", "-C"})),
    "env": Wrapper(frozenset({"-u", "-C", "--unset", "--chdir"})),
    "nice": Wrapper(frozenset({"-n", "--adjustment"})),
    "nohup": Wrapper(frozenset()),
    "exec": Wrapper(frozenset({"-a"})),
    "command": Wrapper(frozenset()),
    "builtin": Wrapper(frozenset()),
    "stdbuf": Wrapper(frozenset({"-i", "-o", "-e"})),
    "xargs": Wrapper(
        frozenset({"-n", "-I", "-i", "-P", "-L", "-l", "-s", "-d", "-E", "-e", "-a", "--max-args", "--max-procs"})
    ),
    "timeout": Wrapper(frozenset({"-s", "-k", "--signal", "--kill-after"}), 1),
    "gosu": Wrapper(frozenset(), 1),
    "su-exec": Wrapper(frozenset(), 1),
    "chroot": Wrapper(frozenset({"--userspec", "--groups"}), 1),
    "flock": Wrapper(frozenset({"-w", "-E", "--timeout", "--conflict-exit-code"}), 1),
    "setpriv": Wrapper(frozenset({"--reuid", "--regid", "--groups", "--inh-caps", "--bounding-set"})),
    "runuser": Wrapper(frozenset({"-u", "-g", "-G", "--user", "--group"})),
    "busybox": Wrapper(frozenset()),
    "unshare": Wrapper(frozenset()),
    "nsenter": Wrapper(frozenset({"-t", "--target"})),
}
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "csh", "tcsh", "mksh", "fish"})


def _skip_case(words: tuple[str, ...], at: int) -> int:
    """Past `case WORD in` and the first pattern (`x)`, `(x)`, `\\x00` for a parenthesised one)."""
    at = words.index("in", at) + 1 if "in" in words[at:] else len(words)
    while at < len(words) and not (words[at].endswith(")") or words[at] == "\x00"):
        at += 1
    return at + 1


def _skip_wrapper(words: tuple[str, ...], at: int, wrapper: Wrapper) -> int:
    while at < len(words) and words[at].startswith("-") and words[at] != "-":
        option = words[at]
        at += 2 if option in wrapper.values else 1
        if option == "--":
            break
    return at + wrapper.positional


def resolve(words: tuple[str, ...]) -> tuple[int, frozenset[str]]:
    """Index of the program word (-1: none), and the wrappers seen before it."""
    seen: set[str] = set()
    at = 0
    while at < len(words):
        word = words[at]
        base = posixpath.basename(word)
        redirect = REDIRECT.fullmatch(word)
        if word == "case":
            at = _skip_case(words, at + 1)
        elif redirect:
            at += 1 if redirect.group(1) else 2
        elif word in LEADERS or ASSIGNMENT.match(word):
            at += 1
        elif base in WRAPPERS:
            seen.add(base)
            at = _skip_wrapper(words, at + 1, WRAPPERS[base])
        else:
            return at, frozenset(seen)
    return -1, frozenset(seen)


def _after_flag(args: tuple[str, ...], at: int) -> str | None:
    """The first non-option word after args[at] (an inline-script flag), skipping `--` and other options."""
    for word in args[at + 1 :]:
        if word == "--" or (word.startswith("-") and word != "-"):
            continue
        return word
    return None


def inline_scripts(prog: str, args: tuple[str, ...], words: tuple[str, ...]) -> list[str]:
    """Strings this command runs as shell code."""
    found: list[str] = []
    first = posixpath.basename(words[0]) if words else ""
    if prog not in SHELLS and first in ("su", "runuser", "flock"):
        prog, args = first, words[1:]
    if prog in SHELLS or prog in ("su", "runuser", "flock"):
        for at, arg in enumerate(args):
            if INLINE_FLAG.fullmatch(arg) and (prog in SHELLS or arg == "-c"):
                script = _after_flag(args, at)
                found += [script] if script is not None else []
                break
            if arg.startswith("--command="):
                found.append(arg.split("=", 1)[1])
                break
    if prog == "eval" and args:
        found.append(" ".join(args))
    for at, word in enumerate(words):
        if word in ("-S", "--split-string") and at + 1 < len(words):
            found.append(words[at + 1])
        elif word.startswith("--split-string="):
            found.append(word.split("=", 1)[1])
    return found
