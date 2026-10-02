"""Commands that print a credential, and the commands that dump the whole environment (stdlib only)."""

from __future__ import annotations

import re
import shlex
from fnmatch import fnmatchcase
from itertools import takewhile
from typing import Any

from chock_shellparse import Cmd, flags_of, positionals

SEPARATORS = frozenset(";&|()")
REDIRECTS = frozenset("<>&|;()")
ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
SECRET_NAME = re.compile(r"api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key|access[_-]?key|credential", re.I)
SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "ash"))
SUDO_VALUES = frozenset(("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"))
PREFIXES = {
    **dict.fromkeys(("sudo", "doas"), SUDO_VALUES),
    **dict.fromkeys(("command", "builtin", "nohup", "time", "exec", "setsid", "!", "{", "}"), frozenset()),
    **dict.fromkeys(("if", "then", "else", "elif", "do", "while", "until"), frozenset()),
    "nice": frozenset(("-n",)),
    "ionice": frozenset(("-c", "-n", "-p", "-t")),
    "stdbuf": frozenset(("-i", "-o", "-e")),
    "timeout": frozenset(("-s", "-k", "--signal", "--kill-after")),
    "xargs": frozenset(("-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s")),
}
ENV_VALUES = frozenset(("-u", "-C", "--unset", "--chdir"))
DUMP = "an environment dump (env, printenv, set, export -p)"


def matches(cmd: Cmd, rule: dict[str, Any]) -> bool:
    """Whether a command is the token printer a table rule names."""
    pos = positionals(cmd.args, frozenset(rule.get("value_flags", ())))
    words = rule["words"]
    wanted = rule.get("flags")
    # The words may follow global options whose values the table does not know (`aws --cli-read-timeout 5 ...`).
    at = next((i for i in range(len(pos) + 1) if pos[i : i + len(words)] == words), None)
    return (
        fnmatchcase(cmd.name, rule["cmd"])
        and at is not None
        and (not wanted or bool(flags_of(cmd.args) & set(wanted)))
        and bool(re.search(rule.get("field", ""), ([*pos[(at or 0) + len(words) :], ""])[0], re.I))
    )


def printer(cmd: Cmd, rules: list[dict[str, Any]]) -> str:
    """What a token-printing command is called in the refusal, or ''."""
    return next((rule["what"] for rule in rules if matches(cmd, rule)), "")


def segments(raw: str) -> list[list[str]]:
    """Words of each simple command in a line, split at ; & | and parentheses; redirections dropped."""
    lexer = shlex.shlex(raw.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        tokens = raw.replace("\n", " ; ").split()
    found: list[list[str]] = [[]]
    skip = False
    for token in tokens:
        punct = set(token) <= REDIRECTS
        if skip:
            skip = False
        elif punct and set(token) <= SEPARATORS:
            found.append([])
        elif punct:
            skip = True
            if found[-1] and found[-1][-1].isdigit():
                found[-1].pop()
        else:
            found[-1].append(token)
    return [words for words in found if words]


def strip(words: list[str]) -> list[str]:
    """The command after sudo, command, time, assignments and shell keywords."""
    while words:
        name = words[0].rsplit("/", 1)[-1]
        if name in PREFIXES:
            words = words[1:]
            while words and words[0].startswith("-") and len(words[0]) > 1:
                words = words[2 if words[0] in PREFIXES[name] else 1 :]
            words = words[1:] if name == "timeout" else words
        elif ASSIGN.match(words[0]):
            words = words[1:]
        else:
            break
    return words


def _env_command(rest: list[str]) -> list[str]:
    """The command `env` runs after its options and assignments; [] when it runs none and so prints the environment."""
    i = 0
    while i < len(rest) and (rest[i] in ENV_VALUES or rest[i].startswith("-") or ASSIGN.match(rest[i])):
        i += 2 if rest[i] in ENV_VALUES else 1
    return rest[i:]


def _dumps(name: str, rest: list[str]) -> bool:
    flags = "".join(word.lstrip("-") for word in rest if word.startswith("-"))
    names = [word for word in rest if not word.startswith("-")]
    bare = not names
    return {
        "env": lambda: not _env_command(rest),
        "printenv": lambda: bare or any(SECRET_NAME.search(word) for word in names),
        "set": lambda: not rest,
        "export": lambda: bare and (not rest or "p" in flags),
        "declare": lambda: bare and (not rest or bool(set(flags) & {"p", "x"})),
        "typeset": lambda: bare and (not rest or bool(set(flags) & {"p", "x"})),
    }.get(name, lambda: False)()


def body(name: str, rest: list[str]) -> str:
    """The script text of `bash -c BODY` or `eval ARGS`, or ''."""
    if name == "eval":
        return " ".join(rest)
    flag = next((i for i, w in enumerate(rest) if w[:1] == "-" and w[1:2] != "-" and "c" in w[1:]), None)
    return rest[flag + 1] if name in SHELLS and flag is not None and flag + 1 < len(rest) else ""


def _mask(text: str) -> str:
    """The text with single-quoted spans and backslash-escaped characters blanked: the shell runs nothing there."""
    out, quote, double, i = list(text), False, False, 0
    while i < len(text):
        char = text[i]
        if quote:
            quote = char != "'"
            out[i] = " "
        elif char == "\\":
            out[i : i + 2] = " " * len(out[i : i + 2])
            i += 1
        elif char == "'" and not double:
            quote, out[i] = True, " "
        else:
            double = double != (char == '"')
        i += 1
    return "".join(out)


def substitutions(text: str) -> list[str]:
    """Bodies of `$(...)` and backtick substitutions the shell would run, quoted or not, nested ones included."""
    masked = _mask(text)
    found = [text[m.start(1) : m.end(1)] for m in re.finditer(r"`([^`]*)`", masked)]
    for start in re.finditer(r"\$\(", masked):
        depth, end = 1, start.end()
        while end < len(masked) and depth:
            depth += {"(": 1, ")": -1}.get(masked[end], 0)
            end += 1
        found.append(text[start.end() : end - 1 if depth == 0 else end])
    return found


def _nested(name: str, rest: list[str]) -> list[str]:
    """Command lines a wrapper runs that the dump check should read too: bash -c, eval, env CMD, env -S, find -exec."""
    found = [body(name, rest)]
    if name == "env":
        found += [
            shlex.join(_env_command(rest)),
            *[rest[i + 1] for i, w in enumerate(rest[:-1]) if w in ("-S", "--split-string")],
        ]
    if name == "find":
        runs = [rest[i + 1 :] for i, w in enumerate(rest) if w in ("-exec", "-execdir", "-ok", "-okdir")]
        found += [shlex.join(list(takewhile(lambda w: w not in (";", "+"), run))) for run in runs]
    return [line for line in found if line]


def dump(raw: str) -> bool:
    """Whether any command in the line prints the environment, looking inside wrappers and substitutions."""
    if any(dump(body) for body in substitutions(raw)):
        return True
    for words in map(strip, segments(raw)):
        name, rest = (words[0].rsplit("/", 1)[-1], words[1:]) if words else ("", [])
        if _dumps(name, rest) or any(dump(line) for line in _nested(name, rest)):
            return True
    return False
