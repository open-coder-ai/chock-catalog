"""Commands that print a credential, and the commands that dump the whole environment (stdlib only)."""

from __future__ import annotations

import re
import shlex
from fnmatch import fnmatchcase
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
}
ENV_VALUES = frozenset(("-u", "-C", "--unset", "--chdir"))
DUMP = "an environment dump (env, printenv, set, export -p)"


def matches(cmd: Cmd, rule: dict[str, Any]) -> bool:
    """Whether a command is the token printer a table rule names."""
    pos = positionals(cmd.args, frozenset(rule.get("value_flags", ())))
    words = rule["words"]
    wanted = rule.get("flags")
    return (
        fnmatchcase(cmd.name, rule["cmd"])
        and pos[: len(words)] == words
        and (not wanted or bool(flags_of(cmd.args) & set(wanted)))
        and bool(re.search(rule.get("field", ""), ([*pos[len(words) :], ""])[0], re.I))
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
        elif ASSIGN.match(words[0]):
            words = words[1:]
        else:
            break
    return words


def _env(rest: list[str]) -> bool:
    """`env` with only options and assignments runs no command, so it prints the environment."""
    skip = False
    for word in rest:
        if skip:
            skip = False
        elif word in ENV_VALUES:
            skip = True
        elif not (word.startswith("-") or ASSIGN.match(word)):
            return False
    return True


def _dumps(name: str, rest: list[str]) -> bool:
    flags = "".join(word.lstrip("-") for word in rest if word.startswith("-"))
    names = [word for word in rest if not word.startswith("-")]
    bare = not names
    return {
        "env": lambda: _env(rest),
        "printenv": lambda: bare or any(SECRET_NAME.search(word) for word in names),
        "set": lambda: not rest,
        "export": lambda: bare and (not rest or "p" in flags),
        "declare": lambda: bare and bool(set(flags) & {"p", "x"}),
        "typeset": lambda: bare and bool(set(flags) & {"p", "x"}),
    }.get(name, lambda: False)()


def _body(name: str, rest: list[str]) -> str:
    """The script text of `bash -c BODY` or `eval ARGS`, or ''."""
    if name == "eval":
        return " ".join(rest)
    flag = next((i for i, w in enumerate(rest) if w[:1] == "-" and w[1:2] != "-" and "c" in w[1:]), None)
    return rest[flag + 1] if name in SHELLS and flag is not None and flag + 1 < len(rest) else ""


def dump(raw: str) -> bool:
    """Whether any command in the line prints the environment, looking inside `bash -c` and `eval` bodies."""
    for words in map(strip, segments(raw)):
        if not words:
            continue
        name, rest = words[0].rsplit("/", 1)[-1], words[1:]
        if _dumps(name, rest):
            return True
        if (body := _body(name, rest)) and dump(body):
            return True
    return False
