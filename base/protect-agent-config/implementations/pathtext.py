"""Read a command line's text before it is parsed: quoting forms, substitutions, here-documents, brace lists (stdlib only)."""

from __future__ import annotations

import re
from typing import NamedTuple

from chock_shellparse.parse import _QUOTED, _unquote
from pathmatch import FRESH

SUBST = "$__subst__"
_WORD = re.compile(f"{_QUOTED}+", re.DOTALL)
_DOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([^\s'\"<>;&|()]+)\2")
_DECLARE = re.compile(r"(?:declare|local|readonly|typeset)[ \t]+(?:-[A-Za-z]+[ \t]+)*")
_DUP = re.compile(r"&[ \t]*(?:\d+-?|-)(?![\w$])")
_BACKTICKS = re.compile(r"`((?:[^`\\]|\\.)*)(?:`|$)")
_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|c.|.)", re.DOTALL)
_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v"}
_RANGE = re.compile(r"(-?\d+)\.\.(-?\d+)|([A-Za-z])\.\.([A-Za-z])")
_LIMIT = 128
# `mktemp` with only these options, and a template (if any) under $TMPDIR, names a fresh path.
_MKTEMP = re.compile(
    r"\s*mktemp(?:\s+(?:-[duqt]+|--(?:directory|dry-run|quiet|tmpdir|suffix=[\w.-]*)))*"
    r"(?:\s+\$\{?TMPDIR\}?/[\w.-]*X{3,}[\w.-]*)?\s*"
)
_MKTEMP_T = re.compile(
    r"\s*mktemp\s+-[duq]*t[duq]*(?:\s+-[duq]+)*\s+[\w.-]*X{3,}[\w.-]*\s*"
)  # -t: a name below $TMPDIR


class Scanned(NamedTuple):
    """The text with every substitution and here-document taken out, and what was taken."""

    outer: str
    bodies: list[str]
    docs: dict[str, str]


def _holder(body: str) -> str:
    """The word a substitution is replaced by: a fresh path for a plain mktemp, otherwise an unknown."""
    return FRESH if _MKTEMP.fullmatch(body) or _MKTEMP_T.fullmatch(body) else SUBST


def _matching(text: str, start: int) -> int:
    """The index after the `)` that closes the `(` at `start` (the end of the text when there is none)."""
    depth, at = 0, start
    while at < len(text):
        depth += (text[at] == "(") - (text[at] == ")")
        at += 1
        if not depth:
            break
    return at


def ansi_c(body: str) -> str:
    """The text of `$'...'` with its backslash escapes decoded (`\\x2e`, `\\056`, `\\u002e`, `\\n`)."""

    def one(found: re.Match[str]) -> str:
        code = found[1]
        if code[0] in "xuU" and len(code) > 1:
            return chr(int(code[1:], 16)) if int(code[1:], 16) else ""
        if code[0] in "01234567":
            return chr(int(code, 8) & 255) if int(code, 8) & 255 else ""
        return _SIMPLE.get(code, code[-1])

    return _ESCAPE.sub(one, body)


class _Text:
    """One left-to-right pass that knows quotes, so a `<<` or `$(` inside one is left alone."""

    def __init__(self, text: str) -> None:
        self.text, self.at, self.quote, self.clause = text, 0, "", 0
        self.out: list[str] = []
        self.bodies: list[str] = []
        self.docs: dict[str, str] = {}
        self.waiting: list[tuple[str, str]] = []

    def emit(self, piece: str, step: int | None = None) -> None:
        self.out.append(piece)
        self.at += len(piece) if step is None else step

    def starts(self, prefix: str) -> bool:
        return self.text.startswith(prefix, self.at)

    def clause_text(self) -> str:
        return "".join(self.out[self.clause :]).strip()

    def run(self) -> Scanned:
        while self.at < len(self.text):
            self.step(self.text[self.at])
        return Scanned("".join(self.out), self.bodies, self.docs)

    def step(self, char: str) -> None:
        if self.quote == "'":
            self.quote = "" if char == "'" else "'"
            self.emit(char)
        elif char == "\\":
            self.emit(self.text[self.at : self.at + 2])
        elif char == '"':
            self.quote = "" if self.quote else '"'
            self.emit(char)
        elif char == "'" and not self.quote:
            self.quote = "'"
            self.emit(char)
        else:
            self.other(char)

    def other(self, char: str) -> None:
        if self.starts("$((") and self.text[_matching(self.text, self.at + 1) - 1] == ")":
            self.emit("0", _matching(self.text, self.at + 1) - self.at)
        elif self.starts("$("):
            end = _matching(self.text, self.at + 1)
            self.bodies.append(self.text[self.at + 2 : end].removesuffix(")"))
            self.emit(_holder(self.bodies[-1]), end - self.at)
        elif char == "`" and (found := _BACKTICKS.match(self.text, self.at)):
            self.bodies.append(found[1])
            self.emit(_holder(found[1]), found.end() - self.at)
        elif not self.quote:
            self.bare(char)
        else:
            self.emit(char)

    def bare(self, char: str) -> None:
        """A character outside quotes."""
        if self.starts("$'") and (end := self.ansi_end()):
            decoded = ansi_c(self.text[self.at + 2 : end]).replace("'", "'\\''")
            self.emit(f"'{decoded}'", end + 1 - self.at)
        elif self.starts('$"'):
            self.quote = '"'
            self.emit('"', 2)
        elif char in "dlrt" and not self.clause_text() and (declared := _DECLARE.match(self.text, self.at)):
            self.emit("export ", declared.end() - self.at)
        elif not self.redirection(char):
            self.plain(char)

    def redirection(self, char: str) -> bool:
        """Handle a `<<<`, `<<` or `>&` here; arithmetic `<<` of a `let` is not one."""
        if char == "<" and self.clause_text().startswith("let "):
            self.emit("_")
        elif self.starts("<<<") and (word := _WORD.match(self.text, self.at + 3 + self.gap(3))):
            self.here(word)
        elif (
            self.starts("<<") and self.text[self.at - 1 : self.at] != "<" and (found := _DOC.match(self.text, self.at))
        ):
            self.document(found)
        elif self.starts(">&") and self.text[self.at - 1 : self.at] != "&" and not _DUP.match(self.text, self.at + 1):
            self.emit(">", 2)
        else:
            return False
        return True

    def plain(self, char: str) -> None:
        if char == "\n":
            self.emit(char)
            self.bodies_of_documents()
            self.clause = len(self.out)
        elif char == "(" and self.starts("((") and not self.clause_text():
            self.emit(":", _matching(self.text, self.at) - self.at)
        else:
            self.emit(char)
            if char in ";|&(":
                self.clause = len(self.out)

    def gap(self, after: int) -> int:
        return len(self.text[self.at + after :]) - len(self.text[self.at + after :].lstrip(" \t"))

    def ansi_end(self) -> int:
        at = self.at + 2
        while at < len(self.text) and self.text[at] != "'":
            at += 2 if self.text[at] == "\\" else 1
        return at if at < len(self.text) else 0

    def here(self, word: re.Match[str]) -> None:
        key = f"__here_{len(self.docs)}__"
        self.docs[key] = _unquote(word[0])
        self.emit(f" < {key} ", word.end() - self.at)

    def document(self, found: re.Match[str]) -> None:
        key = f"__doc_{len(self.docs)}__"
        self.docs[key] = ""
        self.waiting.append((key, found[3]))
        self.emit(f" < {key} ", found.end() - self.at)

    def bodies_of_documents(self) -> None:
        for key, delimiter in self.waiting:
            lines = []
            while self.at < len(self.text):
                end = self.text.find("\n", self.at)
                end = len(self.text) if end < 0 else end
                line, self.at = self.text[self.at : end], end + 1
                if line.strip() == delimiter:
                    break
                lines.append(line)
            self.docs[key] = "\n".join(lines)
        self.waiting = []


def scan(text: str) -> Scanned:
    """`$'..'` decoded, `>&word` read as a file redirection, each `$(..)` and backtick replaced by a placeholder word."""
    return _Text(text).run()


def _alternatives(inner: str) -> list[str]:
    """The items of a brace body: `a,b` or a range `1..3`, `a..c`; nothing when it is neither."""
    depth, items, last = 0, [], 0
    for at, char in enumerate(inner):
        depth += (char == "{") - (char == "}")
        if char == "," and not depth:
            items.append(inner[last:at])
            last = at + 1
    items.append(inner[last:])
    if len(items) > 1:
        return items
    if (ranged := _RANGE.fullmatch(inner)) is None:
        return []
    if ranged[1] is None:
        low, high = sorted((ord(ranged[3]), ord(ranged[4])))
        return [chr(c) for c in range(low, high + 1)]
    low, high = sorted((int(ranged[1]), int(ranged[2])))
    cut = min(high, low + _LIMIT)
    # What is left out of a long range is read as unknown text, never as nothing.
    return [*map(str, range(low, cut + 1)), *([SUBST] if cut < high else [])]


def braces(word: str) -> list[str]:
    """Brace expansion of one word: `.{cursor,x}/mcp.json` gives both paths (the word itself when it has no list)."""
    for start, char in enumerate(word):
        if char != "{" or word[start - 1 : start] == "$":
            continue
        depth = 0
        for end in range(start, len(word)):
            depth += (word[end] == "{") - (word[end] == "}")
            if not depth:
                break
        if depth or not (items := _alternatives(word[start + 1 : end])):
            continue
        found = [piece for item in items for piece in braces(word[:start] + item + word[end + 1 :])]
        return [*found[:_LIMIT], *([SUBST] if len(found) > _LIMIT else [])]
    return [word]
