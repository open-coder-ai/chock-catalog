"""Shell text as commands: one linear pass, quotes and escapes removed from words, nesting and pipes recorded.

A command is the words between ; & && || | newline and the brackets of $( ), <( ), >( ), `...`
and ( ). Each keeps the offset where it starts, the command it was substituted into (its parent:
`bash <(curl ...)`, `sh -c "$(curl ...)"`, `iex (irm ...)`) and the command piped into it. A word is
what the shell would pass: 'ch'mod, ch""mod and ch\\mod are all chmod. Nesting deeper than DEPTH
is not followed; the caller reports such text as too deep to judge.
"""

from __future__ import annotations

import posixpath
import re
from typing import NamedTuple

DEPTH = 64
ENDERS = frozenset("\n;&|")
OPENERS = {"$(": ")", "<(": ")", ">(": ")"}
ASSIGNMENT = re.compile(r"[A-Za-z_]\w*\+?=")
LEADERS = frozenset({"{", "}", "!", "(", "then", "do", "else", "if", "elif", "while", "until", "time", "-p"})
#: Wrappers that run the rest of the line as a command, and their options that take a separate value.
WRAPPERS = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "nohup": frozenset(),
    "exec": frozenset({"-a"}),
    "command": frozenset(),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "xargs": frozenset({"-n", "-I", "-i", "-P", "-L", "-l", "-s", "-d", "-E", "-e", "-a", "--max-args", "--max-procs"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
}


class Cmd(NamedTuple):
    id: int
    words: tuple[str, ...]
    start: int
    parent: int
    piped_from: int
    offsets: tuple[int, ...] = ()


class _Builder:
    def __init__(self, ident: int, parent: int, start: int) -> None:
        self.id, self.parent, self.start = ident, parent, start
        self.words: list[str] = []
        self.offsets: list[int] = []
        self.word: list[str] | None = None
        self.piped_from = -1


class Lexer:
    def __init__(self, text: str) -> None:
        self.text = text
        self.out: list[Cmd] = []
        self.next_id = 0
        self.too_deep = False
        self.stack: list[tuple[_Builder, str, str]] = []
        self.cur = self.new(-1, 0)

    def new(self, parent: int, start: int) -> _Builder:
        self.next_id += 1
        return _Builder(self.next_id, parent, start)

    def add(self, ch: str) -> None:
        if self.cur.word is None:
            self.cur.word = []
            self.cur.offsets.append(self.at)
            if not self.cur.words:
                self.cur.start = self.at
        self.cur.word.append(ch)

    def end_word(self) -> None:
        if self.cur.word is not None:
            self.cur.words.append("".join(self.cur.word))
            self.cur.word = None

    def end_cmd(self, *, pipe: bool) -> None:
        self.end_word()
        if self.cur.words:
            self.out.append(
                Cmd(
                    self.cur.id,
                    tuple(self.cur.words),
                    self.cur.start,
                    self.cur.parent,
                    self.cur.piped_from,
                    tuple(self.cur.offsets),
                )
            )
        piped = self.cur.id if pipe and self.cur.words else -1
        self.cur = self.new(self.cur.parent, self.at + 1)
        self.cur.piped_from = piped

    def push(self, closer: str, quote: str, parent: int) -> None:
        if len(self.stack) >= DEPTH:
            self.too_deep = True
            self.add("\x00")
            return
        self.add("\x00")
        self.stack.append((self.cur, closer, quote))
        self.cur = self.new(parent, self.at + 1)

    def pop(self) -> str:
        self.end_cmd(pipe=False)
        outer, _, quote = self.stack.pop()
        self.cur = outer
        return quote

    def run(self) -> list[Cmd]:
        text, quote, self.at = self.text, "", 0
        while self.at < len(text):
            ch = text[self.at]
            step = self.quoted(ch, quote) if quote else self.plain(ch)
            if isinstance(step, tuple):
                quote, skip = step
            else:
                skip = step
            self.at += skip
        while self.stack:
            self.pop()
        self.end_cmd(pipe=False)
        return self.out

    def closes(self, ch: str) -> bool:
        return bool(self.stack) and self.stack[-1][1] == ch

    def quoted(self, ch: str, quote: str) -> tuple[str, int] | int:
        nxt = self.text[self.at + 1 : self.at + 2]
        if ch == quote:
            return "", 1
        if quote == '"' and ch == "\\" and nxt and nxt in '"$`\\\n':
            if nxt != "\n":
                self.add(nxt)
            return quote, 2
        if quote == '"' and ch == "$" and nxt == "(" and self.text[self.at + 2 : self.at + 3] != "(":
            self.push(")", quote, self.cur.id)
            return "", 2
        if quote == '"' and ch == "`":
            self.push("`", quote, self.cur.id)
            return "", 1
        self.add(ch)
        return quote, 1

    def plain(self, ch: str) -> tuple[str, int] | int:  # noqa: C901, PLR0911, PLR0912
        text, at = self.text, self.at
        pair = text[at : at + 2]
        if ch == "\\":
            if pair == "\\\n":
                return 2
            self.add(text[at + 1 : at + 2])
            return 2
        if ch in "'\"":
            self.add("")
            return ch, 1
        if ch == "#" and self.cur.word is None:
            end = text.find("\n", at)
            return (len(text) if end < 0 else end) - at
        if text.startswith("$((", at):
            end = text.find("))", at)
            stop = len(text) if end < 0 else end + 2
            for part in text[at:stop]:
                self.add(part)
            return stop - at
        if pair in OPENERS:
            self.push(")", "", self.cur.id)
            return 2
        if ch == "`":
            if self.closes("`"):
                return self.pop(), 1
            self.push("`", "", self.cur.id)
            return 1
        if ch == "(":
            self.end_word()
            self.push(")", "", self.cur.id if self.cur.words else -1)
            return 1
        if ch == ")" and self.closes(")"):
            return self.pop(), 1
        if ch == "&" and (pair == "&>" or (self.cur.word and self.cur.word[-1] in "<>")):
            self.add(ch)
            return 1
        if ch in ENDERS:
            pipe = ch == "|" and pair != "||"
            self.end_cmd(pipe=pipe)
            return 2 if pair in ("&&", "||", "|&") else 1
        if ch in " \t\r":
            self.end_word()
            return 1
        self.add(ch)
        return 1


def commands(text: str) -> tuple[list[Cmd], bool]:
    """Every command in `text` (outermost last within its line), and whether nesting ran past DEPTH."""
    lexer = Lexer(text)
    return lexer.run(), lexer.too_deep


def resolve(words: tuple[str, ...]) -> tuple[int, frozenset[str]]:
    """Index of the program word after keywords, assignments and wrappers (-1: none), and the wrappers seen."""
    seen: set[str] = set()
    at = 0
    while at < len(words):
        word = words[at]
        base = posixpath.basename(word)
        if word in LEADERS or ASSIGNMENT.match(word):
            at += 1
            continue
        if base not in WRAPPERS:
            return at, frozenset(seen)
        seen.add(base)
        at += 1
        while at < len(words) and words[at].startswith("-") and words[at] != "-":
            option = words[at]
            at += 2 if option in WRAPPERS[base] else 1
            if option == "--":
                break
        if base == "timeout" and at < len(words):
            at += 1
    return -1, frozenset(seen)
