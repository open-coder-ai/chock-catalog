"""Shell text as commands: one linear pass, quotes and escapes removed from words, nesting and pipes recorded.

A command is the words between ; & && || | newline, a standalone { or }, an unmatched ) (case
patterns, function bodies) and the brackets of $( ), <( ), >( ), `...` and ( ). Each keeps the
offset where it starts, the command it was substituted into (its parent: `bash <(curl ...)`,
`sh -c "$(curl ...)"`, `iex (irm ...)`) and the command piped into it; a pipe after a group or
subshell is fed by the group's last command. `$((` is read as `$(` then `(`, as bash falls back to
when the text is not arithmetic. A word is what the shell would pass: 'ch'mod, ch""mod and ch\\mod
are all chmod. Nesting deeper than DEPTH is not followed; the caller reports it as too deep.
"""

from __future__ import annotations

from typing import NamedTuple

DEPTH = 64
ENDERS = frozenset("\n;&|")
OPENERS = frozenset({"$(", "<(", ">("})
BOUNDARY = frozenset(" \t\r\n;&|)")
SUBSHELL = "S"


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
        self.at = 0
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
        cur = self.cur
        if cur.words:
            self.out.append(Cmd(cur.id, tuple(cur.words), cur.start, cur.parent, cur.piped_from, tuple(cur.offsets)))
        piped = -1
        if pipe:
            piped = cur.id if cur.words else (self.out[-1].id if self.out else -1)
        self.cur = self.new(cur.parent, self.at + 1)
        self.cur.piped_from = piped

    def push(self, closer: str, quote: str, parent: int) -> None:
        if len(self.stack) >= DEPTH:
            self.too_deep = True
            return
        if closer != SUBSHELL:
            self.add("\x00")
        self.stack.append((self.cur, closer, quote))
        self.cur = self.new(parent, self.at + 1)

    def pop(self) -> str:
        self.end_cmd(pipe=False)
        outer, closer, quote = self.stack.pop()
        self.cur = outer
        if closer == SUBSHELL:
            self.end_cmd(pipe=False)
        return quote

    def closes(self, ch: str) -> bool:
        return bool(self.stack) and self.stack[-1][1] in ((ch, SUBSHELL) if ch == ")" else (ch,))

    def run(self) -> list[Cmd]:
        quote = ""
        while self.at < len(self.text):
            ch = self.text[self.at]
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

    def quoted(self, ch: str, quote: str) -> tuple[str, int]:
        nxt = self.text[self.at + 1 : self.at + 2]
        if ch == quote:
            return "", 1
        if quote == '"' and ch == "\\" and nxt and nxt in '"$`\\\n':
            if nxt != "\n":
                self.add(nxt)
            return quote, 2
        if quote == '"' and ch == "$" and nxt == "(":
            self.push(")", quote, self.cur.id)
            return "", 2
        if quote == '"' and ch == "`":
            self.push("`", quote, self.cur.id)
            return "", 1
        self.add(ch)
        return quote, 1

    def plain(self, ch: str) -> tuple[str, int] | int:
        text, at = self.text, self.at
        pair = text[at : at + 2]
        if ch == "\\":
            if pair != "\\\n":
                self.add(text[at + 1 : at + 2])
            return 2
        if ch in "'\"":
            self.add("")
            return ch, 1
        if ch == "#" and self.cur.word is None:
            end = text.find("\n", at)
            return (len(text) if end < 0 else end) - at
        if pair in OPENERS or ch in "`()":
            return self.bracket(ch, pair)
        return self.separator(ch, pair)

    def bracket(self, ch: str, pair: str) -> tuple[str, int] | int:
        if pair in OPENERS:
            self.push(")", "", self.cur.id)
            return 2
        if ch == "`":
            if self.closes("`"):
                return self.pop(), 1
            self.push("`", "", self.cur.id)
            return 1
        if ch == "(":
            return self.paren()
        if self.closes(")"):
            return self.pop(), 1
        self.end_cmd(pipe=False)
        return 1

    def paren(self) -> int:
        """`name=(` opens a word list; `(` after words, a nested command; else a subshell."""
        if self.cur.word and self.cur.word[-1] == "=":
            return self.array()
        self.end_word()
        if self.cur.words:
            self.push(")", "", self.cur.id)
        else:
            self.push(SUBSHELL, "", -1)
        return 1

    def array(self) -> int:
        """`name=( ... )` is a list of words, not a command: kept as text up to its closing bracket."""
        close = self.text.find(")", self.at)
        stop = len(self.text) if close < 0 else close + 1
        for part in self.text[self.at : stop]:
            self.add(part)
        return stop - self.at

    def separator(self, ch: str, pair: str) -> int:
        if ch == "&" and (pair == "&>" or (self.cur.word and self.cur.word[-1] in "<>")):
            self.add(ch)
            return 1
        if ch in ENDERS:
            self.end_cmd(pipe=ch == "|" and pair != "||")
            return 2 if pair in ("&&", "||", "|&") else 1
        if ch in " \t\r":
            self.end_word()
            return 1
        if ch in "{}" and self.cur.word is None and (pair[1:] == "" or pair[1:] in BOUNDARY):
            self.end_cmd(pipe=False)
            return 1
        self.add(ch)
        return 1


def commands(text: str) -> tuple[list[Cmd], bool]:
    """Every command in `text` (inner and upstream ones before the commands using them), and whether nesting ran past DEPTH."""
    lexer = Lexer(text)
    return lexer.run(), lexer.too_deep
