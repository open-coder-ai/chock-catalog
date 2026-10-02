"""Which heredocs a RUN, COPY or ADD line opens, read the way BuildKit reads them (moby/buildkit 0.33 parser).

BuildKit splits the instruction line into shell words with quotes and escapes kept raw and `<<`
plus any blanks after it glued to the next word, then takes a word matching
`^(\\d*)<<(-?)\\s*([^<]*)$` as an opener whose name is the rest, unquoted, when that is one word.
A line it cannot lex (an open quote, a bad ${...}) opens no heredoc, as there.
"""

from __future__ import annotations

import re

OPENER = re.compile(r"(\d*)<<(-?)[\t\n\f\r ]*([^<]*)")
SPECIAL = frozenset("@*#?-$!0")
MODIFIERS = frozenset("+-?#%")


class LexError(ValueError):
    """BuildKit's lexer would refuse this text."""


class TooDeepError(RuntimeError):
    """${...} nests deeper than DEPTH: the line is reported as too deep to judge, not guessed at."""


DEPTH = 64


class _Words:
    def __init__(self) -> None:
        self.buf: list[str] = []
        self.words: list[str] = []
        self.whole: list[str] = []
        self.in_word = False

    def char(self, ch: str) -> None:
        self.whole.append(ch)
        if ch.isspace():
            if self.in_word and "".join(self.buf):
                self.words.append("".join(self.buf))
                self.buf, self.in_word = [], False
        else:
            self.buf.append(ch)
            self.in_word = True

    def raw(self, text: str) -> None:
        self.whole.append(text)
        self.buf.append(text)
        self.in_word = True

    def done(self) -> list[str]:
        if "".join(self.buf):
            self.words.append("".join(self.buf))
        return self.words


class Lex:
    """BuildKit's shell-word lexer, reduced to what heredoc detection needs (no variable is ever set)."""

    def __init__(self, text: str, *, raw: bool) -> None:
        self.text, self.at, self.raw = text, 0, raw
        self.open: list[_Words] = []

    def peek(self) -> str:
        return self.text[self.at] if self.at < len(self.text) else ""

    def take(self) -> str:
        ch = self.peek()
        self.at += 1
        return ch

    def words(self, stop: str = "") -> list[str]:
        return self.lex(stop).done()

    def until(self, stop: str) -> str:
        """The processed text up to `stop` (BuildKit's processStopOn result), for a ${...} word.

        BuildKit's nested call resets the word buffer it shares with the enclosing word, so the
        characters that word had gathered (a `<<` before the ${...} too) are dropped, as here.
        """
        outer = self.open[-1]
        text = "".join(self.lex(stop).whole)
        outer.buf.clear()
        return text

    def lex(self, stop: str) -> _Words:
        if len(self.open) >= DEPTH:
            raise TooDeepError(stop)
        words = _Words()
        self.open.append(words)
        try:
            return self._lex(words, stop)
        finally:
            self.open.pop()

    def _lex(self, words: _Words, stop: str) -> _Words:
        handlers = {"$": self.dollar, "<": self.angle, "'": self.single, '"': self.double}
        while self.peek():
            ch = self.peek()
            if stop and ch == stop:
                self.at += 1
                return words
            if ch in handlers:
                text = handlers[ch]()
                for part in text if ch == "$" else [text]:
                    (words.char if ch == "$" else words.raw)(part)
                continue
            self.at += 1
            if ch == "\\":
                if self.raw:
                    words.raw(ch)
                if not self.peek():
                    break
                words.raw(self.take())
            else:
                words.char(ch)
        if stop:
            raise LexError(stop)
        return words

    def angle(self) -> str:
        self.at += 1
        if self.peek() != "<":
            return "<"
        self.at += 1
        blanks = ""
        while self.peek() and self.peek() in " \t":
            blanks += self.take()
        return "<<" + blanks

    def single(self) -> str:
        quote = self.take()
        out = [quote] if self.raw else []
        while (ch := self.take()) != "'":
            if not ch:
                raise LexError(quote)
            out.append(ch)
        return "".join([*out, ch] if self.raw else out)

    def double(self) -> str:
        quote = self.take()
        out = [quote] if self.raw else []
        while True:
            ch = self.peek()
            if not ch:
                raise LexError('"')
            if ch == '"':
                self.at += 1
                return "".join([*out, ch] if self.raw else out)
            if ch == "$":
                out.append(self.dollar())
                continue
            self.at += 1
            if ch == "\\" and self.peek() in ('"', "$", "\\"):
                out.append(ch if self.raw else "")
                ch = self.take()
            out.append(ch)

    def name(self) -> str:
        ch = self.peek()
        if ch.isdigit():
            start = self.at
            while self.peek().isdigit():
                self.at += 1
            return self.text[start : self.at]
        if ch and ch in SPECIAL:
            return self.take()
        start = self.at
        while self.peek() and (self.peek().isalnum() or self.peek() == "_"):
            self.at += 1
        return self.text[start : self.at]

    def dollar(self) -> str:
        self.at += 1
        if self.peek() != "{":
            name = self.name()
            return "$" + name
        self.at += 1
        if not self.peek() or self.peek() in "{}:":
            raise LexError("${")
        name = self.name()
        op = self.take()
        if not op:
            raise LexError("${")
        if op == "}":
            return "${" + name + "}"
        if op == ":":
            op += self.take()
        if op in MODIFIERS or (op.startswith(":") and op not in (":#", ":%")):
            return "${" + name + op + self.until("}") + "}"
        if op == "/":
            pattern = self.until("/")
            return "${" + name + "/" + pattern + "/" + self.until("}") + "}"
        raise LexError(op)


def openers(line: str) -> list[tuple[bool, str]]:
    """(strip leading tabs, terminator) for each heredoc the line opens, in order."""
    if "<<" not in line:
        return []
    try:
        return [(chomp, name) for chomp, name in map(_opener, Lex(line, raw=True).words()) if name]
    except LexError:
        return []


def _opener(word: str) -> tuple[bool, str]:
    """(strip tabs, name) when `word` opens a heredoc, else (False, "")."""
    match = OPENER.fullmatch(word)
    names = Lex(match.group(3), raw=False).words() if match and match.group(3) else []
    return (match.group(2) == "-", names[0]) if match and len(names) == 1 else (False, "")
