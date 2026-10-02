"""Read a command line into pipelines of stages, keeping what chock_shellparse drops: pipes and substitutions."""

import re
from dataclasses import dataclass, field

_SEPS = ("|&", "||", "&&", ";;", "|", ";", "&")
_REDIR = re.compile(r"[0-9]*(?:<<<|<<-|<<|<>|>>|>\||>&|<&|>|<)|&>>?")
_STOP = frozenset(" \t\r\n|&;()<>")
_OPS = frozenset("\n|&;()")
_ANSI = re.compile(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", re.DOTALL)
_ANSI_NAMED = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v"}


@dataclass
class Sub:
    """A command substitution `$(...)` or backtick, or a process substitution `<(...)` / `>(...)`."""

    kind: str
    body: str


@dataclass
class Word:
    """One shell word: literal text and substitutions, in order; `source` is the word as written."""

    parts: list[str | Sub] = field(default_factory=list)
    source: str = ""
    quoted: bool = False

    def subs(self) -> list[Sub]:
        return [part for part in self.parts if isinstance(part, Sub)]


@dataclass
class Tok:
    kind: str
    value: str = ""
    word: Word | None = None
    body: str | None = None


@dataclass
class Stage:
    """One element of a pipeline: a simple command, or a ( ) / { } group of pipelines."""

    words: list[Word] = field(default_factory=list)
    redirs: list[tuple[str, Word]] = field(default_factory=list)
    heredocs: list[str] = field(default_factory=list)
    group: list[list["Stage"]] | None = None

    def subs(self) -> list[Sub]:
        found = [sub for word in self.words for sub in word.subs()]
        return found + [sub for _, word in self.redirs for sub in word.subs()]


class _Lexer:
    def __init__(self, text: str) -> None:
        self.text, self.pos, self.broken = text, 0, False
        self.pending: list[tuple[Tok, bool]] = []

    def at(self, prefix: str) -> bool:
        return self.text.startswith(prefix, self.pos)

    def token(self) -> Tok | None:
        """The next token, or None for blanks and comments."""
        char = self.text[self.pos]
        if char in " \t\r" or self.at("\\\n"):
            self.pos += 2 if char == "\\" else 1
            return None
        if char == "#":
            end = self.text.find("\n", self.pos)
            self.pos = len(self.text) if end < 0 else end
            return None
        redir = _REDIR.match(self.text, self.pos)
        if redir is not None and not (self.at("<(") or self.at(">(")):
            self.pos = redir.end()
            return Tok("redir", redir.group().lstrip("0123456789"))
        if char in _OPS and not (self.at("<(") or self.at(">(")):
            return self._operator(char)
        return self._word_tok()

    def _operator(self, char: str) -> Tok:
        sep = next((sep for sep in _SEPS if self.at(sep)), "")
        self.pos += len(sep) or 1
        if char == "\n":
            self._heredocs()
        return Tok("sep", sep or char) if sep or char == "\n" else Tok("open" if char == "(" else "close")

    def _word_tok(self) -> Tok:
        word = self.word()
        if word.source in ("{", "}"):
            return Tok("open" if word.source == "{" else "close")
        return Tok("word", word=word)

    def word(self) -> Word:
        """Read one word; an unclosed quote or substitution runs to the end of the text and marks it broken."""
        start, word = self.pos, Word()
        while self.pos < len(self.text) and (self.text[self.pos] not in _STOP or self.at("<(") or self.at(">(")):
            if self.at("<(") or self.at(">("):
                self.pos += 2
                word.parts.append(Sub(self.text[self.pos - 2 : self.pos], self._until_close()))
            else:
                self._piece(word)
        word.source = self.text[start : self.pos]
        return word

    def _piece(self, word: Word) -> None:
        char = self.text[self.pos]
        if self.at("$'"):
            word.quoted = True
            self.pos += 2
            word.parts.append(_ANSI.sub(_ansi, self._single(escapes=True)))
        elif char == "'":
            word.quoted = True
            self.pos += 1
            word.parts.append(self._single(escapes=False))
        elif char == '"':
            word.quoted = True
            self.pos += 1
            self._double(word)
        elif char == "\\":
            word.parts.append(self.text[self.pos + 1 : self.pos + 2])
            self.broken |= self.pos + 1 >= len(self.text)
            self.pos += 2
        elif not self._substitution(word):
            word.parts.append(char)
            self.pos += 1

    def _substitution(self, word: Word) -> bool:
        if self.at("$((") or not (self.at("$(") or self.at("`")):
            return False
        if self.at("`"):
            self.pos += 1
            word.parts.append(Sub("`", self._backtick()))
        else:
            self.pos += 2
            word.parts.append(Sub("$(", self._until_close()))
        return True

    def _single(self, *, escapes: bool) -> str:
        pattern = re.compile(r"(?:[^'\\]|\\.)*'" if escapes else r"[^']*'", re.DOTALL)
        found = pattern.match(self.text, self.pos)
        if found is None:
            self.broken, body, self.pos = True, self.text[self.pos :], len(self.text)
            return body
        self.pos = found.end()
        return found.group()[:-1]

    def _double(self, word: Word) -> None:
        while self.pos < len(self.text) and self.text[self.pos] != '"':
            if self.at("\\") and self.text[self.pos + 1 : self.pos + 2] in ('"', "\\", "$", "`", "\n"):
                word.parts.append(self.text[self.pos + 1].strip("\n"))
                self.pos += 2
            elif not self._substitution(word):
                word.parts.append(self.text[self.pos])
                self.pos += 1
        self.broken |= self.pos >= len(self.text)
        self.pos += 1

    def _backtick(self) -> str:
        found = re.compile(r"(?:[^`\\]|\\.)*`", re.DOTALL).match(self.text, self.pos)
        if found is None:
            self.broken, body, self.pos = True, self.text[self.pos :], len(self.text)
            return body
        self.pos = found.end()
        return re.sub(r"\\([`\\$])", r"\1", found.group()[:-1])

    def _until_close(self) -> str:
        """The body of `$(` or `<(`, up to its matching `)`: quotes and nested substitutions are skipped whole."""
        start, depth = self.pos, 0
        while self.pos < len(self.text):
            tok = self.token()
            if tok is not None and tok.kind in ("open", "close"):
                depth += 1 if tok.kind == "open" else -1
                if depth < 0:
                    return self.text[start : self.pos - 1]
        self.broken = True
        return self.text[start:]

    def _heredocs(self) -> None:
        while self.pending:
            tok, strip = self.pending.pop(0)
            delim = "".join(p for p in tok.word.parts if isinstance(p, str)) if tok.word else ""
            lines, body = self.text[self.pos :].split("\n"), []
            for line in lines:
                self.pos += len(line) + 1
                if (line.lstrip("\t") if strip else line).rstrip("\r") == delim:
                    break
                body.append(line)
            tok.body = "\n".join(body)


def _ansi(match: re.Match[str]) -> str:
    code = match.group(1)
    if code[0] == "x" and len(code) > 1:
        return chr(int(code[1:], 16))
    if code.isdigit():
        return chr(int(code, 8))
    return _ANSI_NAMED.get(code, code)


def _tokens(text: str) -> tuple[list[Tok], bool]:
    lexer = _Lexer(text)
    out: list[Tok] = []
    heredoc = None
    while lexer.pos < len(text):
        tok = lexer.token()
        if tok is None:
            continue
        if heredoc is not None and tok.kind == "word":
            lexer.pending.append((tok, heredoc == "<<-"))
        heredoc = tok.value if tok.kind == "redir" and tok.value in ("<<", "<<-") else None
        out.append(tok)
    return out, lexer.broken


def _parse(toks: list[Tok], at: int) -> tuple[list[list[Stage]], int]:
    pipelines: list[list[Stage]] = []
    stages, cur, redir = [], Stage(), ""
    while at < len(toks):
        tok, at = toks[at], at + 1
        if tok.kind == "close":
            break
        if tok.kind == "open":
            cur.group, at = _parse(toks, at)
        elif tok.kind == "redir":
            redir = tok.value
        elif tok.kind == "word" and redir:
            if redir in ("<<", "<<-"):
                cur.heredocs.append(tok.body or "")
            else:
                cur.redirs.append((redir, tok.word or Word()))
            redir = ""
        elif tok.kind == "word":
            cur.words.append(tok.word or Word())
        else:
            stages.append(cur)
            cur = Stage()
            if tok.value not in ("|", "|&"):
                pipelines.append(stages)
                stages = []
    pipelines.append([*stages, cur])
    return pipelines, at


def lex(text: str) -> tuple[list[list[Stage]], bool]:
    """(pipelines, broken): every pipeline is a list of stages joined by | or |&; broken means quoting never closed."""
    toks, broken = _tokens(text)
    pipelines, _ = _parse(toks, 0)
    return [[s for s in p if s.words or s.redirs or s.group] for p in pipelines if p], broken
