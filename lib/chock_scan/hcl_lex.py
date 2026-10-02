"""HCL2 native-syntax lexer for chock_scan.hcl: tokens with offsets (Lines maps one to its line), strings decoded or COMPUTED.

Comments (`#`, `//`, `/* */`) are dropped; quoted strings and heredocs are one token each, and an
interpolation or directive inside one (`${...}`, `%{...}`) is lexed to find its end, then marks the
string COMPUTED. Anything the scanner cannot read raises HclError; nothing is skipped silently.
"""

from __future__ import annotations

import bisect
import re
from typing import NamedTuple

MAX_CHARS = 1 << 20
MAX_DEPTH = 64
MAX_DIGITS = 4000
MAX_SCALAR = 0x10FFFF
SURROGATES = range(0xD800, 0xE000)
BOM = "\ufeff"
#: Go's unicode.IsSpace set, which HCL trims a heredoc's closing-marker line with.
WS = " \t\n\v\f\r\x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
INDENT = WS.replace("\n", "")
#: The common tokens in one alternation of simple, unnested classes (linear; no backtracking blowup).
#: An ASCII identifier running into a non-ASCII character is re-read by the Unicode-aware loop.
SIMPLE = re.compile(
    r"(?P<NL>\r?\n)|(?P<NUMBER>[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)|(?P<IDENT>[A-Za-z_][A-Za-z0-9_-]*)"
    r"|(?P<PUNCT>\.\.\.|[=!<>]=|&&|\|\||=>|[-+*/%<>!?:.,=()\[\]{}~])"
)
SPACES = re.compile(r"[ \t]+")
SKIPPABLE = frozenset(" \t#/\r")
ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


class HclError(ValueError):
    """The text is not HCL this scanner can read: a security caller refuses it, never reads it as empty."""

    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


class Computed:
    """A value the scanner does not resolve (a reference, call, operator or template): callers fail closed."""

    def __repr__(self) -> str:
        return "COMPUTED"


COMPUTED = Computed()


class Token(NamedTuple):
    kind: str  # IDENT NUMBER STRING HEREDOC PUNCT NL EOF
    text: str
    start: int
    end: int
    value: object = None  # STRING and HEREDOC: the decoded text, or COMPUTED


def tokens(text: str) -> list[Token]:
    """Every token of `text` (a leading BOM already removed), ending with EOF; HclError if unreadable or past the caps."""
    if len(text) > MAX_CHARS:
        msg = f"larger than {MAX_CHARS} characters"
        raise HclError(msg, 1)
    return _Lexer(text).run()


class Lines:
    """The 1-based line of an offset into `text` (lines end at "\n")."""

    def __init__(self, text: str) -> None:
        self.newlines = [m.start() for m in re.finditer("\n", text)]

    def __call__(self, pos: int) -> int:
        return bisect.bisect_left(self.newlines, pos) + 1


class _Lexer:
    def __init__(self, src: str) -> None:
        self.src = src
        self.line = Lines(src)
        self.depth = 0

    def fail(self, message: str, pos: int) -> HclError:
        return HclError(message, self.line(pos))

    def run(self) -> list[Token]:
        out: list[Token] = []
        pos = 0
        while True:
            tok = self.next(pos)
            out.append(tok)
            if tok.kind == "EOF":
                return out
            pos = tok.end

    def next(self, pos: int) -> Token:
        src = self.src
        pos = self.skip(pos)
        if pos >= len(src):
            return Token("EOF", "", pos, pos)
        ch = src[pos]
        if ch == '"':
            return self.quoted(pos)
        if ch == "<" and src.startswith("<<", pos):
            return self.heredoc(pos)
        match = SIMPLE.match(src, pos)
        if match and not (match.lastgroup == "IDENT" and match.end() < len(src) and src[match.end()] > "\x7f"):
            if match.lastgroup == "NUMBER" and match.end() - pos > MAX_DIGITS:
                msg = "number too long"
                raise self.fail(msg, pos)
            return Token(str(match.lastgroup), match.group(), pos, match.end())
        if ch == "_" or ch.isidentifier():
            end = pos + 1
            while end < len(src) and (src[end] == "-" or ("a" + src[end]).isidentifier()):
                end += 1
            return Token("IDENT", src[pos:end], pos, end)
        msg = f"unexpected character {ch!r}"
        raise self.fail(msg, pos)

    def skip(self, pos: int) -> int:
        """Past spaces, tabs and comments; a line comment stops before its newline, which stays a token."""
        src = self.src
        while pos < len(src):
            ch = src[pos]
            if ch not in SKIPPABLE:
                break
            if ch in " \t":
                pos = SPACES.match(src, pos).end()
            elif ch == "#" or src.startswith("//", pos):
                end = src.find("\n", pos)
                pos = len(src) if end == -1 else end - (src[end - 1] == "\r")
            elif src.startswith("/*", pos):
                end = src.find("*/", pos + 2)
                if end == -1:
                    msg = "unterminated /* comment"
                    raise self.fail(msg, pos)
                pos = end + 2
            elif ch == "\r" and not src.startswith("\r\n", pos):
                msg = "carriage return not followed by a newline"
                raise self.fail(msg, pos)
            else:
                break
        return pos

    def quoted(self, start: int) -> Token:
        src = self.src
        parts: list[str] = []
        computed = False
        pos = start + 1
        while True:
            if pos >= len(src) or src[pos] == "\n":
                msg = "unterminated string"
                raise self.fail(msg, start)
            ch = src[pos]
            if ch == '"':
                value = COMPUTED if computed else "".join(parts)
                return Token("STRING", src[start : pos + 1], start, pos + 1, value)
            if ch == "\\":
                text, pos = self.escape(pos)
                parts.append(text)
                continue
            text, pos, interpolated = self.template_char(pos)
            computed = computed or interpolated
            parts.append(text)

    def escape(self, pos: int) -> tuple[str, int]:
        src = self.src
        code = src[pos + 1 : pos + 2]
        if code in ESCAPES:
            return ESCAPES[code], pos + 2
        width = {"u": 4, "U": 8}.get(code, 0)
        digits = src[pos + 2 : pos + 2 + width]
        if width and len(digits) == width and all(c in "0123456789abcdefABCDEF" for c in digits):
            point = int(digits, 16)
            if point <= MAX_SCALAR and point not in SURROGATES:
                return chr(point), pos + 2 + width
        msg = f"invalid escape {src[pos : pos + 2]!r}"
        raise self.fail(msg, pos)

    def template_char(self, pos: int) -> tuple[str, int, bool]:
        """One literal character, an escaped `$${`/`%%{`, or a whole `${...}`/`%{...}` (returned as '')."""
        src = self.src
        ch = src[pos]
        if ch in "$%" and src.startswith(ch + ch + "{", pos):
            return ch + "{", pos + 3, False
        if ch in "$%" and src.startswith("{", pos + 1):
            return "", self.interpolation(pos + 2), True
        return ch, pos + 1, False

    def interpolation(self, pos: int) -> int:
        """The offset just past the `}` closing an interpolation whose body starts at `pos`."""
        self.depth += 1
        if self.depth > MAX_DEPTH:
            msg = f"templates nested deeper than {MAX_DEPTH}"
            raise self.fail(msg, pos)
        opened = pos
        braces = 0
        while True:
            tok = self.next(pos)
            if tok.kind == "EOF":
                msg = "unterminated ${ or %{ in a string"
                raise self.fail(msg, opened)
            if tok.text == "{" and tok.kind == "PUNCT":
                braces += 1
            elif tok.text == "}" and tok.kind == "PUNCT":
                if not braces:
                    self.depth -= 1
                    return tok.end
                braces -= 1
            pos = tok.end

    def heredoc(self, start: int) -> Token:
        src = self.src
        pos = start + 2 + src.startswith("-", start + 2)
        mark = pos
        while pos < len(src) and (src[pos] == "-" or ("a" + src[pos]).isidentifier()):
            pos += 1
        marker = src[mark:pos]
        newline = 1 if src.startswith("\n", pos) else 2 if src.startswith("\r\n", pos) else 0
        if not marker or not newline or not (marker[0] == "_" or marker[0].isidentifier()):
            msg = "<< must open a heredoc: <<MARKER or <<-MARKER, then a newline"
            raise self.fail(msg, start)
        pos += newline
        parts: list[str] = []
        computed = False
        at_line_start = True
        while True:
            if pos >= len(src):
                msg = f"heredoc {marker} is never closed"
                raise self.fail(msg, start)
            if at_line_start:
                eol = src.find("\n", pos)
                eol = len(src) if eol == -1 else eol
                if src[pos:eol].strip(WS) == marker:
                    break
                at_line_start = False
            if src[pos] == "\n":
                parts.append("\n")
                pos += 1
                at_line_start = True
                continue
            text, pos, interpolated = self.template_char(pos)
            computed = computed or interpolated
            parts.append(text)
        value = COMPUTED if computed else _flush("".join(parts)) if src[start + 2] == "-" else "".join(parts)
        return Token("HEREDOC", src[start:eol], start, eol, value)


def _flush(body: str) -> str:
    """A `<<-` heredoc as HCL flushes it: the fewest leading whitespace characters on a non-blank line go from each."""
    lines = body.split("\n")
    leads = [len(ln) - len(ln.lstrip(INDENT)) for ln in lines]
    cut = min((n for n, ln in zip(leads, lines, strict=True) if ln.strip(INDENT)), default=0)
    return "\n".join(ln[cut:] if ln.strip(INDENT) else ln for ln in lines)


def template(text: str) -> object:
    """A JSON-syntax string read as a template: its literal text (`$${` unescaped), or COMPUTED if it interpolates."""
    lexer = _Lexer(text)
    parts: list[str] = []
    computed = False
    pos = 0
    while pos < len(text):
        part, pos, interpolated = lexer.template_char(pos)
        computed = computed or interpolated
        parts.append(part)
    return COMPUTED if computed else "".join(parts)
