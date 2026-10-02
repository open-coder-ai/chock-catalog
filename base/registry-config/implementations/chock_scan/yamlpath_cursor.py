"""The YAML scanner's shared state: the typed error, the node record, input checks and the cursor."""

from __future__ import annotations

import bisect
import re
from typing import NamedTuple

MAX_CHARS = 1 << 20
MAX_DEPTH = 64
MAX_NODES = 200_000
BOM = "\ufeff"
#: Outside YAML's printable set, plus NEL, LS and PS: YAML 1.1 loaders break lines there and 1.2 loaders
#: do not, so a key behind one is a key to one reader and text to another. Refused, never guessed.
FORBIDDEN = re.compile("[^\t\n\x20-\x7e\xa0-\ud7ff\ue000-\ufefe\uff00-\ufffd\U00010000-\U0010ffff]|[\u2028\u2029]")
MARKER = re.compile(r"(?:---|\.\.\.)(?=[ \t]|$)")
#: %YAML is read; %TAG would change what every tag means, and other directives are reserved: both refused.
DIRECTIVE = re.compile(r"%YAML[ \t]++1\.[0-9]++(?:[ \t]++(?:#.*+)?)?")
SPACES = re.compile(r" *+")
BLANKS = re.compile(r"[ \t]*+")
WHITE = " \t"


class ParseError(ValueError):
    """The input is not YAML this scanner reads with certainty. Never a stand-in for 'nothing found'."""

    def __init__(self, reason: str, line: int) -> None:
        super().__init__(f"line {line}: {reason}")
        self.reason = reason
        self.line = line


class Node(NamedTuple):
    """One node: its key path (str keys, int indices), text, 1-based line, and how it was written.

    kind: plain, single, double, literal, folded (scalars); alias (value is the anchor name, never
    expanded); map, seq (a collection starts here, value ""). tag and anchor are as written, or "".
    """

    path: tuple[str | int, ...]
    value: str
    line: int
    kind: str
    tag: str
    anchor: str
    doc: int


class Props(NamedTuple):
    tag: str = ""
    anchor: str = ""
    pos: int = -1


def prepare(text: str, max_chars: int) -> str:
    """The text with one leading BOM dropped and every line break as LF; refused when too big or unprintable."""
    if not isinstance(text, str):
        msg = f"text must be str, not {type(text).__name__}"
        raise TypeError(msg)
    if len(text) > max_chars:
        msg = f"larger than {max_chars} characters"
        raise ParseError(msg, 1)
    text = text.removeprefix(BOM).replace("\r\n", "\n").replace("\r", "\n")
    bad = FORBIDDEN.search(text)
    if bad:
        msg = f"character U+{ord(bad.group()):04X} is not allowed"
        raise ParseError(msg, text.count("\n", 0, bad.start()) + 1)
    return text


def documents(text: str) -> list[tuple[int, str, bool]]:
    """(first line, text, explicit) per document; a `---` marker becomes spaces so columns hold."""
    docs: list[tuple[int, str, bool]] = []
    current: list[str] | None = None
    start, explicit, directive = 1, False, 0
    lines = text.split("\n")
    for number, line in enumerate(lines, 1):
        kept = line if number == len(lines) else line + "\n"
        marker = _marker(line, number)
        if marker:
            if current is not None:
                docs.append((start, "".join(current), explicit))
            current = ["   " + kept[3:]] if marker == "---" else None
            start, explicit, directive = number, True, 0
        elif current is not None:
            current.append(kept)
        else:
            directive = _prefix(line, number, directive)
            if directive < 0:
                current, start, explicit, directive = [kept], number, False, 0
    if current is not None:
        docs.append((start, "".join(current), explicit))
    elif directive:
        msg = "a directive must be followed by ---"
        raise ParseError(msg, directive)
    return docs


def _marker(line: str, number: int) -> str:
    """`---`, `...` or "" for a line; only a comment may follow `...`."""
    if not MARKER.match(line):
        return ""
    rest = line[3:]
    body = rest.lstrip(WHITE)
    if line[0] == "." and body and not (body.startswith("#") and rest[0] in WHITE):
        msg = "only a comment may follow ..."
        raise ParseError(msg, number)
    return line[:3]


def _prefix(line: str, number: int, directive: int) -> int:
    """Between documents: the first directive line seen so far, or -1 when this line starts a document."""
    if line.startswith("%"):
        if not DIRECTIVE.fullmatch(line) or directive:
            msg = "a directive other than one %YAML 1.x"
            raise ParseError(msg, number)
        return number
    if not line.strip(WHITE) or line.lstrip(WHITE).startswith("#"):
        return directive
    if directive:
        msg = "a directive must be followed by ---"
        raise ParseError(msg, directive)
    return -1


class Cursor:
    """A position in one document, the nodes found so far, and the limits that bound the work."""

    def __init__(self, text: str, first_line: int, doc: int, out: list[Node], limits: tuple[int, int]) -> None:
        self.text = text
        self.pos = 0
        self.first = first_line
        self.doc = doc
        self.out = out
        self.max_depth, self.max_nodes = limits
        self.depth = 0
        self.marker = 0  # the line of this document's `---`, where no block collection may start
        self.starts = [0, *(m.end() for m in re.finditer("\n", text))]

    def line(self, pos: int | None = None) -> int:
        return self.first + bisect.bisect_right(self.starts, self.pos if pos is None else pos) - 1

    def col(self) -> int:
        return self.pos - self.starts[bisect.bisect_right(self.starts, self.pos) - 1]

    def char(self, offset: int = 0) -> str:
        at = self.pos + offset
        return self.text[at] if at < len(self.text) else ""

    def error(self, reason: str, pos: int | None = None) -> ParseError:
        return ParseError(reason, self.line(pos))

    def emit(self, path: tuple[str | int, ...], value: str, kind: str, props: Props, at: int) -> None:
        if len(self.out) >= self.max_nodes:
            msg = f"more than {self.max_nodes} nodes"
            raise self.error(msg, at)
        start = props.pos if props.pos >= 0 else at
        self.out.append(Node(path, value, self.line(start), kind, props.tag, props.anchor, self.doc))

    def enter(self) -> None:
        self.depth += 1
        if self.depth > self.max_depth:
            msg = f"nested deeper than {self.max_depth}"
            raise self.error(msg)

    def leave(self) -> None:
        self.depth -= 1

    def skip_blanks(self) -> None:
        self.pos = BLANKS.match(self.text, self.pos).end()

    def at_comment(self) -> bool:
        """A `#` that starts a comment: at a line start or after a space or tab."""
        return self.char() == "#" and (self.pos == 0 or self.text[self.pos - 1] in "\n \t")

    def at_break(self) -> bool:
        return self.char() in ("", "\n")

    def end_line(self) -> None:
        """Consume trailing blanks, a comment and the line break; anything else is an error."""
        self.skip_blanks()
        if self.at_comment():
            end = self.text.find("\n", self.pos)
            self.pos = len(self.text) if end < 0 else end
        if not self.at_break():
            msg = f"unexpected {self.char()!r}"
            raise self.error(msg)
        self.pos = min(self.pos + 1, len(self.text))

    def next_line(self) -> int:
        """Move to the start of the next line holding content and return its indent; -1 at the end."""
        text = self.text
        while self.pos < len(text):
            indent = SPACES.match(text, self.pos).end()
            body = BLANKS.match(text, indent).end()
            if body < len(text) and text[body] not in "\n#":
                if body != indent:
                    msg = "a tab in indentation"
                    raise self.error(msg, body)
                return indent - self.pos
            end = text.find("\n", body)
            self.pos = len(text) if end < 0 else end + 1
        return -1
