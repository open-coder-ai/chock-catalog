"""Checks that hold only on one side of a branch: containment, allowlist membership and lookups.

`startsWith` and `contains` answer yes or no, so what they protect depends on which way the answer
goes. `if (!p.startsWith(base)) log(); read(p);` checks nothing; `if (!p.startsWith(base)) throw ...;
read(p);` does. A check counts only where it decides:

- `if (X)` and `X ? a : b`: the body (the true branch) when the test is positive, `&&`-joined at most;
  after the statement when the test is exactly `!X` and its body starts with throw, return, continue
  or break (also on the next line, or first in a braced block); never with `||` in the condition.
- `Preconditions.checkArgument(X)` and its always-on kin (a Java `assert` is off by default).
- a lookup in a constant collection: `.get(key)` replaces the value with the collection's own.

Containment (`p.startsWith(base)`) is judged on a path that was normalized, and the base must not
carry request data or be a bare `/`; a String (`getCanonicalPath()`, `toString()`) needs a base ending
in a separator, or `/srv-evil` passes for `/srv`. A constant is an allowlist only when this file
declares it `static final` from an immutable factory and never mutates it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from chock_security.sanitizer import carries, closing, receiver_start, sink_regions, statement_end, ternaries

ASSIGNMENT = re.compile(r"(?:^|[^=!<>+\-*/%&|^])(\w+)\s*=(?!=)")

_NORMALIZED = re.compile(
    r"\.\s*(?P<call>normalize\s*\(\s*\)|toRealPath\s*\([^()]*\)|getCanonicalPath\s*\(\s*\)|getCanonicalFile\s*\(\s*\))"
    r"(?:\s*\.\s*(?P<tail>toString|toPath)\s*\(\s*\))?\s*$"
)
_CALL = re.compile(r"\.\s*(startsWith|contains|containsKey|get)\s*\(")
_INLINE = re.compile(r"(?:Map|Set|List)\s*\.\s*(?:of|ofEntries|copyOf)\s*\(.*\)")
_IDENTIFIER = re.compile(r"[\w$]+")
_IF = re.compile(r"(?<![\w$])if\s*\(")
_EXIT = re.compile(r"(?:throw|return|continue|break)\b")
_ALWAYS_ON = re.compile(
    r"(?<![\w$])(?:Preconditions\s*\.\s*check(?:Argument|State)|Validate\s*\.\s*(?:isTrue|validState)"
    r"|Assert\s*\.\s*(?:isTrue|state))\s*\("
)
_SEPARATOR_END = re.compile(r"""(?:"[^"]*[/\\]"|File\s*\.\s*separator(?:Char)?)\s*$""")
_NO_BASE = re.compile(r"""\s*"[\s/\\.]*"\s*""")

_IMMUTABLE = re.compile(
    r"\b(?:static\s+final|final\s+static)\b[^=;]*?(?<![\w$])([A-Z][A-Z0-9_]*)\s*=\s*"
    r"(?:(?:Map|Set|List)\s*\.\s*(?:of|ofEntries|copyOf)\s*\(|Immutable\w+\s*\.\s*(?:of|copyOf)\s*\("
    r"|Collections\s*\.\s*unmodifiable\w+\s*\(\s*(?![A-Za-z_$][\w$]*\s*\)))"
)
_MUTATORS = r"(?:put\w*|add\w*|remove\w*|retainAll|clear|compute\w*|merge|replace\w*|set|sort)"


def kind(value: str) -> str | None:
    """`path` or `string` when the value ends in a call that resolves it to a form `startsWith` can
    hold to a base; None for any other value (`normalize().resolve(name)` ends in another resolve)."""
    match = _NORMALIZED.search(value.strip())
    if match is None:
        return None
    if match["tail"]:
        return "string" if match["tail"] == "toString" else "path"
    call = match["call"]
    if call.startswith("getCanonicalFile"):
        return None
    return "string" if call.startswith("getCanonicalPath") else "path"


def immutable_constants(code: str) -> frozenset[str]:
    """Constants this file declares `static final` from an immutable factory and never mutates."""
    names = {m[1] for m in _IMMUTABLE.finditer(code)}
    return frozenset(n for n in names if not re.search(rf"(?<![\w$]){n}\s*\.\s*{_MUTATORS}\s*\(", code))


@dataclass
class Scope:
    """What a method's lines so far have established: its constants and its normalized paths."""

    constants: frozenset[str] = frozenset()
    normalized: dict[str, str] = field(default_factory=dict)

    def track(self, code: str) -> None:
        for match in ASSIGNMENT.finditer(code):
            value = kind(code[match.end() : statement_end(code, match.end())])
            if value:
                self.normalized[match[1]] = value
            else:
                self.normalized.pop(match[1], None)


@dataclass(frozen=True)
class Atom:
    """A check on one value: the code it spans, which way it answers, and the variable it clears."""

    start: int
    end: int
    negated: bool
    lookup: bool
    name: str | None


@dataclass(frozen=True)
class Effect:
    """What a line's checks cover: spans of this line, the variables a check decides something for
    (a normalized path built before it is no longer refused for it), names cleared from here to the
    method's end, and names cleared only until the block this line opens is closed."""

    spans: tuple[tuple[int, int], ...] = ()
    held: frozenset[str] = frozenset()
    cleared: frozenset[str] = frozenset()
    scoped: frozenset[str] = frozenset()


def _constant(receiver: str, tainted: set[str], scope: Scope) -> bool:
    text = receiver.strip()
    if _INLINE.fullmatch(text):
        return not carries(text, tainted)
    return text in scope.constants


def _holds(receiver: str, base: str, tainted: set[str], scope: Scope) -> bool:
    """Whether `receiver.startsWith(base)` holds a value to a base: the base is not request data, is
    not a bare root, and for a String ends in a separator."""
    if carries(base, tainted) or _NO_BASE.fullmatch(base):
        return False
    kinds = scope.normalized.get(receiver.strip()) or kind(receiver)
    return kinds != "string" or _SEPARATOR_END.search(base.strip()) is not None


def _atoms(code: str, raw: str, tainted: set[str], scope: Scope) -> list[Atom]:
    source = raw if len(raw) == len(code) else code
    found = []
    for match in _CALL.finditer(code):
        method, start = match[1], receiver_start(code, match.start())
        receiver, close = code[start : match.start()], closing(code, match.end() - 1)
        args = code[match.end() : close]
        if method == "startsWith":
            holds = carries(receiver, tainted) and _holds(receiver, source[match.end() : close], tainted, scope)
            name = receiver.strip() if receiver.strip() in scope.normalized else None
        else:
            holds = _constant(receiver, tainted, scope) and carries(args, tainted)
            name = args.strip() if args.strip() in tainted else None
        if holds:
            before = code[:start].rstrip(" \t(")
            found.append(Atom(start, min(close + 1, len(code)), before.endswith("!"), method == "get", name))
    return found


def _decides(condition: str, atom: Atom, offset: int) -> bool:
    """Whether the condition is this check alone, or (when positive) `&&`-joined with others."""
    before = re.sub(r"^\s*return\b", "", condition[: atom.start - offset]).strip(" \t(")
    after = condition[atom.end - offset :].strip(" \t)")
    if "||" in condition:
        return False
    if atom.negated:
        return before == "!" and not after
    return (not before or before.endswith("&&")) and (not after or after.startswith("&&"))


def _block_end(code: str, opening: int) -> int | None:
    """Where the block opened at `opening` is closed, or None when it runs past this line."""
    depth = 0
    for index in range(opening, len(code)):
        depth += (code[index] == "{") - (code[index] == "}")
        if depth == 0:
            return index + 1
    return None


def _body_end(code: str, start: int) -> int:
    if code[start : start + 1] == "{":
        return _block_end(code, start) or len(code)
    return min(len(code), statement_end(code, start) + 1)


def _colon(code: str, start: int, end: int) -> int | None:
    """The `:` of the ternary whose branches start at `start`, skipping nested ternaries."""
    nested = 0
    for index in range(start, end):
        nested += code[index] == "?"
        if code[index] == ":":
            if not nested:
                return index
            nested -= 1
    return None


def _exits(rest: str, following: str) -> bool:
    """Whether the body of an `if` starts with throw, return, continue or break."""
    body = rest or following
    if body[:1] == "{":
        body = body[1:].strip() or following.removeprefix("{").strip()
    return _EXIT.match(body) is not None


@dataclass(frozen=True)
class Cover:
    """Code a check decides, and whether the variable stays cleared after it (`after`) or only while
    the block it opens runs (`block`)."""

    span: tuple[int, int]
    after: bool = False
    block: bool = False


def _if_covers(code: str, atom: Atom, following: str) -> Iterator[Cover]:
    for match in _IF.finditer(code):
        opening = match.end() - 1
        close = closing(code, opening)
        if not (opening < atom.start and atom.end <= close) or not _decides(
            code[opening + 1 : close], atom, opening + 1
        ):
            continue
        rest = code[close + 1 :].strip()
        body = len(code) - len(code[close + 1 :].lstrip())
        if atom.negated and _exits(rest, following):
            yield Cover((_body_end(code, body), len(code)), after=True)
        elif not atom.negated and rest:
            yield Cover((body, _body_end(code, body)), block=rest[0] == "{" and _block_end(code, body) is None)


def _ternary_covers(code: str, atom: Atom) -> Iterator[Cover]:
    for start, question, end in ternaries(code):
        colon = _colon(code, question + 1, end)
        if (
            colon is not None
            and start <= atom.start
            and atom.end <= question
            and _decides(code[start:question], atom, start)
        ):
            yield Cover((colon + 1, end) if atom.negated else (question + 1, colon))


def _always_on_covers(code: str, atom: Atom) -> Iterator[Cover]:
    """`Preconditions.checkArgument(p.startsWith(base), "message")`: the check is the first argument."""
    for match in _ALWAYS_ON.finditer(code):
        opening = match.end() - 1
        close = closing(code, opening)
        first = not code[opening + 1 : atom.start].strip(" \t(") and code[atom.end : close].strip(" \t)")[:1] in (
            "",
            ",",
        )
        if first and not atom.negated and opening < atom.start:
            yield Cover((close + 1, len(code)), after=True)


def analyse(code: str, raw: str, tainted: set[str], scope: Scope, following: str = "") -> Effect:
    """The checks on this line that decide something: where, and for which variables."""
    atoms = _atoms(code, raw, tainted, scope)
    spans: list[tuple[int, int]] = [(a.start, a.end) for a in atoms if a.lookup]
    cleared: set[str] = set()
    scoped: set[str] = set()
    held: set[str] = set()
    for atom in (a for a in atoms if not a.lookup):
        names = {atom.name} if atom.name else set()
        covers = [*_if_covers(code, atom, following), *_ternary_covers(code, atom), *_always_on_covers(code, atom)]
        spans += [cover.span for cover in covers] + [(atom.start, atom.end)] * bool(covers)
        held |= names if covers else set()
        cleared |= names if any(cover.after for cover in covers) else set()
        scoped |= names if any(cover.block for cover in covers) else set()
    return Effect(tuple(spans), frozenset(held), frozenset(cleared), frozenset(scoped))


def deferred_to(line: str, code: str, sinks: list[str]) -> str | None:
    """The variable a sink on this line only builds, as `Path p = Paths.get(base, name).normalize();`:
    the path is refused unless a later line holds `p` to its base. None for any other line."""
    match = ASSIGNMENT.search(code)
    if match is None or not kind(code[match.end() : statement_end(code, match.end())]):
        return None
    inside = all(start >= match.end() for start, _ in sink_regions(line, code, sinks))
    return match.group(1) if inside else None
