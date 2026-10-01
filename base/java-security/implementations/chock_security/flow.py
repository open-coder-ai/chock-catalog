"""Where a value came from, inside one method body. A flow that leaves the method is not ours.

Some vulnerabilities are not a construct but a path: `new File(name)` is correct code until
`name` is something a request carried. This tracks that path within a single method, because
that is where it can be demonstrated rather than guessed -- and a rule that guesses fires on
correct code, which is the one failure this pack does not accept.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from functools import lru_cache

from chock_security.decision import FileText
from chock_security.guards import ASSIGNMENT, Around, Frames, Scope, analyse, deferred_to, immutable_constants
from chock_security.pack import facts
from chock_security.sanitizer import holds, mentions, receiver_start, sanitized, sink_regions, statement_end
from chock_security.source import blank

_FACTS = facts("java")["flow"]

#: A line opening a block that is not a method: matching these as declarations would make
#: every `if (...)` a method and every condition a signature.
_NOT_A_DECLARATION = frozenset(
    {"if", "for", "while", "switch", "catch", "try", "else", "do", "synchronized", "return", "new"}
)

#: A typed declaration is at least a type and a name: `Long id`.
_TYPE_AND_NAME = 2

_NAME_BEFORE_PAREN = re.compile(r"(\w+)\s*\($")
#: An annotation can sit on its own line or in front of the declaration on the same one.
_LEADING_ANNOTATION = re.compile(r"^@\w+(?:\s*\([^()]*\))?\s*")


@dataclass(frozen=True)
class Method:
    """One method: the signature its parameters come from, and the body they flow through."""

    name: str
    signature: str
    body: tuple[tuple[int, str], ...]
    #: `body` line for line, from the whole file's lexing: comments and literal contents blanked.
    code: tuple[str, ...]
    #: Constants the file declares as immutable collections: the allowlists a lookup can be made in.
    constants: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Flow:
    """A value from an untrusted source, reaching a sink on this line."""

    line_no: int
    line: str
    source: str


def _declares(line: str) -> str | None:
    """The method name this line declares, or None. Conservative: an unclear line declares none."""
    stripped = line.strip()
    while match := _LEADING_ANNOTATION.match(stripped):
        stripped = stripped[match.end() :]
    head = stripped.split("(", 1)[0]
    if "(" not in stripped or not head.strip():
        return None
    if stripped.split(maxsplit=1)[0].split("(", maxsplit=1)[0] in _NOT_A_DECLARATION:
        return None
    match = _NAME_BEFORE_PAREN.search(head + "(")
    return match.group(1) if match else None


def _signature(lines: list[str], start: int, name: str) -> tuple[str, int] | None:
    """The parameter list following the method name, and the line it closes on.

    `_declares` read `name(` on `start`'s own line, so the opening parenthesis is found there;
    the list may close up to twenty lines later.
    """
    anchor = re.search(rf"\b{re.escape(name)}\s*\(", lines[start])
    begin, opening = (anchor.start(), anchor.end() - 1) if anchor else (0, len(lines[start]))
    text = ""
    for offset in range(start, min(start + 20, len(lines))):
        text = f"{text} {lines[offset]}" if text else lines[offset]
        depth = 0
        for index in range(opening, len(text)):
            depth += (text[index] == "(") - (text[index] == ")")
            if depth == 0:
                return text[begin : index + 1], offset
    return None


def _body(lines: list[str], after: int) -> tuple[tuple[tuple[int, str], ...], int] | None:
    """The braced block following a signature and the line it closes on, or None with no body.

    What follows the opening brace on its own line is body too, so a one-line method
    (`x(...) { return y; }`) has one, and the text before the brace is never mistaken for it.
    """
    depth = 0
    opened = False
    collected: list[tuple[int, str]] = []
    for offset in range(after, len(lines)):
        line = lines[offset]
        if not opened:
            if ";" in line.split("{")[0] and "{" not in line:
                return None
            if "{" not in line:
                continue
            opened = True
            rest = line.split("{", 1)[1]
            depth = 1 + rest.count("{") - rest.count("}")
            if rest.strip() and rest.strip() != "}":
                collected.append((offset + 1, rest))
            if depth <= 0:
                return tuple(collected), offset
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            return tuple(collected), offset
        collected.append((offset + 1, line))
    return None


def _code_of(clean: list[str], lines: list[str], line_no: int, line: str) -> str:
    """The blanked text of a body line, which may be the tail of its file line (`{ return y; }`).

    A separator `splitlines` honours but lexing blanks (a form feed) merges two lines into one, so
    the blanked lines no longer match the file's; every line then reads as empty, and nothing in
    it can count as a sanitizer. Columns count from the line's start: a CR that lexing blanks inside
    a comment stays on the blanked line as a trailing space, where `splitlines` drops the file's."""
    if len(clean) != len(lines):
        return ""
    start = len(lines[line_no - 1]) - len(line)
    return clean[line_no - 1][start : start + len(line)]


def methods(text: FileText) -> list[Method]:
    """Every method in this file that has a body. Anything unclear is left out, never guessed.

    A fresh list each call over one cached parse: two dozen rules walk the same file's methods,
    and a Method is frozen, so sharing them cannot let one rule change what another reads."""
    return list(_methods(text.text))


#: Distinct file texts one run keeps parsed; a gate run sees a handful, a test session a few thousand.
_METHOD_CACHE_SIZE = 1024


@lru_cache(maxsize=_METHOD_CACHE_SIZE)
def _methods(text: str) -> tuple[Method, ...]:
    lines = text.splitlines()
    clean = blank(text).splitlines()
    constants = immutable_constants(blank(text))
    found: list[Method] = []
    offset = 0
    while offset < len(lines):
        name = _declares(lines[offset])
        signature = _signature(lines, offset, name) if name else None
        block = _body(lines, signature[1]) if signature else None
        if name and signature and block and block[0]:
            code = tuple(_code_of(clean, lines, number, line) for number, line in block[0])
            found.append(Method(name, signature[0], block[0], code, constants))
            offset = block[1]
        offset += 1
    return tuple(found)


#: `ALLOWED.contains(v) ? v : fallback` -- membership decides whether `v` is used at all, however the
#: collection is named, so `v` arrives only as one of the collection's own values.
_MEMBERSHIP = re.compile(r"\.(?:contains|containsKey)\(\s*(\w+)\s*\)\s*\?\s*(\w+)\s*:")


def _guarded(line: str, tainted: set[str]) -> bool:
    """Whether `v` reaches only as a member: `ALLOWED.contains(v) ? v : x`, never `!ALLOWED.contains(v) ? v : x`."""
    code = blank(line)
    return any(
        m.group(1) == m.group(2)
        and m.group(1) in tainted
        and not code[: receiver_start(code, m.start())].rstrip(" \t(").endswith("!")
        for m in _MEMBERSHIP.finditer(code)
    )


def _parameters(signature: str) -> set[str]:
    """Parameters an annotation marks as carrying request data, by name."""
    inside = signature[signature.find("(") + 1 : signature.rfind(")")]
    tainted = set()
    for parameter in inside.split(","):
        if not holds(parameter, _FACTS["source_annotations"]):
            continue
        words = re.findall(r"\w+", _without_annotations(parameter))
        # A number, a boolean, a UUID or a date is parsed before the method sees it: it cannot
        # carry '../', a host or a shell metacharacter, so it taints nothing downstream.
        if len(words) >= _TYPE_AND_NAME and words[-2] in _FACTS["scalar_types"]:
            continue
        if words:
            tainted.add(words[-1])
    return tainted


def _without_annotations(parameter: str) -> str:
    """The declaration with its annotations (and their arguments) removed: `Long id`, not `@PathVariable(...)`."""
    return re.sub(r"@\w+(?:\s*\([^()]*\))?", " ", parameter)


Guard = Callable[[set[str]], list[tuple[int, int]]]


def _retaint(line: str, code: str, tainted: set[str], sanitizers: list[str], guard: Guard | None = None) -> None:
    """Follow one assignment: the target carries what its right-hand side carries, and no more."""
    for match in ASSIGNMENT.finditer(line):
        target = match.group(1)
        right = line[match.end() :]
        carries = holds(right, _FACTS["source_calls"]) or mentions(right, tainted)
        value = [(match.end(), statement_end(code, match.end()))]
        if carries and not sanitized(code, value, sanitizers, tainted, guard) and not _guarded(right, tainted):
            tainted.add(target)
        else:
            tainted.discard(target)


def _unchecked(
    line: str, code: str, tainted: set[str], rules: tuple[list[str], list[str]], guard: Guard | None = None
) -> bool:
    """Whether request data reaches a sink on this line other than through a check. A value assigned
    earlier on the line counts as carried: `String g = f; read(g)` reaches, `read(g); g = f` too."""
    sinks, sanitizers = rules
    carried = set(tainted)
    _retaint(line, code, carried, sanitizers, guard)
    carried |= tainted
    regions = sink_regions(line, code, sinks)
    return not sanitized(code, regions, sanitizers, carried, guard) and not _guarded(line, carried)


def reaching(method: Method, sinks: list[str], sanitizers: tuple[str, ...] = ()) -> Iterator[Flow]:
    """Every line in this body where request data reaches one of these sinks.

    `sanitizers` adds a pack's own checks to the shared list -- an allowlist lookup that only
    makes sense for redirects, say -- without the pack editing another pack's facts.
    """
    tainted = _parameters(method.signature)
    annotated = bool(tainted)
    clean = [*_FACTS["sanitizers"], *sanitizers]
    scope = Scope(method.constants)
    found: list[Flow] = []
    pending: list[tuple[str, Flow]] = []
    frames = Frames()
    for index, ((line_no, line), code) in enumerate(zip(method.body, method.code, strict=True)):

        def guard(names: set[str], line: str = line, code: str = code) -> list[tuple[int, int]]:
            return list(analyse(code, line, names, scope, Around(inside_switch=frames.in_switch)).spans)

        direct = holds(line, _FACTS["source_calls"])
        if (
            holds(line, sinks)
            and (direct or mentions(line, tainted))
            and _unchecked(line, code, tainted, (sinks, clean), guard)
        ):
            flow = Flow(line_no, line, "a request parameter" if annotated else "the request")
            held = deferred_to(line, code, sinks)
            if held:
                pending.append((held, flow))
            else:
                found.append(flow)
        _retaint(line, code, tainted, clean, guard)
        scope.track(code)
        effect = analyse(code, line, tainted, scope, Around(_following(method.code[index + 1 :]), frames.in_switch))
        pending = [(name, flow) for name, flow in pending if name not in effect.held]
        frames.settle(code, effect, tainted)
    yield from sorted(found + [flow for _, flow in pending], key=lambda flow: flow.line_no)


def _following(codes: Sequence[str]) -> str:
    """The next two lines of code with anything on them, without their indentation."""
    return " ".join([code.strip() for code in codes if code.strip()][:2])


def flows(text: FileText, sinks: list[str], sanitizers: tuple[str, ...] = ()) -> Iterator[Flow]:
    """Every sink in this file that a method body shows request data reaching."""
    for method in methods(text):
        yield from reaching(method, sinks, sanitizers)
