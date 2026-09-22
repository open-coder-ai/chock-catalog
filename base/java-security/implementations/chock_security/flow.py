"""Where a value came from, inside one method body. A flow that leaves the method is not ours.

Some vulnerabilities are not a construct but a path: `new File(name)` is correct code until
`name` is something a request carried. This tracks that path within a single method, because
that is where it can be demonstrated rather than guessed -- and a rule that guesses fires on
correct code, which is the one failure this pack does not accept.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from chock_security.decision import FileText
from chock_security.pack import facts

_FACTS = facts("java")["flow"]

#: A line opening a block that is not a method: matching these as declarations would make
#: every `if (...)` a method and every condition a signature.
_NOT_A_DECLARATION = frozenset(
    {"if", "for", "while", "switch", "catch", "try", "else", "do", "synchronized", "return", "new"}
)

_ASSIGNMENT = re.compile(r"(?:^|[^=!<>+\-*/%&|^])(\w+)\s*=(?!=)")
_NAME_BEFORE_PAREN = re.compile(r"(\w+)\s*\($")
#: An annotation can sit on its own line or in front of the declaration on the same one.
_LEADING_ANNOTATION = re.compile(r"^@\w+(?:\s*\([^()]*\))?\s*")


@dataclass(frozen=True)
class Method:
    """One method: the signature its parameters come from, and the body they flow through."""

    name: str
    signature: str
    body: tuple[tuple[int, str], ...]


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
    """The parameter list following the method name, and the line it closes on."""
    text = ""
    for offset in range(start, min(start + 20, len(lines))):
        text = f"{text} {lines[offset]}" if text else lines[offset]
        anchor = re.search(rf"\b{re.escape(name)}\s*\(", text)
        if not anchor:
            continue
        depth = 0
        for index in range(anchor.end() - 1, len(text)):
            depth += (text[index] == "(") - (text[index] == ")")
            if depth == 0:
                return text[anchor.start() : index + 1], offset
    return None


def _body(lines: list[str], after: int) -> tuple[tuple[int, str], ...] | None:
    """The braced block following a signature, or None when the declaration has no body."""
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
            depth = line.count("{") - line.count("}")
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            return tuple(collected)
        collected.append((offset + 1, line))
    return None


def methods(text: FileText) -> list[Method]:
    """Every method in this file that has a body. Anything unclear is left out, never guessed."""
    lines = list(text.lines)
    found: list[Method] = []
    offset = 0
    while offset < len(lines):
        name = _declares(lines[offset])
        signature = _signature(lines, offset, name) if name else None
        body = _body(lines, signature[1]) if signature else None
        if name and signature and body:
            found.append(Method(name, signature[0], body))
            offset = body[-1][0] if body else offset + 1
        offset += 1
    return found


def _mentions(line: str, names: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", line) for name in names)


def _holds(line: str, tokens: list[str]) -> bool:
    return any(token in line for token in tokens)


def _parameters(signature: str) -> set[str]:
    """Parameters an annotation marks as carrying request data, by name."""
    inside = signature[signature.find("(") + 1 : signature.rfind(")")]
    tainted = set()
    for parameter in inside.split(","):
        if not _holds(parameter, _FACTS["source_annotations"]):
            continue
        words = re.findall(r"\w+", parameter)
        if words:
            tainted.add(words[-1])
    return tainted


def _retaint(line: str, tainted: set[str]) -> None:
    """Follow one assignment: the target carries what its right-hand side carries, and no more."""
    for match in _ASSIGNMENT.finditer(line):
        target = match.group(1)
        right = line[match.end() :]
        carries = _holds(right, _FACTS["source_calls"]) or _mentions(right, tainted)
        if carries and not _holds(line, _FACTS["sanitizers"]):
            tainted.add(target)
        else:
            tainted.discard(target)


def reaching(method: Method, sinks: list[str]) -> Iterator[Flow]:
    """Every line in this body where request data reaches one of these sinks."""
    tainted = _parameters(method.signature)
    annotated = bool(tainted)
    for line_no, line in method.body:
        direct = _holds(line, _FACTS["source_calls"])
        reached = _holds(line, sinks) and (direct or _mentions(line, tainted))
        if reached and not _holds(line, _FACTS["sanitizers"]):
            yield Flow(line_no, line, "a request parameter" if annotated else "the request")
        _retaint(line, tainted)


def flows(text: FileText, sinks: list[str]) -> Iterator[Flow]:
    """Every sink in this file that a method body shows request data reaching."""
    for method in methods(text):
        yield from reaching(method, sinks)
