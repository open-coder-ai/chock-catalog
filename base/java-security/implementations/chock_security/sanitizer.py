"""Whether a check guards the request data a sink takes, read from the code and never the comments.

A sanitizer's name somewhere on a line proves nothing: `// TODO sanitize later`, `"/srv/sanitize/"`,
`sanitize(other)` and a `sanitize(name);` whose result is thrown away all hold it. A check counts
when it is a call taking the request value, or a method called on it, in the file's code with
comments and literal contents blanked -- and when the value reaches the sink only through it: inside
the sink's argument, or under an `if (...)` or `cond ? a : b` whose condition is a check on it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from chock_security.pack import facts
from chock_security.source import blank

_FACTS = facts("java")["flow"]


def mentions(line: str, names: set[str]) -> bool:
    """Whether the line USES one of these names: in its code, never inside a string literal or a
    comment -- `"//item[@sku=$sku]"` names an XPath variable, not the `sku` parameter."""
    code_only = blank(line)
    return any(re.search(rf"\b{re.escape(name)}\b", code_only) for name in names)


def holds(line: str, tokens: list[str]) -> bool:
    return any(token in line for token in tokens)


#: `value.matches(SAFE_NAME)`: validation against a named pattern. `Matcher.matches()`, with nothing
#: between its parentheses, is the match itself -- often the very sink being judged -- never a check.
_VALIDATED = re.compile(r"\.matches\(\s*[A-Z][A-Z0-9_]*\s*\)")

#: A call answering yes or no about its value. It keeps nothing out of what the sink receives, so it
#: counts only as the condition of an `if` or a ternary -- and, as a method, only on the value itself.
_PREDICATE = re.compile(r"is[A-Z_$][\w$]*|matches|startsWith|contains|containsKey")

_IDENTIFIER = re.compile(r"[\w$]*")
_CALL_AFTER = re.compile(r"\s*(?:\.\s*[\w$]+\s*)?\(")
_CHAINED_CALL = re.compile(r"\s*\.\s*[\w$]+\s*\(")
_IF = re.compile(r"(?<![\w$])if\s*\(")
_ASSIGN = re.compile(r"[^=!<>]=(?!=)")


#: A lookup in a constant collection: `ALLOWED.get(name)`, `Config.NAMES.contains(name)`, `Set.of(...)`.
_LOOKUP = re.compile(r"\.\s*(get|contains|containsKey)\s*\(")
_CONSTANT = re.compile(r"(?:[\w$]+\s*\.\s*)*[A-Z][A-Z0-9_]*|(?:Map|Set|List)\s*\.\s*(?:of|ofEntries|copyOf)\s*\(.*\)")


@dataclass(frozen=True)
class Check:
    """A check applied to request data: the code it spans, and whether it only answers yes or no."""

    start: int
    end: int
    predicate: bool


def _opening(code: str, close: int) -> int:
    """Where the bracket closing at `close` was opened; 0 when it was opened on an earlier line."""
    depth = 0
    for index in range(close, -1, -1):
        depth += (code[index] in ")]") - (code[index] in "([")
        if depth == 0:
            return index
    return 0


def closing(code: str, opening: int) -> int:
    """Where the parenthesis at `opening` is closed, or the line's end when it is not."""
    depth = 0
    for index in range(opening, len(code)):
        depth += (code[index] == "(") - (code[index] == ")")
        if depth == 0:
            return index
    return len(code)


def _left(code: str, index: int) -> int:
    while index > 0 and code[index - 1].isspace():
        index -= 1
    return index


def _receiver_start(code: str, dot: int) -> int:
    """Where the expression a call is made on starts: `Paths.get(base, name)` for `.normalize()`."""
    start = _left(code, dot)
    while True:
        while start > 0 and code[start - 1] in ")]":
            start = _opening(code, start - 1)
        while start > 0 and (code[start - 1].isalnum() or code[start - 1] in "_$"):
            start -= 1
        dot = _left(code, start)
        if dot == 0 or code[dot - 1] != ".":
            return start
        start = _left(code, dot - 1)


def _carries(expression: str, tainted: set[str]) -> bool:
    return holds(expression, _FACTS["source_calls"]) or mentions(expression, tainted)


def _follow_chain(code: str, opening: int) -> int:
    """`ESAPI.encoder().encodeForHTML(v)`: past calls taking nothing, to the one taking the value."""
    while not code[opening + 1 : closing(code, opening)].strip():
        chained = _CHAINED_CALL.match(code, closing(code, opening) + 1)
        if chained is None:
            break
        opening = chained.end() - 1
    return opening


def _call_opening(code: str, token: str, match: re.Match[str]) -> int | None:
    """Where the call this token names opens its arguments, or None when it is not called here."""
    if "(" in token:
        return match.start() + token.rindex("(")
    call = _CALL_AFTER.match(code, _IDENTIFIER.match(code, match.end()).end())
    return call.end() - 1 if call else None


def _callee(code: str, opening: int) -> str:
    """The name of the method whose arguments open at `opening`."""
    end = _left(code, opening)
    start = end
    while start > 0 and (code[start - 1].isalnum() or code[start - 1] in "_$"):
        start -= 1
    return code[start:end]


def _occurrences(code: str, token: str) -> Iterator[re.Match[str]]:
    """`token` in the code, never as the tail of a longer name: `desanitize(v)` is not `sanitize`."""
    bound = r"(?<![\w$])" if re.match(r"[\w$]", token) else ""
    return re.finditer(bound + re.escape(token), code)


def _check(code: str, token: str, match: re.Match[str], tainted: set[str]) -> Check | None:
    """This occurrence of `token` as a check on request data, or None when it checks nothing.

    `.name` tokens are a method called on the value (`name.startsWith(base)`, `x.normalize()`) or,
    unless they only answer yes or no, one taking it (`.is(value)`). Any other token is a call taking
    it (`FilenameUtils.getName(name)`), or the start of the identifier that is (`isValidPath(name)`,
    `allowlist.get(name)`)."""
    opening = _call_opening(code, token, match)
    on_value = token.startswith(".")
    if opening is None:
        return None
    if not on_value:
        opening = _follow_chain(code, opening)
    close = closing(code, opening)
    end = min(close + 1, len(code))
    predicate = bool(_PREDICATE.fullmatch(_callee(code, opening)))
    receiver = _receiver_start(code, match.start())
    if on_value and _carries(code[receiver : match.start()], tainted):
        return Check(receiver, end, predicate)
    if (not on_value or not predicate) and _carries(code[opening + 1 : close], tainted):
        return Check(match.start(), end, predicate)
    return None


def _lookups(code: str, tainted: set[str]) -> Iterator[Check]:
    """The request value used as the key into a constant collection. `get` hands the sink the
    collection's own value, never the key, so it replaces the value; `contains` only answers yes or no.
    A collection built from the value (`Map.of(name, name)`) is not constant."""
    for match in _LOOKUP.finditer(code):
        receiver = _receiver_start(code, match.start())
        constant = _CONSTANT.fullmatch(code[receiver : match.start()].strip())
        close = closing(code, match.end() - 1)
        if (
            constant
            and not _carries(code[receiver : match.start()], tainted)
            and _carries(code[match.end() : close], tainted)
        ):
            yield Check(receiver, min(close + 1, len(code)), predicate=match.group(1) != "get")


def checks(code: str, sanitizers: list[str], tainted: set[str]) -> list[Check]:
    """Every check in this line's code that is applied to request data it carries."""
    found = [
        check
        for token in sanitizers
        for match in _occurrences(code, token)
        if (check := _check(code, token, match, tainted)) is not None
    ]
    found.extend(_lookups(code, tainted))
    for match in _VALIDATED.finditer(code):
        receiver = _receiver_start(code, match.start())
        if _carries(code[receiver : match.start()], tainted):
            found.append(Check(receiver, match.end(), predicate=True))
    return found


def statement_end(code: str, start: int) -> int:
    """Where the expression starting at `start` ends: a `,` `;` or unmatched closing bracket."""
    depth = 0
    for index in range(start, len(code)):
        depth += (code[index] in "([{") - (code[index] in ")]}")
        if depth < 0 or (depth == 0 and code[index] in ",;"):
            return index
    return len(code)


def _condition_start(code: str, question: int) -> int:
    """Where the condition of the ternary whose `?` is at `question` starts: after an unmatched
    opening bracket, a `,` `;` `?` `:` or an assignment's `=`."""
    depth = 0
    for index in range(question - 1, -1, -1):
        depth += (code[index] in ")]}") - (code[index] in "([{")
        if depth < 0 or (depth == 0 and _separates(code, index)):
            return index + 1
    return 0


def _separates(code: str, index: int) -> bool:
    return code[index] in ",;?:" or (index > 0 and _ASSIGN.match(code, index - 1) is not None)


def _ternaries(code: str) -> Iterator[tuple[int, int, int]]:
    """(condition start, `?`, end) of each ternary: never a generic `<?>` or Kotlin's `?.` and `?:`."""
    for question in (i for i, ch in enumerate(code) if ch == "?"):
        before = code[:question].rstrip()[-1:]
        if before in ("<", ",", "") or code[question + 1 : question + 2] in (".", ":"):
            continue
        yield _condition_start(code, question), question, statement_end(code, question + 1)


def _within(found: list[Check], start: int, end: int) -> bool:
    return any(c.predicate and start <= c.start and c.end <= end for c in found)


def _masked(code: str, found: list[Check]) -> str:
    """The code with every check blanked, and every ternary branch a check decides between."""
    chars = list(code)
    spans = [(c.start, c.end) for c in found]
    spans += [(start, end) for start, question, end in _ternaries(code) if _within(found, start, question)]
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def _under_if(code: str, start: int, found: list[Check]) -> bool:
    """Whether an `if (...)` earlier on this line has a check on the request value as condition."""
    for match in _IF.finditer(code, 0, start):
        close = closing(code, match.end() - 1)
        if close < start and _within(found, match.end(), close):
            return True
    return False


def sink_regions(line: str, code: str, sinks: list[str]) -> list[tuple[int, int]]:
    """Each outermost sink call on this line: what it is called on, its arguments, then any calls
    chained on its result.

    Found in the raw line, since a sink may name a literal (`.putHeader("Location"`), and read in
    the code, which keeps the line's columns."""
    regions: list[tuple[int, int]] = []
    for sink in sinks:
        for match in re.finditer(re.escape(sink), line):
            if "(" not in sink:
                regions.append((match.start(), statement_end(code, match.start())))
                continue
            end = closing(code, match.start() + sink.rindex("("))
            while chained := _CHAINED_CALL.match(code, end + 1):
                end = closing(code, chained.end() - 1)
            start = _receiver_start(code, match.start()) if sink.startswith(".") else match.start()
            regions.append((start, end))
    return [r for r in regions if not any(o != r and o[0] <= r[0] and r[1] <= o[1] for o in regions)]


def sanitized(code: str, regions: list[tuple[int, int]], sanitizers: list[str], tainted: set[str]) -> bool:
    """Whether every region of this line's code takes request data only through a check: inside the
    check's call, or under an `if` or ternary a check decides. Code that could not be aligned with
    the file's line reads as empty, and is never sanitized."""
    if not code:
        return False
    found = checks(code, sanitizers, tainted)
    masked = _masked(code, found)
    return all(not _carries(masked[start:end], tainted) or _under_if(code, start, found) for start, end in regions)
