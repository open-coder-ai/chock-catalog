"""Every `+=` on a String rebuilds the whole thing from scratch, because Strings are immutable --
inside a loop that turns an O(n) pass into O(n^2) work for what a single StringBuilder would do in
linear time."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import Method, methods
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "performance-string-concat-loop"

_FACTS = facts("performance")["string_concat_loop"]

_STRING_DECL = re.compile(r"^\s*(?:final\s+)?String\s+(\w+)\s*[=;]")
_LOOP_OPEN = re.compile(r"\b(?:for|while)\s*\(|\bdo\s*\{")
_CONCAT = re.compile(r"\b(\w+)\s*\+=")
_SELF_CONCAT = re.compile(r"\b(\w+)\s*=\s*\1\s*\+(?!=)")

_MESSAGE = (
    "{name} is concatenated with '+' inside a loop -- each iteration rebuilds the whole String "
    "from scratch, since Strings are immutable, turning a linear pass into quadratic work. Build "
    f"it with a StringBuilder outside the loop and append inside instead. 'chock: allow {RULE_ID}' "
    "on this line if the loop runs only a handful of times."
)


def _blanked_body(text: FileText, method: Method) -> list[tuple[int, str, str]]:
    code_lines = code(text)
    return [
        (line_no, raw, code_lines[line_no - 1] if 0 < line_no <= len(code_lines) else raw)
        for line_no, raw in method.body
    ]


def _concat_target(line: str, declared: set[str]) -> str | None:
    match = _CONCAT.search(line) or _SELF_CONCAT.search(line)
    return match.group(1) if match and match.group(1) in declared else None


def _method_findings(text: FileText, method: Method) -> Iterator[Finding]:
    """`depth` is the brace nesting left over from every prior line; a line is inside a loop's
    body when that carried-over depth already reaches the level the innermost active loop
    opened at -- so the loop's own opening line, checked before its brace is counted, never is."""
    declared: set[str] = set()
    depth = 0
    loop_starts: list[int] = []
    for line_no, raw, line in _blanked_body(text, method):
        decl = _STRING_DECL.match(line)
        if decl:
            declared.add(decl.group(1))
        if loop_starts and depth >= loop_starts[-1]:
            target = _concat_target(line, declared)
            if target:
                yield Finding(RULE_ID, text.path, line_no, raw, _MESSAGE.format(name=target))
        opens_loop = bool(_LOOP_OPEN.search(line))
        depth += line.count("{") - line.count("}")
        if opens_loop:
            loop_starts.append(depth)
        while loop_starts and depth < loop_starts[-1]:
            loop_starts.pop()


def scan(text: FileText) -> Iterator[Finding]:
    """Every `+=` (or `x = x + ...`) on a String local declared in this method, inside a loop."""
    for method in methods(text):
        yield from _method_findings(text, method)


RULE = Rule(
    id=RULE_ID,
    pack="performance",
    title="String concatenated with '+' inside a loop",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(concatenate): a String local with += or `x = x + ...` inside a for/while/do loop -- build it with a StringBuilder outside the loop instead",
    refuses="`name += ...` or `name = name + ...` on a String local declared in the same method, inside a for/while/do loop body",
    silent_on="the same pattern outside any loop; a StringBuilder/StringBuffer .append(...) call; concatenation of a field or a variable not declared String in this method",
    references=(
        "https://rules.sonarsource.com/java/RSPEC-1643/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#sbsc-method-concatenates-strings-using-in-a-loop-sbsc-use-stringbuffer-concatenation",
    ),
)
