"""`.size() == 0` and `.length() == 0` work, but isEmpty() says what the code means directly and,
on some collections, is faster than counting every element just to compare against zero."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import Method, methods
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "performance-size-check"

_FACTS = facts("performance")["size_check"]

_TYPES = "|".join(_FACTS["collection_types"])
_COLLECTION_DECL = re.compile(rf"^\s*(?:final\s+)?({_TYPES})\s*(?:<[^<>]*>)?\s+(\w+)\s*[=;]")
_STRING_DECL = re.compile(r"^\s*(?:final\s+)?String\s+(\w+)\s*[=;]")
_SIZE_CHECK = re.compile(r"\b(\w+)\s*\.\s*(size|length)\(\)\s*(==\s*0|>\s*0|!=\s*0)")
_PARAM = re.compile(rf"^(?:@\w+(?:\([^)]*\))?\s*)*(?:final\s+)?({_TYPES}|String)(?:<.*>)?(?:\[\])?\s+(\w+)$")


def _split_params(inside: str) -> list[str]:
    """Top-level comma splits, respecting `<...>` so `Map<K, V> m` stays one parameter."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(inside):
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(inside[start:i])
            start = i + 1
    parts.append(inside[start:])
    return parts


def _params(signature: str) -> dict[str, str]:
    """method-parameter name -> "size" or "length", from its declared type in the signature."""
    inside = signature[signature.find("(") + 1 : signature.rfind(")")]
    kinds: dict[str, str] = {}
    for part in _split_params(inside):
        match = _PARAM.match(part.strip())
        if match:
            kinds[match.group(2)] = "length" if match.group(1) == "String" else "size"
    return kinds


_MESSAGE = (
    "{expr} works, but {name}.isEmpty() says what this checks directly and never has to count "
    f"elements just to compare against zero. Use {{name}}.isEmpty() (or !{{name}}.isEmpty()) "
    f"instead. 'chock: allow {RULE_ID}' on this line if this genuinely needs the exact count."
)


def _declared(text: FileText, method: Method) -> dict[str, str]:
    """method-local/parameter name -> "size" or "length", from its declared type."""
    code_lines = code(text)
    kinds: dict[str, str] = _params(method.signature)
    for line_no, _raw in method.body:
        blanked = code_lines[line_no - 1] if 0 < line_no <= len(code_lines) else ""
        collection = _COLLECTION_DECL.match(blanked)
        if collection:
            kinds[collection.group(2)] = "size"
            continue
        string = _STRING_DECL.match(blanked)
        if string:
            kinds[string.group(1)] = "length"
    return kinds


def _method_findings(text: FileText, method: Method) -> Iterator[Finding]:
    code_lines = code(text)
    kinds = _declared(text, method)
    for line_no, raw in method.body:
        blanked = code_lines[line_no - 1] if 0 < line_no <= len(code_lines) else raw
        for match in _SIZE_CHECK.finditer(blanked):
            name, accessor, _op = match.groups()
            if kinds.get(name) == accessor:
                yield Finding(RULE_ID, text.path, line_no, raw, _MESSAGE.format(expr=match.group(0), name=name))


def scan(text: FileText) -> Iterator[Finding]:
    """Every `.size() == 0`/`> 0`/`!= 0` on a locally-declared collection, or `.length()` on a String."""
    for method in methods(text):
        yield from _method_findings(text, method)


RULE = Rule(
    id=RULE_ID,
    pack="performance",
    title="size()/length() compared to zero instead of isEmpty()",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(compare): collection.size() == 0|> 0|!= 0, or string.length() == 0|> 0|!= 0 -- use isEmpty()/!isEmpty() instead",
    refuses="`.size() == 0`/`> 0`/`!= 0` on a List/Set/Map/Collection/Queue/Deque local declared in this method; `.length() == 0`/`> 0`/`!= 0` on a String local declared in this method",
    silent_on="`.isEmpty()`/`!.isEmpty()`; `.size()`/`.length()` compared to any value other than 0; `.size()`/`.length()` on a receiver not declared as one of those types in this method (a field, a custom class, an array)",
    references=(
        "https://rules.sonarsource.com/java/RSPEC-1155/",
        "https://rules.sonarsource.com/java/RSPEC-7158/",
    ),
)
