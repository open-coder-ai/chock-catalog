"""Iterating a Map's keySet() and calling get(key) for every entry looks up each value a second
time through the map's hash/tree structure -- iterating entrySet() gives both the key and the
value from the same pass, for free."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "performance-map-keyset-get"

_FOR_KEYSET = re.compile(r"\bfor\s*\(\s*[\w<>,\[\].\s]+?\s+(\w+)\s*:\s*(\w+)\s*\.\s*keySet\s*\(\s*\)\s*\)")

_MESSAGE = (
    "This loop iterates {map}.keySet() and then calls {map}.get({key}) to get the value back -- "
    "that looks the value up a second time through the map's own structure. Iterate "
    f"{{map}}.entrySet() instead and read the value straight off the entry. 'chock: allow "
    f"{RULE_ID}' on this line if the loop only sometimes needs the value."
)


def _body_get_line(code_lines: list[str], start: int, key: str, map_name: str) -> int | None:
    """The line number of the first `map.get(key)` inside the loop body starting at `start`."""
    get_call = re.compile(rf"\b{re.escape(map_name)}\s*\.\s*get\(\s*{re.escape(key)}\s*\)")
    depth = 0
    opened = False
    for index in range(start, len(code_lines)):
        line = code_lines[index]
        if not opened:
            if "{" not in line:
                if ";" in line:
                    return None
                continue
            opened = True
        if get_call.search(line):
            return index + 1
        depth += line.count("{") - line.count("}")
        if opened and depth <= 0:
            return None
    return None


def scan(text: FileText) -> Iterator[Finding]:
    """Every `for (K k : map.keySet())` loop whose body calls `map.get(k)`."""
    code_lines = code(text)
    for index, line in enumerate(code_lines):
        match = _FOR_KEYSET.search(line)
        if not match:
            continue
        key, map_name = match.group(1), match.group(2)
        found = _body_get_line(code_lines, index, key, map_name)
        if found is not None:
            yield Finding(RULE_ID, text.path, found, text.lines[found - 1], _MESSAGE.format(map=map_name, key=key))


RULE = Rule(
    id=RULE_ID,
    pack="performance",
    title="Map.keySet() iterated then get() called for every key",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(iterate): for (K k : map.keySet()) { ... map.get(k) ... } -- iterate map.entrySet() and read the value from the entry",
    refuses="a `for (K k : map.keySet())` loop whose body calls `map.get(k)` on that same map and key",
    silent_on="a `for (Map.Entry<K,V> e : map.entrySet())` loop; a keySet() loop that never calls get() on the same map/key; a keySet() loop that only checks containment",
    references=(
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#wmi-inefficient-use-of-keyset-iterator-instead-of-entryset-iterator-wmi-wrong-map-iterator",
    ),
)
