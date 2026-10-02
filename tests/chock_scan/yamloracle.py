"""PyYAML's event stream as yamlpath nodes: the reference the scanner is diffed against in tests.

PyYAML is a test-only reference (the framework depends on it); the shipped scanner never imports it.
It reads YAML 1.1, so callers keep to inputs where 1.1 and 1.2 agree.
"""

from __future__ import annotations

import yaml

STYLES = {None: "plain", "'": "single", '"': "double", "|": "literal", ">": "folded"}
CORE = "tag:yaml.org,2002:"


def nodes(text: str) -> list[tuple]:
    """(path, value, line, kind, tag, anchor, doc) for every node PyYAML reports, in order."""
    out: list[tuple] = []
    stack: list[list] = []  # [kind, path, next index or pending key]
    doc = -1
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.DocumentStartEvent):
            doc += 1
        elif isinstance(event, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
            stack.pop()
            _advance(stack)
        elif isinstance(event, (yaml.ScalarEvent, yaml.AliasEvent, yaml.SequenceStartEvent, yaml.MappingStartEvent)):
            if stack and stack[-1][0] == "map" and stack[-1][2] is None:
                if not isinstance(event, yaml.ScalarEvent):
                    msg = "a key that is not a scalar"
                    raise yaml.YAMLError(msg)
                stack[-1][2] = event.value  # a key
                continue
            path = _path(stack)
            out.append((path, *_describe(event), doc))
            if isinstance(event, yaml.SequenceStartEvent):
                stack.append(["seq", path, 0])
            elif isinstance(event, yaml.MappingStartEvent):
                stack.append(["map", path, None])
            else:
                _advance(stack)
    return out


def _describe(event: yaml.Event) -> tuple:
    line = event.start_mark.line + 1
    if isinstance(event, yaml.AliasEvent):
        return event.anchor, line, "alias", "", ""
    tag = event.tag or ""
    tag = "!!" + tag[len(CORE) :] if tag.startswith(CORE) else tag
    anchor = event.anchor or ""
    if isinstance(event, yaml.ScalarEvent):
        return event.value, line, STYLES[event.style], tag, anchor
    kind = "seq" if isinstance(event, yaml.SequenceStartEvent) else "map"
    return "", line, kind, tag, anchor


def _path(stack: list[list]) -> tuple:
    return (*stack[-1][1], stack[-1][2]) if stack else ()


def _advance(stack: list[list]) -> None:
    if not stack:
        return
    if stack[-1][0] == "seq":
        stack[-1][2] += 1
    else:
        stack[-1][2] = None
