"""Exposing every actuator endpoint publishes heapdump, env and threaddump alongside health."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-actuator-wildcard-exposure"

_FACTS = facts("java")["actuator"]

_MESSAGE = (
    "Exposing every actuator endpoint publishes heapdump, env, threaddump and mappings, not "
    "just health -- a heap dump carries whatever credentials the process held in memory. Name "
    "the endpoints this service actually serves, for example health,info,metrics."
)


def _flattened_wildcard(line: str) -> bool:
    """The dotted, single-line form -- `management.endpoints.web.exposure.include=*` or the
    same key flattened in YAML. Specific enough on its own: nothing legitimate spells this key."""
    return _FACTS["wildcard"] in line and _FACTS["properties_key"] in line


def _nested_wildcard_lines(text: FileText) -> Iterator[int]:
    """A wildcard `include:` YAML key, but only inside the block a sibling `exposure:` key
    opens -- scanned by indentation, not by the bare substring `include:`. That key is
    ordinary YAML anywhere else in a file (a coverage tool's own `include:` glob, for one),
    and a file merely mentioning the word "exposure" in a comment must not turn it into this
    rule's key.
    """
    exposure_indent: int | None = None
    for line_no, line in enumerate(text.lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if exposure_indent is not None and indent <= exposure_indent:
            exposure_indent = None  # a line back at or above that depth closes the block
        if stripped.startswith("exposure:"):
            exposure_indent = indent
            continue
        if (
            exposure_indent is not None
            and indent > exposure_indent
            and _FACTS["yaml_key"] in stripped
            and _FACTS["wildcard"] in stripped
        ):
            yield line_no


def scan(text: FileText) -> Iterator[Finding]:
    """A wildcard include, in a file that is configuring actuator exposure at all."""
    if not text.holds(_FACTS["exposure_marker"]):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _flattened_wildcard(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)
    if text.suffix in {".yml", ".yaml"}:
        for line_no in _nested_wildcard_lines(text):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Every actuator endpoint exposed",
    suffixes=(".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        "never(expose): management.endpoints.web.exposure.include=* "
        "-- it publishes heapdump and env; name the endpoints served"
    ),
    refuses="`exposure.include=*` in properties or YAML",
    silent_on="named endpoints; a wildcard `include:` outside actuator config",
)
