"""Directory listing turns a static-file mount into a browsable index of everything it serves."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.jakarta._config import not_spring

RULE_ID = "jakarta-directory-listing"

_FACTS = facts("jakarta")["directory_listing"]

_MESSAGE = (
    "This turns directory listing on, so anyone who requests the folder gets an index of every "
    "file it serves, including ones nobody meant to publish. Turn listing off and, if a directory "
    "index is genuinely wanted, generate it yourself from a known file list."
)


def _web_xml_listing(text: FileText) -> Iterator[int]:
    """`<param-name>listings</param-name>` followed within a few lines by a `true` value."""
    lines = text.lines
    for offset, line in enumerate(lines):
        if _FACTS["web_xml_param_name"] not in line:
            continue
        for follow_no, follow in enumerate(lines[offset + 1 : offset + 4], start=offset + 2):
            if _FACTS["web_xml_param_value_true"] in follow:
                yield follow_no
                break


def _keyed_true(text: FileText, key: str) -> Iterator[int]:
    """A `key ... true` pair on one line -- Jetty's `dirAllowed`, Undertow's `directory-listing`."""
    for line_no, line in enumerate(text.lines, 1):
        if key in line and _FACTS["true_token"] in line:
            yield line_no


def scan(text: FileText) -> Iterator[Finding]:
    """Directory listing turned on, in whichever server this file configures."""
    if not not_spring(text):
        return
    if text.suffix == ".xml":
        for line_no in _web_xml_listing(text):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)
        for line_no in _keyed_true(text, _FACTS["jetty_key"]):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)
    if text.suffix in {".xml", ".properties", ".conf"}:
        for line_no in _keyed_true(text, _FACTS["undertow_key"]):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)
    if text.suffix in {".java", ".kt"}:
        for line_no, line in enumerate(text.lines, 1):
            if _FACTS["vertx_call"] in line:
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="Directory listing enabled",
    suffixes=(".xml", ".properties", ".conf", ".java", ".kt"),
    scan=scan,
    constraint=(
        "never(enable): web.xml listings=true|Jetty dirAllowed=true|Undertow directory-listing=true|"
        "StaticHandler.setDirectoryListing(true) -- turn listing off"
    ),
    refuses="directory listing turned on, in servlet, Jetty, Undertow or Vert.x/Quarkus config",
    silent_on="listing left off or explicitly false; Spring code",
)
