"""A wildcard CORS origin with credentials is refused by every browser; it never does what it looks
like it does, whether it is set as a raw header, a Vert.x handler or a Quarkus/Micronaut key."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.jakarta._config import flat_value, not_spring, yaml_value

RULE_ID = "jakarta-cors-wildcard-credentials"

_FACTS = facts("jakarta")["cors"]

_MESSAGE = (
    "A wildcard origin together with credentials is refused by every browser, so this "
    "configuration never does what it looks like it does. Name the origins that may send "
    "credentials, or keep the wildcard and drop credentials."
)


def _java_credentials(text: FileText) -> bool:
    return text.holds(_FACTS["vertx_credentials"]) or any(
        _FACTS["credentials_header_key"] in line and _FACTS["credentials_true"] in line
        for line in text.lines
    )


def _java_wildcard_lines(text: FileText) -> Iterator[int]:
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["vertx_cors_create_wildcard"] in line:
            yield line_no
        elif _FACTS["origin_header_key"] in line and f'"{_FACTS["wildcard"]}"' in line:
            yield line_no


def _quarkus_credentials(text: FileText) -> bool:
    if text.suffix == ".properties":
        return any(v == "true" for _, _, v in flat_value(text, _FACTS["quarkus_credentials_key"]))
    return any(v == "true" for _, _, v in yaml_value(text, _FACTS["quarkus_credentials_key"]))


def _quarkus_wildcard_lines(text: FileText) -> Iterator[int]:
    reader = flat_value if text.suffix == ".properties" else yaml_value
    for line_no, _, value in reader(text, _FACTS["quarkus_origins_key"]):
        if value in {"*", "/.*/"}:
            yield line_no


def _has_micronaut_cors_block(text: FileText) -> bool:
    """A `micronaut: ... server: ... cors:` block -- checked by presence, not by nested lookup,
    since the marker is only ever used to gate a plain key search on the rest of the file."""
    return text.holds("micronaut:") and text.holds("cors:")


def _micronaut_wildcard_lines(text: FileText) -> Iterator[int]:
    """The `allowed-origins` key inside a `micronaut.server.cors` block, set to a wildcard."""
    if not _has_micronaut_cors_block(text):
        return
    lines = text.lines
    for offset, line in enumerate(lines):
        if _FACTS["micronaut_origins_key"] not in line.strip().partition(":")[0]:
            continue
        if "*" in line:
            yield offset + 1
            continue
        # a YAML sequence written on the following, more-indented lines
        indent = len(line) - len(line.lstrip(" "))
        for follow_no, follow in enumerate(lines[offset + 1 :], start=offset + 2):
            stripped = follow.strip()
            if not stripped:
                continue
            follow_indent = len(follow) - len(follow.lstrip(" "))
            if follow_indent <= indent or not stripped.startswith("-"):
                break
            if "*" in stripped:
                yield follow_no
                break


def _micronaut_credentials(text: FileText) -> bool:
    if not _has_micronaut_cors_block(text):
        return False
    return any(
        _FACTS["micronaut_credentials_key"] in line.strip().partition(":")[0] and "true" in line
        for line in text.lines
    )


def scan(text: FileText) -> Iterator[Finding]:
    """Every wildcard origin, but only where the same file also turns credentials on."""
    if not not_spring(text):
        return
    if text.suffix in {".java", ".kt"}:
        if not _java_credentials(text):
            return
        for line_no in _java_wildcard_lines(text):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)
        return
    if text.suffix in {".properties", ".yml", ".yaml"}:
        if _quarkus_credentials(text):
            for line_no in _quarkus_wildcard_lines(text):
                yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)
        if text.suffix in {".yml", ".yaml"} and _micronaut_credentials(text):
            for line_no in _micronaut_wildcard_lines(text):
                yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="Wildcard CORS origin with credentials",
    suffixes=(".java", ".kt", ".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        'never(pair): CORS origin "*" (raw header, Vert.x CorsHandler, quarkus.http.cors.origins, '
        "micronaut allowed-origins) with credentials enabled -- name the origins instead"
    ),
    refuses="a wildcard CORS origin **with** credentials enabled, in a non-Spring file",
    silent_on="a wildcard alone; a named origin; credentials without a wildcard; Spring code",
)
