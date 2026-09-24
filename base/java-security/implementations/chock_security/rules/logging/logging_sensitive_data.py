"""A secret written to the log reaches every place the log ships to: aggregators, dashboards,
tickets pasted with a stack trace -- far more readers than the code that handled it ever had."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "logging-sensitive-data"

_FACTS = facts("logging")["sensitive_data"]
_NAMES = frozenset(name.replace("_", "") for name in _FACTS["names"])

_LOGGER_CALL = re.compile(r"\b(?:log|logger|LOG|LOGGER)\.(?:trace|debug|info|warn|error)\(")
_QUOTED = re.compile(r'"[^"]*"')
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_MESSAGE = (
    "This log call's arguments include {name}, so the secret itself lands in the log rather "
    "than just a description of the event -- every log sink, dashboard and pasted ticket now "
    "carries it. Log an identifier instead, or mask the value before it reaches the logger. A "
    f"value that is already masked needs 'chock: allow {RULE_ID}' on this line."
)


#: A compound name's last two segments can spell the secret: `getApiKey` ends in api+key.
_COMPOUND = 2


def _segments(identifier: str) -> list[str]:
    """An identifier split on `_` and camelCase boundaries: `getPassword` -> ['get', 'password']."""
    spaced = _CASE_BOUNDARY.sub(" ", identifier.replace("_", " "))
    return [segment.lower() for segment in spaced.split() if segment]


def _is_sensitive(identifier: str) -> bool:
    """Whether this identifier IS a sensitive name, not merely contains one as a substring.

    `tokenType`, `tokenCount`, `passwordPolicy` and `tokenizer` must not match: none of them is
    a sensitive name itself, they only share a word fragment with one. `userPassword`,
    `db_password` and `getPassword` match on their last segment; `apiKey`, `accessToken` and
    `privateKey` match as a whole, since the sensitive name is itself two words run together.
    """
    whole = identifier.replace("_", "").lower()
    if whole in _NAMES:
        return True
    segments = _segments(identifier)
    if segments and segments[-1] in _NAMES:
        return True
    return len(segments) >= _COMPOUND and "".join(segments[-2:]) in _NAMES


def _call_arguments(line: str) -> str | None:
    match = _LOGGER_CALL.search(line)
    if match is None:
        return None
    return line[match.end() :].rstrip().removesuffix(";").rstrip(")")


def _is_masked(arguments: str) -> bool:
    return any(marker in arguments for marker in _FACTS["masked_markers"])


def _sensitive_identifier(arguments: str) -> str | None:
    """The first identifier outside any string literal that is itself a sensitive name."""
    unquoted = _QUOTED.sub('""', arguments)
    for match in _IDENTIFIER.finditer(unquoted):
        if _is_sensitive(match.group(0)):
            return match.group(0)
    return None


def scan(text: FileText) -> Iterator[Finding]:
    """Every logger call whose arguments name a secret outside the message string, unmasked."""
    for line_no, line in enumerate(text.lines, 1):
        arguments = _call_arguments(line)
        if arguments is None or _is_masked(arguments):
            continue
        identifier = _sensitive_identifier(arguments)
        if identifier is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(name=identifier))


RULE = Rule(
    id=RULE_ID,
    pack="logging",
    title="Secret value passed to a logger",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(log): a value named password|passwd|secret|token|apiKey|accessToken|refreshToken|"
        "privateKey|creditCard|cardNumber|cvv|ssn passed or concatenated into a logger call "
        "-- log an identifier, or mask the value first"
    ),
    refuses="a logger call whose concatenated or {}-argument identifier IS a secret name (its whole name, or its last camelCase/snake_case segment) and is not masked",
    silent_on=(
        "the same words only as part of a longer identifier (tokenType, tokenCount, "
        "passwordPolicy, tokenizer, tokens); the same name only inside the message's string "
        "literal; a value passed through mask(...)/redact(...) or already shown as ****"
    ),
)
