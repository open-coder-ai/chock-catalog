"""A credential literal in source ships to everyone who has the source, forever, in every clone."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "crypto-hardcoded-credential"

_FACTS = facts("crypto")["hardcoded_credential"]

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("DriverManager.getConnection", re.compile(r'DriverManager\.getConnection\(\s*[^,]+,\s*[^,]+,\s*"([^"]*)"\s*\)')),
    (
        "new PasswordAuthentication",
        re.compile(r'new\s+PasswordAuthentication\(\s*[^,]+,\s*"([^"]*)"\s*\.toCharArray\(\)\s*\)'),
    ),
    (".setPassword", re.compile(r'\.setPassword\(\s*"([^"]*)"\s*\)')),
    ("new SecretKeySpec", re.compile(r'new\s+SecretKeySpec\(\s*"([^"]*)"\s*\.getBytes\(')),
    ("Algorithm.HMAC", re.compile(r'Algorithm\.HMAC(?:256|384|512)\(\s*"([^"]*)"\s*\)')),
)

_MESSAGE = (
    "{what} is a literal signing/connection secret written into the source, so it ships to "
    "everyone who has the repository and cannot be rotated without a new release. Read it from "
    "an environment variable, the configuration server, or a secrets vault instead. A placeholder "
    f"that carries no real secret needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every credential-shaped call whose secret argument is a non-empty string literal."""
    if _FACTS["test_path_marker"] in text.path:
        return
    for line_no, line in enumerate(text.lines, 1):
        for what, pattern in _PATTERNS:
            match = pattern.search(line)
            if match and match.group(1):
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(what=what))
                break


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Credential literal in source",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(write): DriverManager.getConnection|PasswordAuthentication|setPassword|"
        "SecretKeySpec|Algorithm.HMAC* with a non-empty string literal as the secret -- read it "
        "from environment, configuration, or a vault"
    ),
    refuses=(
        "a non-empty literal password/secret passed to DriverManager.getConnection, "
        "PasswordAuthentication, dataSource.setPassword, SecretKeySpec, or Algorithm.HMAC256/384/512"
    ),
    silent_on="the same calls given a variable, an env/config/vault read, or an empty string literal; anything under src/test/",
    cwe=("CWE-798", "CWE-321", "CWE-259"),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",),
)
