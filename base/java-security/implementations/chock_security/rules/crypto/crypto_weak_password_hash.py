"""A fast, unsalted general-purpose digest is not a password hash: it invites offline cracking."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "crypto-weak-password-hash"

_FACTS = facts("crypto")["password_hash"]
_NAMES = frozenset(_FACTS["password_names"])

_GET_INSTANCE = re.compile(r'(\w+)\s*=\s*MessageDigest\.getInstance\(\s*"([^"]+)"')
_DIGEST_CALL = re.compile(r"\b(\w+)\.(?:update|digest)\(([^)]*)\)")
_DIGEST_UTILS_CALL = re.compile(r"(DigestUtils\.\w+Hex)\(([^)]*)\)")
_QUOTED = re.compile(r'"[^"]*"')
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_MESSAGE = (
    "{what} hashes {value}, which names a password, with a fast general-purpose digest that a "
    "modern GPU tries billions of times a second -- it is not a password hash. Use BCrypt, "
    "Argon2, PBKDF2 or SCrypt, which are deliberately slow and salted. A digest that is not "
    f"really hashing a password needs 'chock: allow {RULE_ID}' on this line."
)


def _segments(identifier: str) -> list[str]:
    spaced = _CASE_BOUNDARY.sub(" ", identifier.replace("_", " "))
    return [segment.lower() for segment in spaced.split() if segment]


def _is_password_named(identifier: str) -> bool:
    """Whether this identifier IS a password name, not merely mentions one somewhere in the file.

    `hashPassword`'s own parameter (`password`), `userPassword` and `getPassword()` match; an
    unrelated identifier that merely shares a file with the word "password" in a log message
    does not -- that word never reaches this check, because it never becomes a digest argument.
    """
    whole = identifier.replace("_", "").lower()
    if whole in _NAMES:
        return True
    segments = _segments(identifier)
    return bool(segments) and segments[-1] in _NAMES


def _password_argument(arguments: str) -> str | None:
    """The first identifier in this call's argument list that is itself a password name."""
    unquoted = _QUOTED.sub('""', arguments)
    for match in _IDENTIFIER.finditer(unquoted):
        if _is_password_named(match.group(0)):
            return match.group(0)
    return None


def scan(text: FileText) -> Iterator[Finding]:
    """A weak digest whose actual input -- the argument it hashes -- is named as a password.

    Tracked across the whole file rather than method by method: a digest object is created on
    one line and fed on another, and the two rarely share a line. What must NOT decide this is
    whether the word "password" appears anywhere in the surrounding method -- a log statement
    two lines away saying "password changed" must not turn an unrelated checksum into a match.
    """
    weak_digest: dict[str, tuple[int, str]] = {}
    reported: set[int] = set()
    for line_no, line in enumerate(text.lines, 1):
        assignment = _GET_INSTANCE.search(line)
        if assignment and assignment.group(2) in _FACTS["digest_algorithms"]:
            weak_digest[assignment.group(1)] = (line_no, line)
        for call in _DIGEST_CALL.finditer(line):
            variable, argument = call.group(1), call.group(2)
            source = weak_digest.get(variable)
            if source is None or source[0] in reported:
                continue
            value = _password_argument(argument)
            if value is not None:
                reported.add(source[0])
                yield Finding(
                    RULE_ID, text.path, source[0], source[1], _MESSAGE.format(what="This digest", value=value)
                )
        for du_call in _DIGEST_UTILS_CALL.finditer(line):
            call_name, argument = du_call.groups()
            if f"{call_name}(" not in _FACTS["digest_utils_calls"] or line_no in reported:
                continue
            value = _password_argument(argument)
            if value is not None:
                reported.add(line_no)
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(what=call_name, value=value))


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Fast digest used to hash a password",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(hash): MessageDigest MD5|SHA-1|SHA-256 or DigestUtils.md5Hex|sha1Hex|sha256Hex "
        "over an argument that IS a password name -- use BCrypt|Argon2|PBKDF2|SCrypt, which are "
        "slow and salted"
    ),
    refuses="MD5/SHA-1/SHA-256 (or DigestUtils' hex forms) whose digested/updated argument is itself named password/passwd/pwd (whole name or last segment)",
    silent_on=(
        "the same digests fed a value not named as a password (a checksum, an ETag, file "
        "bytes), even in a method that separately logs something about a password; BCrypt/Argon2/PBKDF2/SCrypt"
    ),
)
