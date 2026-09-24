"""A key below today's recommended size is crackable within a realistic budget, not just in theory."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import methods
from chock_security.pack import Rule, facts

RULE_ID = "crypto-short-key"

_FACTS = facts("crypto")["short_key"]

_GET_INSTANCE = re.compile(r'(\w+)\s*=\s*(?:KeyPairGenerator|KeyGenerator)\.getInstance\(\s*"(\w+)"')
_INITIALIZE = re.compile(r"\b(\w+)\.(?:initialize|init)\(\s*(\d+)\b")
_PBE_KEY_SPEC = re.compile(r"new\s+PBEKeySpec\([^,]+,[^,]+,\s*(\d+)\s*,")

_MESSAGE_KEY = (
    "{algorithm} initialized at {size} bits falls under the {threshold}-bit floor that today's "
    "guidance treats as breakable within a realistic budget. Initialize it at {threshold} or "
    f"above. A key this small that only signs test fixtures needs 'chock: allow {RULE_ID}' on "
    "this line."
)
_MESSAGE_PBE = (
    "{iterations} PBKDF2/PBE iterations is far below the {threshold} this guidance treats as a "
    "floor, so a password hashed this way is cheap to brute-force offline. Raise the iteration "
    f"count, or move to Argon2/BCrypt. 'chock: allow {RULE_ID}' on this line if this only feeds "
    "a test vector."
)


def _threshold_for(algorithm: str) -> tuple[str, int] | None:
    if algorithm == _FACTS["ec_algorithm"]:
        return algorithm, _FACTS["ec_threshold"]
    if algorithm == _FACTS["aes_algorithm"]:
        return algorithm, _FACTS["aes_threshold"]
    if algorithm in _FACTS["keypair_algorithms"]:
        return algorithm, _FACTS["keypair_threshold"]
    return None


def _key_size_findings(text: FileText) -> Iterator[Finding]:
    for method in methods(text):
        algorithm_of: dict[str, str] = {}
        for _, line in method.body:
            match = _GET_INSTANCE.search(line)
            if match:
                algorithm_of[match.group(1)] = match.group(2)
        for line_no, line in method.body:
            match = _INITIALIZE.search(line)
            if not match:
                continue
            variable, size = match.group(1), int(match.group(2))
            algorithm = algorithm_of.get(variable)
            if algorithm is None:
                continue
            bounds = _threshold_for(algorithm)
            if bounds is not None and size < bounds[1]:
                yield Finding(
                    RULE_ID,
                    text.path,
                    line_no,
                    line,
                    _MESSAGE_KEY.format(algorithm=algorithm, size=size, threshold=bounds[1]),
                )


def _pbe_iteration_findings(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(text.lines, 1):
        match = _PBE_KEY_SPEC.search(line)
        if match and int(match.group(1)) < _FACTS["pbe_iteration_threshold"]:
            yield Finding(
                RULE_ID,
                text.path,
                line_no,
                line,
                _MESSAGE_PBE.format(iterations=match.group(1), threshold=_FACTS["pbe_iteration_threshold"]),
            )


def scan(text: FileText) -> Iterator[Finding]:
    """A key generator initialized below today's size floor, or a PBEKeySpec below the iteration floor."""
    yield from _key_size_findings(text)
    yield from _pbe_iteration_findings(text)


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Key or iteration count below today's size floor",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(initialize): KeyPairGenerator RSA|DSA|DH below 2048, EC below 224, KeyGenerator AES "
        "below 128, or PBEKeySpec below 10000 iterations -- raise it to the floor this pack documents"
    ),
    refuses="RSA/DSA/DH below 2048 bits, EC below 224 bits, AES below 128 bits, PBEKeySpec below 10000 iterations",
    silent_on="a literal size or iteration count at or above these floors; a size read from configuration rather than a literal",
    cwe=("CWE-326",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",),
)
