"""A signature algorithm built on MD5 or SHA-1 is forgeable: both hashes have practical chosen-
prefix collision attacks, so a signature over one proves nothing about which document was signed."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "crypto-weak-signature-algorithm"

_FACTS = facts("crypto")["signature"]

_GET_INSTANCE = re.compile(r'Signature\.getInstance\(\s*"([^"]+)"')

_MESSAGE = (
    '"{algorithm}" signs a hash (MD5 or SHA-1) with a practical chosen-prefix collision attack, '
    "so an attacker can craft two different documents that sign identically -- a signature over "
    "one says nothing about which was actually signed. Use SHA256withRSA, SHA256withECDSA, or "
    f"another SHA-2/SHA-3-based algorithm instead. An algorithm you cannot change yet needs "
    f"'chock: allow {RULE_ID}' on this line and a plan to migrate it."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every Signature.getInstance() naming an MD5- or SHA-1-based algorithm."""
    for line_no, line in enumerate(text.lines, 1):
        match = _GET_INSTANCE.search(line)
        if match and match.group(1) in _FACTS["weak_algorithms"]:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(algorithm=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Weak signature algorithm",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        'never(call): Signature.getInstance("MD2withRSA"|"MD5withRSA"|"MD5andMD2withRSA"|'
        '"SHA1withRSA"|"SHA1withDSA"|"SHA1withECDSA") -- use a SHA-2/SHA-3-based algorithm instead'
    ),
    refuses="Signature.getInstance() naming an MD2/MD5- or SHA-1-based signature algorithm",
    silent_on="SHA256withRSA, SHA256withECDSA, SHA384withRSA, SHA512withRSA, Ed25519, and any other SHA-2/SHA-3-based algorithm",
    cwe=("CWE-327",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",),
)
