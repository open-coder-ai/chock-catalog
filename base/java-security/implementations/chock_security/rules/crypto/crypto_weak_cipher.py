"""A weak cipher algorithm or an ECB mode leaks patterns in the plaintext regardless of the key."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "crypto-weak-cipher"

_FACTS = facts("crypto")["cipher"]

_GET_INSTANCE = re.compile(r'Cipher\.getInstance\(\s*"([^"]+)"')

_MESSAGE = (
    "{transform} is a broken or improperly-configured cipher: {reason}. Use AES/GCM/NoPadding "
    "(or ChaCha20-Poly1305) with a fresh 12-byte SecureRandom nonce per encryption instead. A "
    f"transform you cannot change yet needs 'chock: allow {RULE_ID}' on this line and a plan to "
    "migrate it."
)


def _reason(transform: str) -> str | None:
    """Why this transform is weak, or None when it is not one this rule refuses."""
    if transform.startswith(_FACTS["rsa_ecb_prefix"]):
        return None  # RSA/ECB/OAEP... -- "ECB" here names RSA's single-block format, not a mode
    if _FACTS["weak_mode"] in transform:
        return "ECB reuses the same block pattern for identical plaintext blocks"
    if transform == _FACTS["bare_aes"]:
        return "no mode or padding is given, and the JCA default is AES/ECB/PKCS5Padding"
    algorithm = transform.split("/", 1)[0]
    if algorithm in _FACTS["weak_algorithms"]:
        return f"{algorithm} is small-block or broken and is not a safe cipher choice today"
    return None


def scan(text: FileText) -> Iterator[Finding]:
    """Every Cipher.getInstance() naming a weak algorithm, an ECB mode, or bare AES."""
    for line_no, line in enumerate(text.lines, 1):
        match = _GET_INSTANCE.search(line)
        if not match:
            continue
        reason = _reason(match.group(1))
        if reason is not None:
            message = _MESSAGE.format(transform=match.group(1), reason=reason)
            yield Finding(RULE_ID, text.path, line_no, line, message)


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="Weak cipher algorithm or ECB mode",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        'never(call): Cipher.getInstance(DES|DESede|RC2|RC4|ARCFOUR|Blowfish|.../ECB/...|bare "AES") '
        "-- use AES/GCM/NoPadding or ChaCha20-Poly1305 with a fresh SecureRandom nonce"
    ),
    refuses='DES, DESede, RC2, RC4/ARCFOUR, Blowfish; any `/ECB/` mode; bare `"AES"`',
    silent_on="AES/GCM/NoPadding; ChaCha20-Poly1305; AES/CBC/PKCS5Padding; RSA/ECB/OAEP* and RSA/ECB/PKCS1Padding",
)
