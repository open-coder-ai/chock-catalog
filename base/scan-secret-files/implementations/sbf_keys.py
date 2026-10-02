"""Private keys by content, whatever the file is called: PEM blocks, PuTTY keys, DER and keystore headers, browser stores.

At commit the engine hands a staged blob over as UTF-8 text with invalid bytes replaced (U+FFFD), so
binary signatures are matched on what survives that: ASCII control bytes and replacement characters.
"""

from __future__ import annotations

import base64
import bisect
import re

from sbf_core import ASK, BLOCK, BROWSER, KEYS, MIN_BODY, Finding, body_lines, body_size, line_of

#: PEM labels of private keys (RFC 7468 and OpenSSL/OpenSSH/PGP practice) and OpenVPN's static key.
LABEL = r"((?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V1)"
BEGIN = re.compile(r"-----BEGIN " + LABEL + "-----")
END = re.compile(r"-----END " + LABEL + "-----")
#: An unterminated block is read this far (or to the next BEGIN), so every byte is read about once.
MAX_BODY = 16384
#: ENDs tried per BEGIN (a forged early END, then the real one): bounds the work per block.
MAX_ENDS = 8
OPENSSH_MAGIC = b"openssh-key-v1\0"
PUTTY = re.compile(r"(?m)^PuTTY-User-Key-File-\d+:")
PUTTY_CIPHER = re.compile(r"(?m)^Encryption:[ \t]*(\S*)")
#: DER, from the first byte: SEQUENCE, a length of one to four bytes (some replaced), then a version.
PKCS12 = re.compile(r"0[\s\S]{1,4}?\x02\x01\x030")
DER_KEY = re.compile(r"0[\s\S]{1,4}?\x02\x01(?:\x00[0\x02]|\x01[0\x04])")
#: JKS (FEEDFEED) and JCEKS (CECECECE) magic decode to four U+FFFD; version 1|2, a count under 65536,
#: then the first entry's tag. Whether it holds a key is read from the key-protector OID.
KEYSTORE = re.compile("\\ufffd{4}\\x00\\x00\\x00[\\x01\\x02]\\x00\\x00[\\s\\S]{2}\\x00\\x00\\x00[\\x01\\x02]")
#: A plaintext private key in DER, at any offset: a PKCS#8 version and key algorithm OID (RSA, EC, DSA,
#: X25519/Ed25519), a PKCS#1 version and modulus, a SEC1 version and key octets.
PLAIN_ANYWHERE = re.compile(
    rb"\x02\x01[\x00\x01]\x30[\s\S]{1,2}\x06[\s\S]{1,2}"
    rb"(?:\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01|\x2a\x86\x48\xce\x3d\x02\x01|\x2a\x86\x48\xce\x38\x04\x01|\x2b\x65[\x6e\x70])"
    rb"|\x02\x01\x00\x02[\x81\x82]|\x02\x01\x01\x04[\x20\x30\x42]"
)
#: Password-based encryption algorithm OIDs: PKCS#5 (PBES1, PBES2) and PKCS#12.
PBE_OID = re.compile(rb"\x2a\x86\x48\x86\xf7\x0d\x01(?:\x05|\x0c\x01)")
OPENSSH_TYPES = re.compile(rb"ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-")
MAX_DECODE = 1 << 16
#: Java's key-protector OIDs (bytes under 0x80, so they survive the lossy decode): a store that holds a key.
KEY_PROTECTORS = ("\x2b\x06\x01\x04\x01\x2a\x02\x11\x01\x01", "\x2b\x06\x01\x04\x01\x2a\x02\x13\x01")
SQLITE = "SQLite format 3\x00"
#: Tables a browser keeps credentials in: by name, or by the column that holds the secret.
TABLE = re.compile(r'CREATE TABLE "?(\w+)')
BROWSER_TABLES = frozenset({"moz_cookies", "moz_logins", "nssPrivate"})
SECRET_COLUMNS = {"cookies": "encrypted_value", "logins": "password_value"}


def judge(text: str) -> list[Finding]:
    """Every private key and credential store the content itself shows."""
    return [*pem_blocks(text), *putty(text), *binary(text)]


def pem_blocks(text: str) -> list[Finding]:
    """Each PEM private-key block with a body of at least MIN_BODY base64 characters; an encrypted one asks."""
    starts = list(BEGIN.finditer(text))
    ends: dict[str, list[int]] = {}
    for match in END.finditer(text):
        ends.setdefault(match[1], []).append(match.start())
    found = []
    for index, match in enumerate(starts):
        limit = min(starts[index + 1].start() if index + 1 < len(starts) else len(text), match.end() + MAX_BODY)
        same = ends.get(match[1], [])
        at = bisect.bisect_left(same, match.end())
        closing = [end for end in same[at : at + MAX_ENDS] if end < limit]
        # An END forged straight after BEGIN must not cut the body short: try each END up to the next BEGIN.
        for end, terminated in [*((end, True) for end in closing), (limit, False)]:
            body = text[match.end() : end]
            if body_size(body, terminated=terminated) >= MIN_BODY:
                level = ASK if encrypted(match[1], body, terminated=terminated) else BLOCK
                found.append(
                    Finding(KEYS, line_of(text, match.start()), f"private key block ({match[1]})", body, level)
                )
                break
    return found


def encrypted(label: str, body: str, *, terminated: bool = True) -> bool:
    """Whether a key block is passphrase-protected, judged by its bytes: a label or header alone never says so.

    A plaintext key structure anywhere in the body (at any of the four base64 alignments) refuses,
    whatever the label or headers claim. Otherwise: OpenSSH names a cipher and carries its key type
    once (a plaintext private section repeats it); PKCS#8 names a password-based encryption algorithm;
    a legacy key has Proc-Type and DEK-Info headers.
    """
    raws = alignments(body, terminated=terminated)
    if any(PLAIN_ANYWHERE.search(raw) for raw in raws):
        return False
    if label == "OPENSSH PRIVATE KEY":
        return openssh_cipher(raws[0]) not in (None, b"none") and len(OPENSSH_TYPES.findall(raws[0])) < 2  # noqa: PLR2004
    if label == "ENCRYPTED PRIVATE KEY":
        return any(PBE_OID.search(raw[:64]) for raw in raws)
    return "Proc-Type: 4,ENCRYPTED" in body and "DEK-Info:" in body


def alignments(body: str, *, terminated: bool = True) -> list[bytes]:
    """The body decoded from each of its four base64 alignments, to its last byte (bounded: never raises)."""
    chars = "".join(body_lines(body, terminated=terminated)).replace("=", "")[:MAX_DECODE]
    parts = (chars[shift:] for shift in range(4))
    return [base64.b64decode(part[: len(part) - (len(part) % 4 == 1)] + "==") for part in parts]


def openssh_cipher(raw: bytes) -> bytes | None:
    """The cipher name an openssh-key-v1 body starts with, or None when it does not decode as one."""
    if not raw.startswith(OPENSSH_MAGIC) or len(raw) < len(OPENSSH_MAGIC) + 4:
        return None
    size = int.from_bytes(raw[len(OPENSSH_MAGIC) : len(OPENSSH_MAGIC) + 4], "big")
    return raw[len(OPENSSH_MAGIC) + 4 : len(OPENSSH_MAGIC) + 4 + size]


def putty(text: str) -> list[Finding]:
    """A PuTTY private key file (.ppk format); one with a cipher other than none asks."""
    match = PUTTY.search(text)
    if match is None or "Private-Lines:" not in text:
        return []
    cipher = PUTTY_CIPHER.search(text)
    level = ASK if cipher and cipher[1] != "none" else BLOCK
    return [Finding(KEYS, line_of(text, match.start()), "PuTTY private key", text, level)]


def binary(text: str) -> list[Finding]:
    """DER private keys, PKCS#12 and Java keystores by their first bytes; browser stores by their SQLite schema."""
    for pattern, what in ((PKCS12, "PKCS#12 key store"), (DER_KEY, "DER private key")):
        if pattern.match(text):
            return [Finding(KEYS, 1, what, text)]
    if KEYSTORE.match(text):
        if any(oid in text for oid in KEY_PROTECTORS):
            return [Finding(KEYS, 1, "Java keystore holding a private key", text)]
        return [Finding(KEYS, 1, "Java keystore with no key entry seen (a truststore?)", text, ASK)]
    if text.startswith(SQLITE) and browser_tables(text):
        return [Finding(BROWSER, 1, "browser cookie or password database", text)]
    return []


def browser_tables(text: str) -> bool:
    """A browser's credential table in a SQLite schema; each statement is read to the next one, at most 4000 characters."""
    tables = list(TABLE.finditer(text))
    for index, table in enumerate(tables):
        stop = min(tables[index + 1].start() if index + 1 < len(tables) else len(text), table.end() + 4000)
        column = SECRET_COLUMNS.get(table[1])
        if table[1] in BROWSER_TABLES or (column and column in text[table.end() : stop]):
            return True
    return False
