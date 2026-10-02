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
OPENSSH_MAGIC = b"openssh-key-v1\0"
PUTTY = re.compile(r"(?m)^PuTTY-User-Key-File-\d+:")
PUTTY_CIPHER = re.compile(r"(?m)^Encryption:[ \t]*(\S*)")
#: DER, from the first byte: SEQUENCE, a length of one to four bytes (some replaced), then a version.
PKCS12 = re.compile(r"0[\s\S]{1,4}?\x02\x01\x030")
DER_KEY = re.compile(r"0[\s\S]{1,4}?\x02\x01(?:\x00[0\x02]|\x01[0\x04])")
#: JKS (FEEDFEED) and JCEKS (CECECECE) magic decode to four U+FFFD; version 1|2, a count under 65536,
#: then the first entry's tag (1 private key, 2 trusted certificate).
KEYSTORE = re.compile("\\ufffd{4}\\x00\\x00\\x00[\\x01\\x02]\\x00\\x00[\\s\\S]{2}\\x00\\x00\\x00([\\x01\\x02])")
#: A plain (unencrypted) DER private key's first bytes: SEQUENCE, length, INTEGER version 0 or 1.
PLAIN_DER = re.compile(rb"\x30[\s\S]{1,4}?\x02\x01[\x00\x01]")
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
        closing = ends.get(match[1], [])
        at = bisect.bisect_left(closing, match.end())
        stop = min(
            closing[at] if at < len(closing) else len(text),
            starts[index + 1].start() if index + 1 < len(starts) else len(text),
            match.end() + MAX_BODY,
        )
        body = text[match.end() : stop]
        if body_size(body) >= MIN_BODY:
            level = ASK if encrypted(match[1], body) else BLOCK
            found.append(Finding(KEYS, line_of(text, match.start()), f"private key block ({match[1]})", body, level))
    return found


def encrypted(label: str, body: str) -> bool:
    """Whether a key block is passphrase-protected, judged by its bytes: a label or header alone never says so.

    OpenSSH names its cipher; an ENCRYPTED PRIVATE KEY (PKCS#8) opens with an algorithm SEQUENCE where a
    plain key has its version; legacy Proc-Type/DEK-Info headers count only over bytes that are not a
    plain DER key. A plaintext key relabelled or given headers stays a plaintext key (block).
    """
    raw = decoded(body)
    if label == "OPENSSH PRIVATE KEY":
        return openssh_cipher(raw) not in (None, b"none")
    if label == "ENCRYPTED PRIVATE KEY":
        return sequence_first(raw)
    legacy = "Proc-Type: 4,ENCRYPTED" in body and "DEK-Info:" in body
    return legacy and not PLAIN_DER.match(raw)


def decoded(body: str) -> bytes:
    """The first bytes of a block's base64 body (whole quads, padding dropped: never raises)."""
    chars = "".join(body_lines(body)).replace("=", "")[:128]
    return base64.b64decode(chars[: len(chars) // 4 * 4])


def sequence_first(raw: bytes) -> bool:
    """A DER SEQUENCE whose first element is itself a SEQUENCE (EncryptedPrivateKeyInfo's algorithm)."""
    if len(raw) < 2 or raw[0] != 0x30:  # noqa: PLR2004 -- tag and length
        return False
    header = 2 + (raw[1] & 0x7F if raw[1] & 0x80 else 0)
    return len(raw) > header and raw[header] == 0x30  # noqa: PLR2004 -- SEQUENCE tag


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
    if store := KEYSTORE.match(text):
        if store[1] == "\x01":
            return [Finding(KEYS, 1, "Java keystore holding a private key", text)]
        return [Finding(KEYS, 1, "Java keystore whose first entry is a certificate (a truststore?)", text, ASK)]
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
