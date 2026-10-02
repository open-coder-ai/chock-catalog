"""A host name or address normalised for comparison, read the way the URL Standard's host parser reads it
(https://url.spec.whatwg.org/#host-parsing); input that clients may read as different hosts is refused.

Never resolves a name (no DNS): two names of one machine stay different hosts. IPv4 is accepted
only as a plain dotted quad (no hex, octal, leading zero, integer, short form or trailing dot): the URL
Standard reads those as an address, but Go, Java, curl or glibc read some as a DNS name, so they are
refused with the URL Standard reading in the message.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .idn import UnparseableError, flags, to_ascii

__all__ = ["Host", "UnparseableError", "normalize_host"]

MAX_INPUT = 1024
MAX_NAME = 253
MAX_PARTS = 4
MAX_BYTE = 255
DOMAIN = "domain"
IPV4 = "ipv4"
IPV6 = "ipv6"
#: Flags beside the idn module's IDN, MIXED_SCRIPT and CONFUSABLE.
PERCENT_ENCODED = "percent-encoded"
IPV4_MAPPED = "ipv4-mapped"
IPV4_EMBEDDED = "ipv4-embedded"

LABEL = re.compile(r"[a-z0-9_-]{1,63}")
DECIMAL = re.compile(r"[0-9]+")
HEX = re.compile(r"0[xX][0-9A-Fa-f]*")
OCTAL = re.compile(r"0[0-7]+")
PERCENT = re.compile(rb"%([0-9A-Fa-f]{2})")
ZONE = re.compile(r"[A-Za-z0-9._~-]{1,64}")
#: IPv6 prefixes that carry an IPv4 address a translator or tunnel may deliver to: NAT64 (RFC 6052,
#: RFC 8215) and IPv4-compatible (RFC 4291, deprecated). 6to4 and Teredo come from ipaddress itself.
EMBEDDING = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("::/96"),
)


@dataclass(frozen=True)
class Host:
    """`name` is canonical for `kind`: lowercase ASCII (A-labels) without a trailing dot, a dotted-quad
    IPv4 address, or a compressed IPv6 address without brackets (a zone id kept after '%')."""

    name: str
    kind: str
    flags: frozenset[str] = field(default_factory=frozenset)


def normalize_host(text: str) -> Host:
    """The canonical host for a bare host: a name, an IPv4 form, or an IPv6 address with or without brackets.

    No port, userinfo or scheme: those make the input unparseable here (parse a URL with urls.parse_url).
    """
    if not isinstance(text, str):
        msg = f"host must be str, not {type(text).__name__}"
        raise TypeError(msg)
    if len(text) > MAX_INPUT:
        msg = f"host longer than {MAX_INPUT} characters"
        raise UnparseableError(msg)
    if text.startswith("["):
        if not text.endswith("]"):
            msg = "'[' without a closing ']'"
            raise UnparseableError(msg)
        return _ipv6(text[1:-1], "%25")
    if ":" in text:
        return _ipv6(text, "%")
    if "%" not in text:
        return _domain(text, frozenset())
    return _domain(_percent_decode(text), frozenset({PERCENT_ENCODED}))


def _percent_decode(text: str) -> str:
    """One round of %XX decoding, as the host parser does; a stray '%' or a non-UTF-8 result raises."""
    raw = text.encode("utf-8", "surrogatepass")
    if PERCENT.sub(b"", raw).count(b"%"):
        msg = "a '%' not followed by two hex digits"
        raise UnparseableError(msg)
    try:
        return PERCENT.sub(lambda m: bytes.fromhex(m[1].decode("ascii")), raw).decode("utf-8")
    except UnicodeDecodeError:
        msg = "percent-encoding that does not decode to UTF-8"
        raise UnparseableError(msg) from None


def _domain(text: str, seen: frozenset[str]) -> Host:
    if not text:
        msg = "empty host"
        raise UnparseableError(msg)
    name = to_ascii(text)
    name = name.removesuffix(".")
    labels = name.split(".")
    if len(name) > MAX_NAME:
        msg = f"host longer than {MAX_NAME} characters"
        raise UnparseableError(msg)
    bad = next((label for label in labels if not LABEL.fullmatch(label)), None)
    if bad is not None:
        msg = f"label {bad!r} is empty, too long, or holds a character outside a-z 0-9 '-' '_'"
        raise UnparseableError(msg)
    if DECIMAL.fullmatch(labels[-1]) or HEX.fullmatch(labels[-1]):
        return _ipv4(labels, seen, written=text)
    return Host(name, DOMAIN, seen | flags(labels))


def _ipv4(parts: list[str], seen: frozenset[str], written: str) -> Host:
    """A dotted quad written canonically; every other numeric form is refused, naming the URL Standard reading."""
    value = _value(parts)
    if value is None:
        msg = "the last label is a number, but the host is not an IPv4 address"
        raise UnparseableError(msg)
    name = str(ipaddress.IPv4Address(value))
    if name != written:
        msg = (
            f"IPv4 not written as a plain dotted quad: the URL Standard and inet_aton read {name}, "
            "while Go, Java or curl read a DNS name or another address"
        )
        raise UnparseableError(msg)
    return Host(name, IPV4, seen)


def _value(parts: list[str]) -> int | None:
    """The URL Standard's IPv4 parser (hex, octal, 1-4 parts); None where it fails."""
    if len(parts) > MAX_PARTS:
        return None
    numbers = [_number(part) for part in parts]
    if None in numbers:
        return None
    *high, last = [n for n in numbers if n is not None]
    if any(n > MAX_BYTE for n in high) or last >= (MAX_BYTE + 1) ** (MAX_PARTS - len(high)):
        return None
    return sum(n << (8 * (3 - i)) for i, n in enumerate(high)) + last


def _number(part: str) -> int | None:
    if HEX.fullmatch(part):
        return int(part[2:] or "0", 16)
    if not DECIMAL.fullmatch(part):
        return None
    if len(part) > 1 and part.startswith("0"):
        return int(part, 8) if OCTAL.fullmatch(part) else None
    return int(part)


def _ipv6(inner: str, zone_mark: str) -> Host:
    address, marked, zone = inner.partition(zone_mark)
    if "%" in address or (marked and not ZONE.fullmatch(zone)):
        msg = f"a zone id must be written '{zone_mark}' then letters, digits or '._~-'"
        raise UnparseableError(msg)
    try:
        ip = ipaddress.IPv6Address(address)
    except ValueError:
        msg = f"{address!r} is not an IPv6 address"
        raise UnparseableError(msg) from None
    if ip.ipv4_mapped is not None:
        if marked:
            msg = "a zone id on an IPv4-mapped address"
            raise UnparseableError(msg)
        return Host(str(ip.ipv4_mapped), IPV4, frozenset({IPV4_MAPPED}))
    embeds = ip.sixtofour or ip.teredo or (any(ip in net for net in EMBEDDING) and int(ip) > 1)
    name = ip.compressed + (f"%{zone}" if marked else "")
    return Host(name, IPV6, frozenset({IPV4_EMBEDDED} if embeds else ()))
