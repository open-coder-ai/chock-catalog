"""The host and port a URL names, split the way the URL Standard splits one (https://url.spec.whatwg.org/);
a URL that parsers are known to split differently is refused, never read one way.

Refused: tabs, newlines and other controls inside; a special scheme ('https:') not followed by exactly
'//'; a backslash before the path (the URL Standard reads it as '/', others as part of the userinfo);
more than one '@'; an '@' after a '?' or '#' that ends the host; userinfo holding a percent-encoded
delimiter or a character NFKC maps to one (CVE-2019-9636); a port outside 0-65535, or any on file:.
A schemeless 'host[:port][/path]' or '//host' is read as curl reads it; its port is None unless written.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .hosts import Host, UnparseableError, normalize_host

__all__ = ["DEFAULT_PORTS", "Url", "parse_url"]

MAX_URL = 8192
#: The URL Standard's special schemes and their default ports (file has none).
DEFAULT_PORTS: dict[str, int | None] = {"ftp": 21, "file": None, "http": 80, "https": 443, "ws": 80, "wss": 443}
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
EDGE = "".join(map(chr, range(0x21)))
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
AUTHORITY_END = re.compile(r"[/?#]")
PORT = re.compile(r"[0-9]*")
MAX_PORT = 65535
#: Delimiters a client that applies NFKC to the whole URL would find in a fullwidth or compatibility form.
DELIMITERS = frozenset("/?#@:[]\\")
ENCODED_DELIMITER = re.compile(r"%(?:2[fF3]|3[fF]|40|5[cC])")


@dataclass(frozen=True)
class Url:
    """`scheme` is lowercase, or None when the input had none; `port` is the written port, else the
    scheme's default, else None; `userinfo` is True when an '@' put credentials (even empty) before the host."""

    scheme: str | None
    host: Host
    port: int | None
    userinfo: bool


def parse_url(text: str) -> Url:
    """Scheme, canonical host, port and whether credentials were embedded; UnparseableError when ambiguous."""
    if not isinstance(text, str):
        msg = f"URL must be str, not {type(text).__name__}"
        raise TypeError(msg)
    if len(text) > MAX_URL:
        msg = f"URL longer than {MAX_URL} characters"
        raise UnparseableError(msg)
    text = text.strip(EDGE)
    if CONTROL.search(text):
        msg = "a tab, newline or control character inside: the URL Standard deletes some, other clients keep them"
        raise UnparseableError(msg)
    scheme, rest = _split_scheme(text)
    end = AUTHORITY_END.search(rest)
    authority, after = (rest[: end.start()], rest[end.start() :]) if end else (rest, "")
    if "\\" in authority:
        msg = "a backslash before the path: the URL Standard reads it as '/', other parsers do not"
        raise UnparseableError(msg)
    if after.startswith(("?", "#")) and "@" in after:
        msg = "an '@' after the '?' or '#' that ends the host: parsers disagree on which host is meant"
        raise UnparseableError(msg)
    userinfo, at, hostport = authority.rpartition("@")
    if "@" in userinfo:
        msg = "more than one '@' before the host: parsers disagree on which one ends the userinfo"
        raise UnparseableError(msg)
    _check_userinfo(userinfo)
    host_text, port_text = _split_port(hostport)
    host = normalize_host(host_text)
    if scheme == "file" and port_text:
        msg = "a port on a file: URL, which the URL Standard refuses"
        raise UnparseableError(msg)
    return Url(scheme, host, _port(port_text, scheme), bool(at))


def _check_userinfo(userinfo: str) -> None:
    """Refuse userinfo that a client decoding or NFKC-normalising the URL first splits at another delimiter."""
    if ENCODED_DELIMITER.search(userinfo):
        msg = "userinfo holds a percent-encoded '/', '?', '#', '@' or '\\': clients that decode first read another host"
        raise UnparseableError(msg)
    if any(not c.isascii() and DELIMITERS & set(unicodedata.normalize("NFKC", c)) for c in userinfo):
        msg = "userinfo holds a character NFKC maps to a URL delimiter: clients that normalise first read another host"
        raise UnparseableError(msg)


def _split_scheme(text: str) -> tuple[str | None, str]:
    """(lowercase scheme or None, the text from the authority on)."""
    match = SCHEME.match(text)
    scheme = match[0][:-1].lower() if match else None
    if match and text[match.end() :].startswith("//"):
        rest = text[match.end() + 2 :]
    elif scheme in DEFAULT_PORTS:
        msg = f"'{scheme}:' not followed by exactly '//': the URL Standard skips slashes there, other parsers do not"
        raise UnparseableError(msg)
    elif text.startswith("//"):
        scheme, rest = None, text[2:]
    else:
        # No scheme, or 'name:' that is a host and port (curl reads 'localhost:8080' so).
        scheme, rest = None, text
    if rest.startswith(("/", "\\")):
        msg = "no host before the path"
        raise UnparseableError(msg)
    return scheme, rest


def _split_port(hostport: str) -> tuple[str, str]:
    """(host text, port text) split at the first ':' outside an IPv6 literal's brackets."""
    if hostport.startswith("["):
        close = hostport.find("]") + 1
        if not close or (not hostport.startswith(":", close) and close != len(hostport)):
            msg = "an IPv6 literal must be '[address]' or '[address]:port'"
            raise UnparseableError(msg)
        return hostport[:close], hostport[close + 1 :]
    host, _, port = hostport.partition(":")
    return host, port


def _port(text: str, scheme: str | None) -> int | None:
    if not text:
        return DEFAULT_PORTS.get(scheme) if scheme else None
    digits = text.lstrip("0") or "0"
    if not PORT.fullmatch(text) or len(digits) > len(str(MAX_PORT)) or int(digits) > MAX_PORT:
        msg = f"port {text[:16]!r} is not a number from 0 to {MAX_PORT}"
        raise UnparseableError(msg)
    return int(digits)
