"""Host allowlist entries and matching with explicit semantics: an entry names one host, or '*.' and a
domain for its subdomains only; nothing matches by substring, prefix or suffix text.

  example.com    matches example.com (any case, IDN or trailing-dot spelling) and nothing else
  *.example.com  matches a.example.com and a.b.example.com; never example.com, evilexample.com
                 or example.com.evil.net
  192.0.2.1, [2001:db8::1]  match that address in any spelling the hosts module reads; no CIDR

Refused entries (UnparseableError): a bare '*', '*' anywhere but a leading '*.', a wildcard over an IP
address or over a single label ('*.com'). Without the Public Suffix List a wildcard over a public
suffix such as '*.co.uk' is not detected: whoever edits the allowlist owns that choice.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hosts import DOMAIN, Host, UnparseableError, normalize_host

__all__ = ["Entry", "matches", "parse_allowlist", "parse_entry", "same_host"]

WILDCARD = "*."
BOM = "\ufeff"
BLANKS = " \t"


@dataclass(frozen=True)
class Entry:
    """One allowlist entry: `host` itself, or with `subdomains` every host below it (and not it)."""

    host: Host
    subdomains: bool = False


def parse_entry(text: str) -> Entry:
    """An entry as written in an allowlist; UnparseableError for anything the module docstring refuses."""
    if not isinstance(text, str):
        msg = f"entry must be str, not {type(text).__name__}"
        raise TypeError(msg)
    subdomains = text.startswith(WILDCARD)
    body = text[len(WILDCARD) :] if subdomains else text
    if "*" in body:
        msg = f"{text!r}: '*' is allowed only as a leading '*.' label"
        raise UnparseableError(msg)
    host = normalize_host(body)
    if subdomains and (host.kind != DOMAIN or "." not in host.name):
        msg = f"{text!r}: a wildcard needs a domain of two or more labels below it"
        raise UnparseableError(msg)
    return Entry(host, subdomains)


def matches(host: Host | str, entry: Entry | str) -> bool:
    """Whether `host` is allowed by `entry`; a string is normalised first and may raise UnparseableError."""
    host = host if isinstance(host, Host) else normalize_host(host)
    entry = entry if isinstance(entry, Entry) else parse_entry(entry)
    if entry.subdomains:
        return host.kind == DOMAIN and host.name.endswith("." + entry.host.name)
    return (host.kind, host.name) == (entry.host.kind, entry.host.name)


def same_host(a: Host | str, b: Host | str) -> bool:
    """Whether two hosts normalise to the same host; names are compared, never resolved."""
    a = a if isinstance(a, Host) else normalize_host(a)
    b = b if isinstance(b, Host) else normalize_host(b)
    return (a.kind, a.name) == (b.kind, b.name)


def parse_allowlist(text: str) -> tuple[Entry, ...]:
    """Entries of an allowlist file: one per '\\n'-separated line, '#' starts a comment, blank lines skipped.

    Any unparseable line makes the whole file unparseable (message names the line), so a typo can
    neither drop an entry silently nor widen one. An empty result is the caller's to refuse.
    """
    entries: list[Entry] = []
    for number, line in enumerate(text.removeprefix(BOM).split("\n"), 1):
        body = line.removesuffix("\r").partition("#")[0].strip(BLANKS)
        if not body:
            continue
        try:
            entries.append(parse_entry(body))
        except UnparseableError as exc:
            msg = f"line {number}: {exc}"
            raise UnparseableError(msg) from None
    return tuple(entries)
