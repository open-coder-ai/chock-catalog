"""Findings, verdict classes and the URL, host and credential checks every registry-config reader shares."""

from __future__ import annotations

import bisect
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from functools import cached_property

from chock_scan.hostmatch import Entry, matches
from chock_scan.hosts import DOMAIN, Host, UnparseableError
from chock_scan.urls import parse_url

CREDENTIAL = "reg-npmrc-token"
HTTP = "reg-http-registry"
TLS = "reg-tls-off"
SCRIPTS = "reg-script-allow-weaken"
HOST = "reg-registry-host"
UNREADABLE = "reg-unreadable"
CONFUSION = "reg-confusion"
REDIRECT = "reg-overrides-redirect"
COOLDOWN = "reg-cooldown-absent"
VCS = "reg-vcs-weaken"
ALLOWLIST = "reg-allowlist-changed"
#: Rules with no legitimate form in a committed config: a new one blocks. Every other rule asks a person.
BLOCK = frozenset({CREDENTIAL, HTTP, TLS, SCRIPTS, HOST, UNREADABLE})

#: A value that names a secret held elsewhere: ${VAR}, ${env.X}, $VAR, %VAR%, ${{ secrets.X }}, {env:X}, env("X"),
#: Ruby's #{ENV["X"]}, Renovate's {{ secrets.X }}.
ENV_REF = re.compile(
    r"^\s*[\"']?(?:\$\{\{[^}]*\}\}|\$\{[A-Za-z_][A-Za-z0-9_.]*(?::?-|\?)?\}|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|%[A-Za-z_][A-Za-z0-9_]*%|\{env:[A-Za-z_][A-Za-z0-9_]*\}|env\(\s*[\"'][A-Za-z_][A-Za-z0-9_]*[\"']\s*\)"
    r"|#\{ENV(?:\[|\.fetch\(\s*)[\"'][A-Za-z_][A-Za-z0-9_]*[\"'][^}]*\}|\{\{\s*secrets\.[\w.]+\s*\}\})[\"']?\s*$"
)
#: Scheme prefixes package managers put before a URL (cargo's sparse+ and registry+, pip's git+).
PREFIX = re.compile(r"^(?:sparse|registry|git|hg|svn|bzr)\+", re.IGNORECASE)
#: Schemes that send what they fetch in clear text.
CLEAR = frozenset({"http", "ws", "ftp", "git", "svn"})
#: A URL: any scheme with '//', or a special scheme with anything after it (WHATWG reads 'https:\\h' and
#: 'https:h' as https://h, so those are URLs that parse_url then refuses as ambiguous).
SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|(?:https?|wss?|ftp|file):)", re.IGNORECASE)
AUTHORITY_END = re.compile(r"[/?#]")
QUOTES = "\"'"


#: Past this many findings in one file the gate stops reading it and reports one finding marked new.
MAX_PER_FILE = 2000
#: How far past the last match `line_of` looks for a setting's text: readers visit settings in document
#: order, so a bounded search keeps a file of many settings linear. A miss reports the last line found.
WINDOW = 8192


class TooManyError(Exception):
    """A file holds more findings than MAX_PER_FILE."""


@dataclass
class Ctx:
    """One file being judged: its path, its lines, the allowed registry hosts and the findings so far."""

    path: str
    text: str
    allow: tuple[Entry, ...] = ()
    out: list[dict] = field(default_factory=list)
    cursor: int = 0

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines() or [""]

    @cached_property
    def low(self) -> str:
        return self.text.lower()

    @cached_property
    def breaks(self) -> list[int]:
        return [m.start() for m in re.finditer("\n", self.text)]

    def line_at(self, pos: int) -> int:
        """The 1-based line holding offset `pos`."""
        return bisect.bisect_left(self.breaks, pos) + 1


def digest(text: str) -> str:
    """A short stable name for text that must not be echoed (a secret) or is too long to key on."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def norm(text: object) -> str:
    """A value as a key part: stripped, quotes removed, inner whitespace collapsed, cut to 200 characters."""
    return " ".join(str(text).strip().strip(QUOTES).split())[:200]


def add(ctx: Ctx, rule: str, line: int, key: tuple[str, str], message: str) -> None:
    """Record one finding keyed by rule, setting and detail; never by line, so a moved line stays the same finding."""
    setting, detail = key
    if len(ctx.out) >= MAX_PER_FILE:
        raise TooManyError
    ctx.out.append(
        {
            "key": f"{rule}|{setting}|{detail}",
            "path": ctx.path,
            "line": max(1, line),
            "rule": rule,
            "message": f"{rule}: {message}"[:300],
        }
    )


def line_of(ctx: Ctx, needle: str) -> int:
    """The line of the next occurrence of `needle` (case-insensitive) within WINDOW characters of the last one
    found, else within the first WINDOW characters, else the last line found. Only for messages: no key holds it."""
    wanted = needle.lower()
    for start in (ctx.cursor, 0):
        pos = ctx.low.find(wanted, start, start + WINDOW + len(wanted)) if wanted else -1
        if pos >= 0:
            ctx.cursor = pos
            break
    return ctx.line_at(ctx.cursor)


def literal(value: object) -> bool:
    """Whether a credential value is written out in the file rather than read from the environment."""
    text = norm(value)
    return bool(text) and not ENV_REF.match(str(value))


def secret(ctx: Ctx, line: int, setting: str, value: object) -> None:
    """A credential setting: a literal value is a finding, keyed and reported by digest, never echoed."""
    if literal(value):
        add(ctx, CREDENTIAL, line, (setting.lower(), digest(norm(value))), f"{setting} holds a literal credential")


def loopback(host: Host) -> bool:
    """localhost (and *.localhost, which resolvers keep on the machine), 127.0.0.0/8 or ::1."""
    if host.kind == DOMAIN:
        return host.name == "localhost" or host.name.endswith(".localhost")
    return ipaddress.ip_address(host.name.split("%")[0]).is_loopback


def allowed(ctx: Ctx, host: Host) -> bool:
    return loopback(host) or any(matches(host, entry) for entry in ctx.allow)


def url(ctx: Ctx, line: int, setting: str, value: object, *, registry: bool = True) -> None:
    """Judge a URL a setting points packages at: clear text, an unparseable spelling, embedded
    credentials and, when `registry`, a host outside the allowlist. A path without a scheme is local."""
    text = norm(value)
    bare = PREFIX.sub("", text)
    if not SCHEME.match(bare):
        return
    try:
        parsed = parse_url(bare)
    except UnparseableError as exc:
        add(ctx, UNREADABLE, line, (setting, digest(text)), f"{setting}: a URL clients may read differently ({exc})")
        return
    shown = f"{parsed.scheme}://{parsed.host.name}"
    if parsed.userinfo:
        _userinfo(ctx, line, setting, bare)
    if parsed.scheme in CLEAR and not loopback(parsed.host):
        add(ctx, HTTP, line, (setting, shown), f"{setting} fetches over clear text ({shown}); use https")
    elif registry and parsed.scheme != "file" and not allowed(ctx, parsed.host):
        add(
            ctx,
            HOST,
            line,
            (setting, parsed.host.name),
            f"{setting} points at {parsed.host.name}, which is not an allowed registry host",
        )


def _userinfo(ctx: Ctx, line: int, setting: str, text: str) -> None:
    """A password in a URL's userinfo is a literal secret unless it is an env reference; a user name
    alone (as in an ssh URL) is not a credential."""
    authority = AUTHORITY_END.split(text.split("://", 1)[1], maxsplit=1)[0]
    creds = authority.rpartition("@")[0]
    _, colon, pw = creds.partition(":")
    if colon and literal(pw):
        add(ctx, CREDENTIAL, line, (setting, digest(creds)), f"{setting} carries a password in its URL")


def falsy(value: object) -> bool:
    return norm(value).lower() in {"false", "0", "no", "off"}


def truthy(value: object) -> bool:
    return norm(value).lower() in {"true", "1", "yes", "on"}
