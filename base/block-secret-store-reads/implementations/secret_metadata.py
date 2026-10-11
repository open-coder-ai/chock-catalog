"""Requests to cloud instance-metadata credential endpoints (169.254.169.254 and kin), stdlib only, no network."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote

import secret_paths as store
from chock_scan import data_table
from chock_shellparse import Cmd

TABLE = Path(__file__).resolve().parent / "data" / "metadata_endpoints.json"
KEYS = ("endpoints", "variables", "fetchers", "sockets")
NAT64 = (ipaddress.IPv6Network("64:ff9b::/96"), ipaddress.IPv6Network("::/96"))
URL = re.compile(r"[A-Za-z][\w+.-]*://[^\s'\"`<>(){}\\]+|//[^\s'\"`<>(){}\\]+")
DEV_NET = re.compile(r"^/dev/(?:tcp|udp)/([^/]+)/", re.I)
ENDS = frozenset(",;)]}\n")


class Endpoint(NamedTuple):
    label: str
    hosts: frozenset[str]
    allow: tuple[re.Pattern[str], ...]


class Table(NamedTuple):
    endpoints: tuple[Endpoint, ...]
    variables: tuple[str, ...]
    fetchers: frozenset[str]
    sockets: frozenset[str]
    literal: re.Pattern[str]


def _problems(doc: dict) -> list[str]:
    found = []
    for item in doc["endpoints"]:
        for host in item["hosts"]:
            if canonical(host) != host:
                found.append(f"{item['id']}: host {host!r} is not in canonical form")
        for pattern in item["allow"]:
            try:
                re.compile(pattern)
            except re.error as exc:
                found.append(f"{item['id']}: allow {pattern!r}: {exc}")
    return found


def load(path: Path = TABLE) -> Table:
    """The validated table; a TableError (a guard fault, never a verdict) when it is broken."""
    doc = data_table.load(path, kind="curated", schema=1, keys=KEYS, check=_problems)
    endpoints = tuple(
        Endpoint(item["label"], frozenset(item["hosts"]), tuple(re.compile(p) for p in item["allow"]))
        for item in doc["endpoints"]
    )
    hosts = sorted({host for e in endpoints for host in e.hosts}, key=len, reverse=True)
    literal = re.compile("|".join(rf"(?<![\w.:]){re.escape(h)}(?!\w|\.\w)" for h in hosts), re.I)
    return Table(endpoints, tuple(doc["variables"]), frozenset(doc["fetchers"]), frozenset(doc["sockets"]), literal)


def _ipv4(text: str) -> int | None:
    """The address the URL Standard (and curl) read in 1 to 4 decimal, octal or hex parts, else None."""
    parts = text.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if not 1 <= len(parts) <= 4:  # noqa: PLR2004
        return None
    numbers = []
    for part in parts:
        base = 16 if part[:2].lower() == "0x" else 8 if len(part) > 1 and part[0] == "0" else 10
        digits = part[2:] if base == 16 else part  # noqa: PLR2004
        try:
            numbers.append(int(digits or "0", base) if digits.isalnum() else -1)
        except ValueError:
            return None
    *head, last = numbers
    if min(numbers) < 0 or any(n > 255 for n in head) or last >= 256 ** (5 - len(numbers)):  # noqa: PLR2004
        return None
    return sum(n << (8 * (3 - i)) for i, n in enumerate(head)) + last


def canonical(host: str) -> str:
    """A host as one comparable string: dotted-quad IPv4, compressed IPv6, or a lowercase name without a trailing dot.
    IPv4 written as IPv4-mapped, IPv4-compatible or NAT64 IPv6 reads as the IPv4 address."""
    host = unquote(host).strip().lower()
    inner = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        six = ipaddress.IPv6Address(inner.split("%", 1)[0])
    except ValueError:
        six = None
    if six is not None:
        embedded = any(six in net for net in NAT64)
        four = six.ipv4_mapped or (ipaddress.IPv4Address(int(six) & 0xFFFFFFFF) if embedded else None)
        return str(four or six)
    number = _ipv4(host)
    return str(ipaddress.IPv4Address(number)) if number is not None else host.rstrip(".")


def split(word: str) -> tuple[str, str]:
    """The host and the path (percent-decoded once, dot segments and a trailing slash removed) a URL names;
    a word with no scheme is read as curl reads it, as `host[:port][/path]`."""
    rest = word.split("://", 1)[1] if "://" in word else word.removeprefix("//")
    end = re.search(r"[/?#]", rest)
    authority, after = (rest[: end.start()], rest[end.start() :]) if end else (rest, "")
    hostport = authority.rpartition("@")[2]
    host = hostport[: hostport.index("]") + 1] if hostport.startswith("[") and "]" in hostport else hostport
    host = host if host.startswith("[") else host.split(":", 1)[0]
    path = re.split(r"[?#]", after, maxsplit=1)[0]
    return canonical(host), "/" + "/".join(store.collapse(unquote(path)))


def endpoint(host: str, table: Table) -> Endpoint | None:
    return next((e for e in table.endpoints if host in e.hosts), None)


def judge_url(word: str, table: Table) -> str:
    """What a request to this URL would read, or '' when it names no endpoint or only an allowed path."""
    host, path = split(word)
    found = endpoint(host, table)
    if found is None or any(p.fullmatch(path) for p in found.allow):
        return ""
    return found.label


def _words(cmd: Cmd) -> list[str]:
    """Each argument, and the value of an `--opt=value` or `-Opt:value` argument, with the line's variables set."""
    found = []
    for written in cmd.args:
        word = store.expand(written, cmd.env)
        if word.startswith("-"):
            word = re.split(r"[=:]", word, maxsplit=1)[1] if re.search(r"^-[\w-]+[=:]", word) else ""
        found += (store.braces(word) or [word]) if word else []
    return found


def _variable(text: str, table: Table) -> str:
    return next((f"the ECS task credential endpoint (${name})" for name in table.variables if name in text), "")


def _code(text: str, table: Table) -> str:
    """A metadata URL in interpreter code, unless it is a whole allowed URL in its own string literal; a bare
    metadata host left in the code (a path built elsewhere) counts too."""
    for match in URL.finditer(text):
        what = judge_url(match.group(0), table)
        if not what and endpoint(split(match.group(0))[0], table):
            before, after = text[match.start() - 1 : match.start()], text[match.end() : match.end() + 1]
            tail = text[match.end() + 1 :].lstrip(" \t")
            whole = before in ("'", '"') and after == before and (not tail or tail[0] in ENDS)
            what = "" if whole else endpoint(split(match.group(0))[0], table).label
        if what:
            return what
    rest = URL.sub(" ", text)
    found = table.literal.search(rest)
    if found:
        return endpoint(canonical(found.group(0)), table).label
    return ""


def request(cmd: Cmd, table: Table, *, interpreter: bool) -> str:
    """What credential endpoint this command would read, or ''."""
    for target in [*cmd.reads, *cmd.writes]:
        net = DEV_NET.match(store.expand(target, cmd.env))
        if net and endpoint(canonical(net.group(1)), table):
            return endpoint(canonical(net.group(1)), table).label
    if interpreter:
        text = store.expand("\n".join([*cmd.args, cmd.doc]), cmd.env)
        return _variable(text, table) or _code(text, table)
    if cmd.name in table.fetchers:
        words = _words(cmd)
        return _variable(" ".join(words), table) or next(filter(None, (judge_url(w, table) for w in words)), "")
    if cmd.name in table.sockets:
        return next((e.label for w in _words(cmd) if (e := endpoint(canonical(w), table))), "")
    return ""
