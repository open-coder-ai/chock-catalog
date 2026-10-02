"""Remote URLs judged for data they carry out: secret words in the query, data-shaped parts, embeds, dictionaries."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from chock_scan.urls import UnparseableError, parse_url

BARE = re.compile(r"(?:https?|ftp|wss?)://[^\s<>\"'`]+", re.IGNORECASE)
DESTINATION = re.compile(r"\]\(\s*(<[^>\n]*>|[^\s)]*)")
TRAILING = ".,;:!?*_"
REMOTE = re.compile(r"(?:https?|ftp|wss?):|//", re.IGNORECASE)
#: The URL Standard deletes tabs and newlines inside a URL, so `ht<tab>tps:` is still https.
STRIPPED = re.compile(r"[\t\n\r]")
PLACEHOLDER = re.compile(
    r"\{\{?[^{}\s]{1,40}\}\}?|\$\{|\$[A-Z_][A-Z0-9_]+|\[[A-Za-z_][\w .-]{0,40}\]|<[A-Za-z_][\w .-]{0,40}>|%[sd]"
)
TOKENISH = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
HEXISH = re.compile(r"[0-9a-fA-F]{32,}")
KEEP_SEGMENT = re.compile(r"[a-z_.-]{1,24}")
MIXED_RUN = 20
LONG_QUERY = 40
RUN = 5
#: A dictionary entry's name: one or two characters, the extension aside.
MAX_STEM = 2
SECRET, SHAPE, EMBED, UNPARSEABLE, CAMO = (
    "exfil-url-secret",
    "exfil-url-shape",
    "remote-embed",
    "unparseable-url",
    "camo-url-run",
)
#: Promotion verdicts: these would block, the rest ask (roadmap NP01 default and block tier).
BLOCKING = frozenset({SECRET, CAMO})


PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2})+")


def unquote(text: str, *, plus: bool = False) -> str:
    """Percent-decoding as a server reads it (UTF-8, bad bytes replaced); with `plus`, '+' is a space."""
    text = text.replace("+", " ") if plus else text
    return PERCENT.sub(lambda m: bytes.fromhex(m.group(0).replace("%", "")).decode("utf-8", "replace"), text)


def pairs_of(query: str) -> list[tuple[str, str]]:
    """Query parameters split on '&', each name and value decoded; a part without '=' has an empty value."""
    out = []
    for part in query.split("&"):
        if part:
            name, _, value = part.partition("=")
            out.append((unquote(name, plus=True), unquote(value, plus=True)))
    return out


@dataclass(frozen=True)
class Verdict:
    rule: str
    host: str
    shape: str
    reason: str


def clean(raw: str) -> str:
    """The URL as a client reads it: entities decoded, angle brackets, tabs and newlines dropped."""
    return STRIPPED.sub("", html.unescape(raw.strip()).strip("<>").strip())


def _encoded(part: str) -> bool:
    """Hex of 32 or more, or base64 of 32 or more holding a run of 20 or more between '_' and '-' with
    upper case, lower case and digits: a slug of words ('A08_2021-Software_and_Data') has short runs."""
    if HEXISH.search(part):
        return True
    for token in TOKENISH.finditer(part):
        for run in re.split("[_-]", token.group(0)):
            if len(run) >= MIXED_RUN and all(re.search(c, run) for c in ("[a-z]", "[A-Z]", "[0-9]")):
                return True
    return False


def _shape(path: str, names: list[str]) -> str:
    segments = [s if KEEP_SEGMENT.fullmatch(s.lower()) else "*" for s in path.split("/") if s]
    return "/" + "/".join(segments) + ("?" + ",".join(sorted(set(names))) if names else "")


def _carries_data(path: str, query: str, vocab: object, *, allowed: bool) -> tuple[str, str] | None:
    """(rule, reason) when the path or query is shaped to carry data, else None."""
    pairs = pairs_of(query)
    decoded = unquote(query, plus=True)
    if nouns := vocab.secret_words(decoded):
        return SECRET, f"its query names {', '.join(nouns)}"
    values = [v for _, v in pairs] or [decoded]
    longest = max(map(len, values)) if allowed else len(query)
    if longest >= LONG_QUERY:
        return SHAPE, f"a query of {longest} characters"
    if PLACEHOLDER.search(path) or PLACEHOLDER.search(decoded):
        return SHAPE, "a placeholder for data to fill in"
    if any(_encoded(part) for part in [*path.split("/"), *values]):
        return SHAPE, "an encoded segment of 32 or more characters"
    return None


def judge(raw: str, vocab: object, *, embed: bool) -> Verdict | None:
    """The finding a URL earns, or None for a relative, allowlisted or data-free one."""
    url = clean(raw)
    head = url.partition("#")[0]
    rest, _, query = head.partition("?")
    if not REMOTE.match(url) or ("//" in rest and not re.split(r"[/?#]", rest.split("//", 1)[1], maxsplit=1)[0]):
        return None  # relative, another scheme, or no host: nothing is fetched from a host
    try:
        host = parse_url(head).host
    except (UnparseableError, ValueError):
        return Verdict(UNPARSEABLE, "?", "?", "a URL clients may read as different hosts")
    authority_end = re.search(r"(?<!/)/(?!/)", rest)
    path = unquote(rest[authority_end.start() :]) if authority_end else "/"
    shape = _shape(path, [k.lower()[:24] for k, _ in pairs_of(query)])
    allowed = vocab.allowed_host(host)
    if allowed and not query:
        return None
    found = _carries_data(path, query, vocab, allowed=allowed)
    if found is None and embed and not allowed:
        found = EMBED, "it is fetched when the file is rendered"
    return Verdict(found[0], host.name, shape, found[1]) if found else None


def _trim(url: str) -> str:
    url = url.rstrip(TRAILING)
    while url.endswith((")", "]")) and url.count(url[-1]) > url.count("(" if url[-1] == ")" else "["):
        url = url[:-1].rstrip(TRAILING)
    return url


def text_urls(text: str) -> list[tuple[int, str]]:
    """(offset, URL) of bare URLs and Markdown link and image destinations."""
    found = [(m.start(), _trim(m.group(0))) for m in BARE.finditer(text)]
    found += [(m.start(1), m.group(1)) for m in DESTINATION.finditer(text) if "/" in m.group(1)]
    return found


def runs(urls: list[tuple[int, str]], vocab: object) -> list[tuple[int, Verdict]]:
    """A dictionary of URLs, one per character to leak: five or more camo-style URLs, or one host serving
    five or more one- or two-character names under one path."""
    camo: list[int] = []
    families: dict[tuple[str, str], dict[str, int]] = {}
    for line, raw in urls:
        url = clean(raw)
        if not REMOTE.match(url):
            continue
        try:
            host = parse_url(url.partition("#")[0]).host
        except (UnparseableError, ValueError):
            continue
        if vocab.camo_host(host):
            camo.append(line)
            continue
        if vocab.allowed_host(host):
            continue
        path = url.partition("#")[0].partition("?")[0].split("//", 1)[-1].partition("/")[2]
        prefix, _, last = path.rpartition("/")
        stem = last.rpartition(".")[0] or last
        if 0 < len(stem) <= MAX_STEM:
            families.setdefault((host.name, prefix), {}).setdefault(stem, line)
    out = []
    if len(camo) >= RUN:
        out.append((min(camo), Verdict(CAMO, "camo", "camo", f"{len(camo)} camo-style image URLs")))
    for (host, prefix), stems in sorted(families.items()):
        if len(stems) >= RUN:
            reason = f"{len(stems)} one- or two-character names under one path"
            out.append((min(stems.values()), Verdict(CAMO, host, "/" + prefix, reason)))
    return out
