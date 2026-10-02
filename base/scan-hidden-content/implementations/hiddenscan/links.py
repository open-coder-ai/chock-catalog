"""Remote URLs judged for data they carry out: secret words in the query, data-shaped parts, embeds, dictionaries."""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass

from chock_scan.urls import UnparseableError, parse_url

from hiddenscan.markdown import is_image

BARE = re.compile(r"(?:https?|ftp|wss?)://[^\s<>\"'`]+", re.IGNORECASE)
DESTINATION = re.compile(r"\]\(\s*(<[^>\n]*>|[^\s)]*)")
TRAILING = ".,;:!?*_"
#: CommonMark backslash escapes: any ASCII punctuation.
MD_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
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
LINK_NAMED = "exfil-link-secret"
#: How a URL is fetched: when a link is followed, as a Markdown image on render, or by an HTML tag or CSS.
LINK, IMAGE, TAG = 0, 1, 2
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


def judge(raw: str, vocab: object, *, load: int) -> Verdict | None:
    """The finding a URL earns, or None for a relative, allowlisted or data-free one. `load` is LINK (fetched
    when followed), IMAGE (a Markdown image: fetched on render, judged by shape) or TAG (an HTML or CSS source:
    fetched on render, and judged by host too)."""
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
    if found is not None and found[0] == SECRET and load == LINK:
        found = LINK_NAMED, found[1] + " (a link: fetched only when followed)"
    if found is None and load == TAG and not allowed:
        found = EMBED, "it is fetched when the file is rendered"
    return Verdict(found[0], host.name, shape, found[1]) if found else None


def _trim(url: str) -> str:
    """A bare URL without the punctuation around it, and cut where a Markdown link wraps it (`](`, `)[`)."""
    for joint in ("](", ")["):
        url = url.split(joint, 1)[0]
    end = len(url.rstrip(TRAILING))
    surplus = {
        ")": url.count(")", 0, end) - url.count("(", 0, end),
        "]": url.count("]", 0, end) - url.count("[", 0, end),
    }
    while end and url[end - 1] in surplus and surplus[url[end - 1]] > 0:
        surplus[url[end - 1]] -= 1
        end -= 1
        while end and url[end - 1] in TRAILING:
            end -= 1
    return url[:end]


def text_urls(text: str) -> list[tuple[int, str, bool]]:
    """(offset, URL, is an image) of bare URLs and Markdown link and image destinations, backslash escapes
    in destinations decoded as CommonMark decodes them."""
    found = [(m.start(), _trim(m.group(0)), False) for m in BARE.finditer(text)]
    for m in DESTINATION.finditer(text):
        dest = MD_ESCAPE.sub(r"\1", m.group(1))
        if "/" in dest or ":" in dest:
            found.append((m.start(1), dest, is_image(text, m.start())))
    return found


def _family(url: str) -> tuple[str, str] | None:
    path = url.partition("#")[0].partition("?")[0].split("//", 1)[-1].partition("/")[2]
    prefix, _, last = path.rpartition("/")
    stem = last.rpartition(".")[0] or last
    return (prefix, stem) if 0 < len(stem) <= MAX_STEM else None


def runs(urls: list[tuple[int, str]], vocab: object) -> list[tuple[int, Verdict]]:
    """A dictionary of URLs, one per character to leak: five or more camo-style URLs, or one host serving
    five or more one- or two-character names under one path. Each member is its own finding, keyed by a
    hash of the URL, so a run that grows reports the URLs it gains."""
    camo: dict[str, int] = {}
    families: dict[tuple[str, str], dict[str, tuple[int, str]]] = {}
    for line, raw in urls:
        url = clean(raw)
        if not REMOTE.match(url):
            continue
        try:
            host = parse_url(url.partition("#")[0]).host
        except (UnparseableError, ValueError):
            continue
        if vocab.camo_host(host):
            camo.setdefault(url, line)
        elif not vocab.allowed_host(host) and (member := _family(url)):
            families.setdefault((host.name, member[0]), {}).setdefault(member[1], (line, url))
    groups = [("camo", {u: (n, u) for u, n in camo.items()}, "camo-style image URLs")]
    groups += [
        (host, stems, "one- or two-character names under one path") for (host, _), stems in sorted(families.items())
    ]
    out = []
    for host, members, what in groups:
        if len(members) >= RUN:
            for line, url in sorted(members.values()):
                shape = hashlib.sha256(url.encode("utf-8", "surrogatepass")).hexdigest()[:16]
                out.append((line, Verdict(CAMO, host, shape, f"one of {len(members)} {what}")))
    return out
