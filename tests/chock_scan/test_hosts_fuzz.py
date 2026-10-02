"""chock_scan host modules on generated input: only UnparseableError escapes, results are canonical
and stable, wildcard matching is exactly the suffix rule, and hostile input stays fast.

Seeded generators (hypothesis is not a dev dependency here), so a failure reproduces from its seed.
"""

from __future__ import annotations

import contextlib
import random
import time
from types import SimpleNamespace

import pytest
from chock_scan.hostkit import load, sources

SEEDS = range(60)
#: Characters host parsers treat specially, plus lookalikes, mapped forms and invisibles.
TRICKY = [
    *"aAzZ09xX.-_%@:/\\?#[]* \t\n",
    "\u3002",
    "\uff0e",
    "\uff0f",
    "\uff20",
    "\uff03",
    "\u2488",
    "\u2100",
    "\u00df",
    "\u03c2",
    "\u200b",
    "\u200d",
    "\u202e",
    "\u00ad",
    "\u0430",
    "\u0435",
    "\u00fc",
    "\u0308",
    "\ufeff",
    "\U0001d400",
    "\u4e2d",
]
PIECES = ["%2F", "%40", "%25", "%C3%BC", "0x7f", "0177", "xn--", "::", "%25eth0", "ffff:", "255", "4294967296"]
SEPARATORS = {
    "": "b",
    ":443": "b",
    "/": "a",
    "\\": None,
    "#": None,
    "?": None,
    "%2F": None,
    "%40": None,
    "\uff0f": None,
}


@pytest.fixture(params=sources("hostmatch"))
def hk(request: pytest.FixtureRequest) -> SimpleNamespace:
    return load(request.param)


def _rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret


def _text(rng: random.Random, size: int) -> str:
    return "".join(rng.choice(TRICKY) if rng.random() < 0.8 else rng.choice(PIECES) for _ in range(size))


def _domain(rng: random.Random) -> str:
    return ".".join(
        "".join(rng.choice("abcxyz019-") for _ in range(rng.randrange(1, 6))) + "q" for _ in range(rng.randrange(2, 4))
    )


def _bracketed(name: str, kind: str) -> str:
    return f"[{name.replace('%', '%25')}]" if kind == "ipv6" else name


@pytest.mark.parametrize("seed", SEEDS)
def test_hosts_are_canonical_and_stable_or_refused(hk: SimpleNamespace, seed: int) -> None:
    rng = _rng(seed)
    for _ in range(200):
        text = _text(rng, rng.randrange(0, 24))
        try:
            host = hk.hosts.normalize_host(text)
        except hk.hosts.UnparseableError:
            continue
        assert host.name.isascii()
        assert host.name == host.name.lower() or host.kind == "ipv6"
        again = hk.hosts.normalize_host(_bracketed(host.name, host.kind))
        assert (again.kind, again.name) == (host.kind, host.name)
        assert hk.hostmatch.matches(host, hk.hostmatch.Entry(again))


@pytest.mark.parametrize("seed", SEEDS)
def test_urls_give_the_host_their_canonical_form_gives_or_refuse(hk: SimpleNamespace, seed: int) -> None:
    rng = _rng(seed)
    for _ in range(200):
        text = rng.choice(["https://", "http:", "//", "", "ws://u@"]) + _text(rng, rng.randrange(0, 30))
        try:
            url = hk.urls.parse_url(text)
        except hk.hosts.UnparseableError:
            continue
        again = hk.urls.parse_url(f"{url.scheme or 'http'}://{_bracketed(url.host.name, url.host.kind)}/")
        assert (again.host.kind, again.host.name) == (url.host.kind, url.host.name)
        assert url.port is None or 0 <= url.port <= 65535


@pytest.mark.parametrize("seed", SEEDS)
def test_userinfo_tricks_give_the_url_standard_host_or_refuse(hk: SimpleNamespace, seed: int) -> None:
    rng = _rng(seed)
    a, b = _domain(rng), _domain(rng)
    for sep, standard in SEPARATORS.items():
        text = f"https://{a}{sep}@{b}/"
        try:
            got = hk.urls.parse_url(text).host.name
        except hk.hosts.UnparseableError:
            assert standard is None, text
            continue
        assert got == {"a": a, "b": b}[standard], text


@pytest.mark.parametrize("seed", SEEDS)
def test_a_wildcard_matches_exactly_the_hosts_below_its_domain(hk: SimpleNamespace, seed: int) -> None:
    rng = _rng(seed)
    base = _domain(rng)
    entry = hk.hostmatch.parse_entry("*." + base.upper())
    for _ in range(50):
        label = rng.choice(["", "x.", "x.y.", "evil", "evil-", "evil."])
        tail = rng.choice(["", ".evil.net", "x"])
        host = hk.hosts.normalize_host(label + base + tail)
        labels, base_labels = host.name.split("."), base.split(".")
        below = len(labels) > len(base_labels) and labels[-len(base_labels) :] == base_labels
        assert hk.hostmatch.matches(host, entry) is below
        assert hk.hostmatch.matches(host, base) is (host.name == base)


@pytest.mark.parametrize("seed", SEEDS)
def test_allowlists_parse_whole_or_refuse(hk: SimpleNamespace, seed: int) -> None:
    rng = _rng(seed)
    lines = [rng.choice(["# c", "", "  ", "*." + _domain(rng), _domain(rng), _text(rng, 6)]) for _ in range(8)]
    split = "\n".join(lines).split("\n")
    bodies = [b for b in (line.partition("#")[0].strip(" \t") for line in split) if b]
    try:
        entries = hk.hostmatch.parse_allowlist("\n".join(lines))
    except hk.hosts.UnparseableError:
        with pytest.raises(hk.hosts.UnparseableError):
            for body in bodies:
                hk.hostmatch.parse_entry(body)
        return
    assert entries == tuple(hk.hostmatch.parse_entry(body) for body in bodies)


HOSTILE = [
    "%41" * 340,
    "%" * 1024,
    "0x" + "f" * 1022,
    "1." * 512,
    "9" * 1024,
    "[" + ":" * 1022 + "]",
    "xn--" + "a" * 59 + "." + "xn--" + "9" * 59,
    "\u0430" * 1024,
    "\uff45" * 1024,
    ".".join(["a"] * 512),
    ("\u00fc" * 63 + ".") * 16,
]


@pytest.mark.parametrize("text", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_hosts_are_refused_fast(hk: SimpleNamespace, text: str) -> None:
    start = time.perf_counter()
    for _ in range(20):
        with pytest.raises(hk.hosts.UnparseableError):
            hk.hosts.normalize_host(text)
        with pytest.raises(hk.hosts.UnparseableError):
            hk.urls.parse_url("https://" + text + "/")
    assert time.perf_counter() - start < 2.0


@pytest.mark.parametrize(
    "text",
    [
        "https://" + "a@" * 4000,
        "https://a.com:" + "0" * 8000,
        "https://" + "\\" * 8000,
        "x" * 8192,
        "https://a/" + "%" * 8000,
    ],
    ids=range(5),
)
def test_hostile_urls_are_handled_fast(hk: SimpleNamespace, text: str) -> None:
    start = time.perf_counter()
    for _ in range(20):
        with contextlib.suppress(hk.hosts.UnparseableError):
            hk.urls.parse_url(text)
    assert time.perf_counter() - start < 2.0
