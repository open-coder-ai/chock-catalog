"""chock_scan host modules against real-world corpora (fixtures/hosts/SOURCES.md names each source).

The URL Standard's own tests (web-platform-tests): where the parser accepts an input, the host and
port must equal the standard's; where the standard fails an input, the parser must refuse it. A
refusal of an input the standard accepts is allowed: callers fail closed. The SSRF corpus pins each
published bypass to its expected host or refusal; every real URL cited by this catalog must parse.
"""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest
from chock_scan.hostkit import FIXTURES, fixture, load, sources

WPT_URLS = fixture("wpt-urltestdata-special.json")
WPT_IDNA = [c for name in ("wpt-toascii.json", "wpt-IdnaTestV2.json") for c in fixture(name) if isinstance(c, dict)]
SSRF = fixture("ssrf-corpus.json")
REAL = (FIXTURES / "real-urls.txt").read_text(encoding="utf-8").split()
EDGE = "".join(map(chr, range(0x21)))


@pytest.fixture(params=sources("urls"))
def hk(request: pytest.FixtureRequest) -> SimpleNamespace:
    return load(request.param)


def _standard_host(case: dict[str, str]) -> str:
    """The URL Standard's hostname in this module's canonical form (no brackets, no trailing dot, mapped IPv4 unmapped)."""
    name = case["hostname"]
    scheme = case["input"].strip(EDGE).split(":", 1)[0].lower()
    if scheme == "file" and not name:
        return "localhost"  # the standard serialises file://localhost/ with an empty host
    if name.startswith("["):
        ip = ipaddress.IPv6Address(name[1:-1])
        return str(ip.ipv4_mapped or ip.compressed)
    return name.removesuffix(".")


def test_never_disagrees_with_the_url_standard(hk: SimpleNamespace) -> None:
    disagreements, accepted = [], 0
    for case in WPT_URLS:
        try:
            url = hk.urls.parse_url(case["input"])
        except hk.hosts.UnparseableError:
            continue
        accepted += 1
        if case.get("failure"):
            disagreements.append((case["input"], "the standard fails it", url))
            continue
        scheme = url.scheme or ""
        port = int(case["port"]) if case["port"] else hk.urls.DEFAULT_PORTS[scheme]
        if (url.host.name, url.port) != (_standard_host(case), port):
            disagreements.append((case["input"], case["hostname"], url))
    assert not disagreements
    assert accepted >= 100  # the comparison is not vacuous


def test_never_disagrees_with_the_url_standards_idna_tests(hk: SimpleNamespace) -> None:
    disagreements, accepted = [], 0
    for case in WPT_IDNA:
        try:
            host = hk.hosts.normalize_host(case["input"])
        except hk.hosts.UnparseableError:
            continue
        accepted += 1
        want = case["output"]
        if want is None or (host.kind == "domain" and host.name != want.removesuffix(".")):
            disagreements.append((case["input"], want, host))
    assert not disagreements
    assert accepted >= 1000


@pytest.mark.parametrize("case", SSRF, ids=[f"{c['source']}:{c['input']!r}" for c in SSRF])
def test_published_ssrf_bypasses(hk: SimpleNamespace, case: dict[str, object]) -> None:
    if case["host"] is None:
        with pytest.raises(hk.hosts.UnparseableError):
            hk.urls.parse_url(case["input"])
        return
    url = hk.urls.parse_url(case["input"])
    assert (url.host.name, url.port) == (case["host"], case["port"])


def test_every_real_url_this_catalog_cites_parses(hk: SimpleNamespace) -> None:
    assert len(REAL) > 500
    refused = []
    for text in REAL:
        try:
            hk.urls.parse_url(text)
        except hk.hosts.UnparseableError as exc:
            refused.append((text, str(exc)))
    assert not refused
