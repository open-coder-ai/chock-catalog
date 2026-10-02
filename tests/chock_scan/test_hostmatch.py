"""chock_scan.hostmatch: allowlist entries with explicit wildcard semantics, and host equality.

Run against lib/ and every copy a policy ships.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from chock_scan.hostkit import load, sources


@pytest.fixture(params=sources("hostmatch"))
def hk(request: pytest.FixtureRequest) -> SimpleNamespace:
    return load(request.param)


@pytest.mark.parametrize(
    ("host", "entry", "want"),
    [
        ("example.com", "example.com", True),
        ("EXAMPLE.com.", "example.com", True),
        ("a.example.com", "example.com", False),
        ("example.com.evil.net", "example.com", False),
        ("evilexample.com", "example.com", False),
        ("a.example.com", "*.example.com", True),
        ("a.b.example.com", "*.example.com", True),
        ("A.Example.COM.", "*.example.com", True),
        ("example.com", "*.example.com", False),
        ("example.com.evil.net", "*.example.com", False),
        ("evilexample.com", "*.example.com", False),
        ("a.evilexample.com", "*.example.com", False),
        ("xn--bcher-kva.de", "B\u00fccher.de", True),
        ("www.B\u00fccher.de", "*.xn--bcher-kva.de", True),
        ("127.0.0.1", "127.0.0.1", True),
        ("2130706433", "127.0.0.1", True),
        ("0x7f.1", "127.0.0.1", True),
        ("[::ffff:127.0.0.1]", "127.0.0.1", True),
        ("127.0.0.1", "[::ffff:7f00:1]", True),
        ("[0:0::1]", "::1", True),
        ("[::1]", "127.0.0.1", False),
        ("[fe80::1%25eth0]", "fe80::1", False),
        ("1.2.3.4", "*.example.com", False),
        ("[::1]", "*.example.com", False),
        ("localhost", "127.0.0.1", False),
    ],
)
def test_matches_has_one_meaning_per_entry_form(hk: SimpleNamespace, host: str, entry: str, want: bool) -> None:
    assert hk.hostmatch.matches(host, entry) is want
    parsed_host = hk.hosts.normalize_host(host)
    assert hk.hostmatch.matches(parsed_host, hk.hostmatch.parse_entry(entry)) is want


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "*",
        "*.",
        "*.com",
        "*.co",
        "**.example.com",
        "*example.com",
        "a.*.example.com",
        "example.*",
        "*.*.example.com",
        "*.127.0.0.1",
        "*.1.2.3",
        "*.[::1]",
        "example.com:443",
        "https://example.com",
        "example.com/",
        " example.com",
        "fa\u00df.de",
    ],
)
def test_entries_with_no_single_meaning_are_refused(hk: SimpleNamespace, entry: str) -> None:
    with pytest.raises(hk.hosts.UnparseableError):
        hk.hostmatch.parse_entry(entry)


def test_an_unparseable_host_raises_instead_of_not_matching(hk: SimpleNamespace) -> None:
    with pytest.raises(hk.hosts.UnparseableError):
        hk.hostmatch.matches("0177.0.0.1", "127.0.0.1")
    with pytest.raises(TypeError):
        hk.hostmatch.parse_entry(None)


@pytest.mark.parametrize(
    ("a", "b", "want"),
    [
        ("Example.COM.", "example.com", True),
        ("b\u00fccher.de", "XN--BCHER-KVA.DE", True),
        ("2130706433", "127.0.0.1", True),
        ("[::ffff:127.0.0.1]", "0x7f.0.0.1", True),
        ("[2001:DB8:0::1]", "2001:db8::1", True),
        ("www.example.com", "example.com", False),
        ("localhost", "127.0.0.1", False),
        ("[::1]", "127.0.0.1", False),
    ],
)
def test_same_host_compares_canonical_names_never_resolves(hk: SimpleNamespace, a: str, b: str, want: bool) -> None:
    assert hk.hostmatch.same_host(a, b) is want
    assert hk.hostmatch.same_host(hk.hosts.normalize_host(a), hk.hosts.normalize_host(b)) is want


def test_allowlist_files_skip_comments_and_blanks(hk: SimpleNamespace) -> None:
    text = "\ufeff# approved hosts\r\nexample.com\r\n\n  *.example.org   # mirrors\n\t127.0.0.1\n#*.evil.net\n"
    entries = hk.hostmatch.parse_allowlist(text)
    assert [(e.host.name, e.subdomains) for e in entries] == [
        ("example.com", False),
        ("example.org", True),
        ("127.0.0.1", False),
    ]
    assert hk.hostmatch.parse_allowlist("") == ()
    assert hk.hostmatch.parse_allowlist("# nothing\n\n") == ()


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("example.com\n*.com\n", 2),
        ("example.com\nexample.org evil.net\n", 2),
        ("a.com\nb.com\nexample.com\u2028evil.net\n", 3),
        ("example.com\x0bevil.net\n", 1),
        ("example.com\x0cevil.net\n", 1),
        ("example.com\x85evil.net\n", 1),
        ("example.com\revil.net\n", 1),
        ("\ufeff\ufeffexample.com\n", 1),
    ],
)
def test_one_bad_line_refuses_the_whole_allowlist(hk: SimpleNamespace, text: str, line: int) -> None:
    with pytest.raises(hk.hosts.UnparseableError, match=f"^line {line}: "):
        hk.hostmatch.parse_allowlist(text)
