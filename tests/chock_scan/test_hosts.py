"""chock_scan.hosts and chock_scan.idn: one canonical host per input, or an explicit UnparseableError.

Run against lib/ and every copy a policy ships. Escapes, never literal invisible characters.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from chock_scan.hostkit import load, sources

ANY = "0.0.0.0"  # noqa: S104 -- a host under test, nothing binds


@pytest.fixture(params=sources("hosts"))
def hk(request: pytest.FixtureRequest) -> SimpleNamespace:
    return load(request.param)


def _host(hk: SimpleNamespace, text: str) -> tuple[str, str, set[str]]:
    host = hk.hosts.normalize_host(text)
    return host.name, host.kind, set(host.flags)


@pytest.mark.parametrize(
    ("text", "name", "flags"),
    [
        ("example.com", "example.com", set()),
        ("Example.COM.", "example.com", set()),
        ("_dmarc.example.com", "_dmarc.example.com", set()),
        ("-x.example", "-x.example", set()),
        ("\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com", "example.com", set()),
        ("example\u3002com", "example.com", set()),
        ("example\uff0ecom\uff61", "example.com", set()),
        ("B\u00fccher.de", "xn--bcher-kva.de", {"idn"}),
        ("B\u00dcCHER.DE", "xn--bcher-kva.de", {"idn"}),
        ("XN--BCHER-KVA.de", "xn--bcher-kva.de", {"idn"}),
        ("\u65e5\u672c\u8a9e.jp", "xn--wgv71a119e.jp", {"idn"}),
        ("\u3072\u3089\u304c\u306a\u6f22\u5b57.jp", "xn--v8j0cwa6gy22xv2ya.jp", {"idn"}),
        ("p\u0430ypal.com", "xn--pypal-4ve.com", {"idn", "mixed-script", "confusable"}),
        ("\u0430\u0440\u0440\u0456\u0435.com", "xn--80ak6aa4i.com", {"idn", "confusable"}),
        ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com", {"idn", "confusable"}),
        ("a\u03b2.com", "xn--a-1lb.com", {"idn", "mixed-script"}),
        ("\u10a3.com", "xn--ukj.com", {"idn"}),
        ("%65xample.com", "example.com", {"percent-encoded"}),
        ("a%2Ecom", "a.com", {"percent-encoded"}),
        ("%C3%BC.de", "xn--tda.de", {"percent-encoded", "idn"}),
    ],
)
def test_names_normalise_to_one_lowercase_ascii_form(
    hk: SimpleNamespace, text: str, name: str, flags: set[str]
) -> None:
    assert _host(hk, text) == (name, "domain", flags)


@pytest.mark.parametrize(
    "text",
    [
        "",
        ".",
        "a..b",
        ".a.b",
        "example.com..",
        "a b.com",
        "a/b.com",
        "a@b.com",
        "a#b.com",
        "a\\b.com",
        "a*.com",
        "a\x00b.com",
        "a]b",
        "x" * 64 + ".com",
        ("a" * 63 + ".") * 4,
        "a" * 1025,
        "%",
        "%4",
        "%zz.com",
        "%ff.com",
        "%2541.com",
        "a%00b.com",
        "a%40b.com",
        "a%2Fb.com",
        "fa\u00df.de",
        "\u03c2.gr",
        "a\u200cb.com",
        "a\u200db.com",
        "a\u200bb.com",
        "a\u202eb.com",
        "a\u00adb.com",
        "a\u115fb.com",
        "a\ufe0fb.com",
        "\u2c00.com",
        "\u04cf.com",
        "\U0002f868.com",
        "a\u2488com",
        "\u0308c.com",
        "a\ue000b.com",
        "\u00fc" * 64 + ".de",
        "xn--",
        "xn--a-",
        "xn--zz9-.com",
        "xn--bcher-kva-.de",
        "xn--a.com",
        "evil.com\uff20allowed.com",
        "evil.com\u2100.allowed.com",
    ],
)
def test_ambiguous_or_invalid_names_are_refused(hk: SimpleNamespace, text: str) -> None:
    with pytest.raises(hk.hosts.UnparseableError):
        hk.hosts.normalize_host(text)


@pytest.mark.parametrize(
    ("text", "name", "flags"),
    [
        ("127.0.0.1", "127.0.0.1", set()),
        ("255.255.255.255", "255.255.255.255", set()),
        (ANY, ANY, set()),
        ("%31%32%37.0.0.1", "127.0.0.1", {"percent-encoded"}),
    ],
)
def test_ipv4_only_as_a_plain_dotted_quad(hk: SimpleNamespace, text: str, name: str, flags: set[str]) -> None:
    assert _host(hk, text) == (name, "ipv4", flags)


@pytest.mark.parametrize(
    ("text", "reading"),
    [
        ("127.0.0.1.", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("0X7F.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("127.0.1", "127.0.0.1"),
        ("0x", ANY),
        ("10.0x.0x.1", "10.0.0.1"),
        ("0", ANY),
        ("00.0.0.0", ANY),
        ("01.02.03.04", "1.2.3.4"),
        ("0177.0.0.1", "127.0.0.1"),
        ("010.0.0.1", "8.0.0.1"),
        ("0" * 40 + "177.0.0.1", "127.0.0.1"),
        ("4294967295", "255.255.255.255"),
        ("\uff11\uff12\uff17.0.0.1", "127.0.0.1"),
    ],
)
def test_other_ipv4_forms_are_refused_naming_the_url_standard_reading(
    hk: SimpleNamespace, text: str, reading: str
) -> None:
    with pytest.raises(hk.hosts.UnparseableError, match=f"read {re.escape(reading)},"):
        hk.hosts.normalize_host(text)


@pytest.mark.parametrize(
    "text",
    [
        "08.0.0.1",
        "1.2.3.09",
        "1.2.3.4.5",
        "1.256.0.0",
        "1.2.3.256",
        "1.2.65536",
        "4294967296",
        "0x100000000",
        "example.123",
        "a.0x",
        "o177.0.0.1",
        "0o177.0.0.1",
    ],
)
def test_numeric_hosts_that_are_not_an_address_are_refused(hk: SimpleNamespace, text: str) -> None:
    with pytest.raises(hk.hosts.UnparseableError, match="not an IPv4 address"):
        hk.hosts.normalize_host(text)


@pytest.mark.parametrize(
    ("text", "name", "kind", "flags"),
    [
        ("[::1]", "::1", "ipv6", set()),
        ("::1", "::1", "ipv6", set()),
        ("[0000:0:0::1]", "::1", "ipv6", set()),
        ("[::]", "::", "ipv6", set()),
        ("[2001:DB8::1]", "2001:db8::1", "ipv6", set()),
        ("[fe80::1%25eth0]", "fe80::1%eth0", "ipv6", set()),
        ("fe80::1%eth0", "fe80::1%eth0", "ipv6", set()),
        ("[::ffff:127.0.0.1]", "127.0.0.1", "ipv4", {"ipv4-mapped"}),
        ("[0:0:0:0:0:ffff:7f00:1]", "127.0.0.1", "ipv4", {"ipv4-mapped"}),
        ("[64:ff9b::127.0.0.1]", "64:ff9b::7f00:1", "ipv6", {"ipv4-embedded"}),
        ("[64:ff9b:1::1]", "64:ff9b:1::1", "ipv6", {"ipv4-embedded"}),
        ("[::127.0.0.1]", "::7f00:1", "ipv6", {"ipv4-embedded"}),
        ("[2002:7f00:1::]", "2002:7f00:1::", "ipv6", {"ipv4-embedded"}),
        ("[2001::1]", "2001::1", "ipv6", {"ipv4-embedded"}),
    ],
)
def test_ipv6_literals_and_embedded_ipv4(hk: SimpleNamespace, text: str, name: str, kind: str, flags: set[str]) -> None:
    assert _host(hk, text) == (name, kind, flags)


@pytest.mark.parametrize(
    "text",
    [
        "[::1",
        "[::1]x",
        "[1::2::3]",
        "[::ffff:0177.0.0.1]",
        "[fe80::1%eth0]",
        "[fe80::1%25]",
        "[fe80::1%25a b]",
        "fe80::1%",
        "[::ffff:1.2.3.4%25x]",
        "[example.com]",
        ":",
        "1::2:3:4:5:6:7:8:9",
    ],
)
def test_malformed_ipv6_is_refused(hk: SimpleNamespace, text: str) -> None:
    with pytest.raises(hk.hosts.UnparseableError):
        hk.hosts.normalize_host(text)


def test_a_non_string_is_a_caller_error(hk: SimpleNamespace) -> None:
    with pytest.raises(TypeError):
        hk.hosts.normalize_host(b"example.com")


def test_the_error_is_a_value_error_naming_the_reason(hk: SimpleNamespace) -> None:
    with pytest.raises(ValueError, match="dotted quad"):
        hk.hosts.normalize_host("0177.0.0.1")
    with pytest.raises(ValueError, match="U\\+00DF"):
        hk.hosts.normalize_host("fa\u00df.de")
