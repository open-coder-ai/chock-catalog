"""chock_scan.urls: the host and port a URL names, or UnparseableError where parsers split it differently.

Run against lib/ and every copy a policy ships.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from chock_scan.hostkit import load, sources


@pytest.fixture(params=sources("urls"))
def hk(request: pytest.FixtureRequest) -> SimpleNamespace:
    return load(request.param)


def _url(hk: SimpleNamespace, text: str) -> tuple[str | None, str, int | None, bool]:
    url = hk.urls.parse_url(text)
    return url.scheme, url.host.name, url.port, url.userinfo


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("https://example.com", ("https", "example.com", 443, False)),
        ("HTTP://Example.COM./path?q#f", ("http", "example.com", 80, False)),
        ("ws://example.com", ("ws", "example.com", 80, False)),
        ("wss://example.com", ("wss", "example.com", 443, False)),
        ("ftp://example.com", ("ftp", "example.com", 21, False)),
        ("file://server/share", ("file", "server", None, False)),
        ("ssh://git@github.com:22/org/repo", ("ssh", "github.com", 22, True)),
        ("git://github.com/org/repo", ("git", "github.com", None, False)),
        ("https://example.com:8443/", ("https", "example.com", 8443, False)),
        ("https://example.com:/", ("https", "example.com", 443, False)),
        ("https://example.com:0443", ("https", "example.com", 443, False)),
        ("https://example.com:0", ("https", "example.com", 0, False)),
        ("https://example.com:65535", ("https", "example.com", 65535, False)),
        ("http://[::1]:8080/", ("http", "::1", 8080, False)),
        ("http://[::1]/", ("http", "::1", 80, False)),
        ("http://[::ffff:127.0.0.1]", ("http", "127.0.0.1", 80, False)),
        ("https://user:pw@example.com/", ("https", "example.com", 443, True)),
        ("https://@example.com/", ("https", "example.com", 443, True)),
        ("https://allowed.com@evil.com/", ("https", "evil.com", 443, True)),
        ("https://a b%25:c@example.com/", ("https", "example.com", 443, True)),
        ("https://example.com/@evil.com", ("https", "example.com", 443, False)),
        ("https://example.com/x?to=a@b.com", ("https", "example.com", 443, False)),
        ("https://example.com/a\\b", ("https", "example.com", 443, False)),
        ("  https://example.com/  ", ("https", "example.com", 443, False)),
        ("\x00\x1fhttps://example.com\x7f"[:-1], ("https", "example.com", 443, False)),
        ("example.com", (None, "example.com", None, False)),
        ("example.com/path", (None, "example.com", None, False)),
        ("example.com:8443/x", (None, "example.com", 8443, False)),
        ("localhost:8080", (None, "localhost", 8080, False)),
        ("//example.com/x", (None, "example.com", None, False)),
        ("user:pw@example.com", (None, "example.com", None, True)),
        ("B\u00fccher.de", (None, "xn--bcher-kva.de", None, False)),
    ],
)
def test_scheme_host_port_and_userinfo(hk: SimpleNamespace, text: str, want: tuple[object, ...]) -> None:
    assert _url(hk, text) == want


@pytest.mark.parametrize(
    "text",
    [
        "",
        "https://",
        "https://user@",
        "https:example.com",
        "https:/example.com",
        "https:\\\\example.com",
        "https:/\\example.com",
        "https:///example.com",
        "https://\\example.com",
        "///example.com",
        "/path",
        "\\\\server\\share",
        "http://ex\tample.com/",
        "http://example.com/\nx",
        "http://example.com/a\x00b",
        "http://example.com/a\x7fb",
        "https://evil.com\\@allowed.com",
        "https://evil.com\\.allowed.com",
        "https://allowed.com#@evil.com",
        "https://allowed.com?@evil.com",
        "https://allowed.com?x=@evil.com",
        "https://a@b@evil.com",
        "https://allowed.com%2F@evil.com",
        "https://allowed.com%2f@evil.com",
        "https://allowed.com%3F@evil.com",
        "https://allowed.com%23@evil.com",
        "https://allowed.com%40@evil.com",
        "https://allowed.com%5C@evil.com",
        "https://allowed.com\uff0f@evil.com",
        "https://allowed.com\uff03@evil.com",
        "https://allowed.com\ufe6b@evil.com",
        "https://example.com:x/",
        "https://example.com:-1/",
        "https://example.com:65536/",
        "https://example.com:" + "9" * 30,
        "https://example.com:\u0661\u0662",
        "https://example.com:80:80/",
        "http://[::1/",
        "http://[::1]x/",
        "http://[::1]:x/",
        "http://::1/",
        "http://1::2:80/",
        "http://0x7f.1/",
        "http://10.0x.0x.1/",
        "http://127.0.0.1./",
        "file:///etc/passwd",
        "file://host:1/",
        "data:text/plain,hi",
        "javascript:alert(1)",
        "https://" + "a" * 8200,
    ],
)
def test_urls_parsers_disagree_on_are_refused(hk: SimpleNamespace, text: str) -> None:
    with pytest.raises(hk.hosts.UnparseableError):
        hk.urls.parse_url(text)


def test_a_non_string_is_a_caller_error(hk: SimpleNamespace) -> None:
    with pytest.raises(TypeError):
        hk.urls.parse_url(None)


def test_default_ports_are_the_url_standard_special_schemes(hk: SimpleNamespace) -> None:
    assert hk.urls.DEFAULT_PORTS == {"ftp": 21, "file": None, "http": 80, "https": 443, "ws": 80, "wss": 443}
