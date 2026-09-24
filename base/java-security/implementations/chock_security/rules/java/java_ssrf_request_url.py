"""A URL built from request data lets the caller choose which host this server calls out to."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-ssrf-request-url"

_FACTS = facts("java")["ssrf"]

_MESSAGE = (
    "This outbound call is built from {source}, so the caller chooses which host this server "
    "connects to -- including internal services, the cloud metadata endpoint, and file:// or "
    "other URLs the client library will happily open. Resolve the value against a fixed allowlist "
    "of hosts (or a schema of known endpoints) before it reaches this call, rather than building "
    f"the destination from it directly. A destination that must stay dynamic needs "
    f"'chock: allow {RULE_ID}' on this line, with that allowlist behind it."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every outbound URL call a method body shows request data reaching."""
    for flow in flows(text, _FACTS["sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Outbound URL built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(call): new URL|URI.create|new URI|HttpRequest.newBuilder|.uri(|.getForObject|"
        ".getForEntity|.exchange(|new HttpGet|new HttpPost|.url(|Jsoup.connect over "
        "@RequestParam|@PathVariable|request.get* -- check the host against a fixed allowlist "
        "before it reaches the call"
    ),
    refuses=(
        "a `new URL`, `URI.create`/`new URI`, `HttpRequest.newBuilder`/`.uri`, RestTemplate/"
        "WebClient call, `HttpGet`/`HttpPost`, OkHttp `.url`, or `Jsoup.connect` a method body "
        "shows request data reaching"
    ),
    silent_on=(
        "a constant or configured URL; a host checked against an allowlist before the call; the "
        "same builder called with no request data reaching it"
    ),
)
