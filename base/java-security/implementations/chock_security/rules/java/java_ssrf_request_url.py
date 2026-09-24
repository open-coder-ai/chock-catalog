"""A URL built from request data lets the caller choose which host this server calls out to."""

from __future__ import annotations

import re
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


#: A destination whose literal start already names the host -- or is a path on this server -- leaves
#: the caller only a path or a query to vary, never where the request goes.
_FIXED_HOST = re.compile(r'^"(?:/(?!/)|[a-zA-Z][a-zA-Z0-9+.-]*://[^/"?#{}+\s]+[/?])')


def _destination_is_fixed(line: str) -> bool:
    """Whether the sink's first argument opens with a literal that fixes the host (or is relative).

    Only ever called on a flow's own line, which `flows()` has already matched against this same
    sink list, so one of them is always present here.
    """
    sink = next(s for s in _FACTS["sinks"] if s in line)
    at = line.find(sink)
    return bool(_FIXED_HOST.match(line[at + len(sink) :].lstrip()))


def scan(text: FileText) -> Iterator[Finding]:
    """Every outbound URL call a method body shows request data reaching, where the host is not fixed."""
    for flow in flows(text, _FACTS["sinks"]):
        if _destination_is_fixed(flow.line):
            continue
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
        'a constant or configured URL; a literal that fixes scheme and host (`"https://api.x/v1?q=" + q`) '
        'or is a path on this server (`"/users/" + id`); a host checked against an allowlist before the '
        "call; the same builder called with no request data reaching it"
    ),
    cwe=("CWE-918",),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
)
