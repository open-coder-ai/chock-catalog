"""A trust manager or hostname verifier that accepts everything makes TLS decorative: any
certificate for any host is accepted, so the connection authenticates nobody."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "crypto-tls-trust-all"

_FACTS = facts("crypto")["tls_trust"]

_TRUST_METHODS = frozenset({"checkServerTrusted", "checkClientTrusted"})
_METHOD_DECL = re.compile(r"\b(checkServerTrusted|checkClientTrusted|verify)\s*\(")

_MESSAGE_TRUST = (
    "{name} never rejects a certificate -- its body is empty or only returns -- so this trust "
    "manager accepts any certificate for any host, which is the same as not checking one. "
    "Delegate to the platform's default TrustManagerFactory (or a pinned one) and throw "
    f"CertificateException on failure. A test double needs 'chock: allow {RULE_ID}' on this line."
)
_MESSAGE_VERIFIER = (
    "This hostname verifier always returns true, so it never checks that the certificate matches "
    "the host you connected to -- a valid certificate for any site passes. Verify the session's "
    f"peer host against the presented name, or drop the custom verifier. 'chock: allow {RULE_ID}' "
    "on this line if a test double genuinely needs it."
)
_MESSAGE_TOKEN = (
    "{token} disables certificate validation outright, so this connection trusts whatever server "
    "answers. Use the platform default trust manager and hostname verifier, or one pinned to a "
    f"known certificate. 'chock: allow {RULE_ID}' on this line if this is a throwaway test client."
)


def _method_body(lines: list[str], decl_idx: int) -> tuple[str, int] | None:
    """The braced body text following a declaration, and the line its closing brace sits on.

    A local, single-purpose stand-in for flow.methods(): that one drops a body with zero
    statement lines (`{}`, or braces around nothing but whitespace), which is exactly the shape
    a trust-everything override takes -- so it cannot tell us this method is trivial at all.
    """
    depth = 0
    opened = False
    collected: list[str] = []
    for index in range(decl_idx, len(lines)):
        current = lines[index]
        if not opened:
            if "{" not in current:
                if ";" in current:
                    return None  # an abstract or interface declaration, not an override
                continue
            opened = True
        depth += current.count("{") - current.count("}")
        collected.append(current)
        if depth <= 0:
            text = "\n".join(collected)
            return text[text.find("{") + 1 : text.rfind("}")], index + 1
    return None


def _trivial(body: str) -> bool:
    """Whether a method body never does more than return -- so it never actually checks anything."""
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped in _FACTS["trivial_return_lines"]:
            continue
        return False
    return True


def _declared_methods(text: FileText, names: frozenset[str]) -> Iterator[tuple[str, str, int]]:
    lines = text.lines
    for index, line in enumerate(lines):
        match = _METHOD_DECL.search(line)
        if not match or match.group(1) not in names:
            continue
        found = _method_body(lines, index)
        if found is not None:
            yield match.group(1), found[0], found[1]


def _trust_manager_findings(text: FileText) -> Iterator[Finding]:
    if not text.holds(_FACTS["trust_manager_marker"]):
        return
    for name, body, line_no in _declared_methods(text, _TRUST_METHODS):
        if _trivial(body):
            line = text.lines[line_no - 1] if 0 < line_no <= len(text.lines) else name
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE_TRUST.format(name=name))


def _hostname_verifier_findings(text: FileText) -> Iterator[Finding]:
    if not text.holds(_FACTS["hostname_verifier_marker"]):
        return
    for name, body, line_no in _declared_methods(text, frozenset({"verify"})):
        if _trivial(body) and "return true;" in body:
            line = text.lines[line_no - 1] if 0 < line_no <= len(text.lines) else name
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE_VERIFIER)
    for line_no, line in enumerate(text.lines, 1):
        if "->" in line and "true" in line and _FACTS["hostname_verifier_marker"].lower() in line.lower():
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE_VERIFIER)


def _unambiguous_token_findings(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(text.lines, 1):
        token = next((t for t in _FACTS["unambiguous_tokens"] if t in line), None)
        if token is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE_TOKEN.format(token=token))


def scan(text: FileText) -> Iterator[Finding]:
    """Every trust-everything trust manager, hostname verifier, or well-known insecure shortcut."""
    yield from _trust_manager_findings(text)
    yield from _hostname_verifier_findings(text)
    yield from _unambiguous_token_findings(text)


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="TLS trust manager or hostname verifier that accepts everything",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(implement): checkServerTrusted|checkClientTrusted with an empty or return-only body, "
        "or a HostnameVerifier.verify that always returns true, or NoopHostnameVerifier|"
        "ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy|TrustSelfSignedStrategy|"
        "InsecureTrustManagerFactory.INSTANCE -- delegate to the platform default or a pinned trust store"
    ),
    refuses=(
        "a checkServerTrusted/checkClientTrusted body that never throws; a verify() that always "
        "returns true; NoopHostnameVerifier, ALLOW_ALL_HOSTNAME_VERIFIER, TrustAllStrategy, "
        "TrustSelfSignedStrategy, InsecureTrustManagerFactory.INSTANCE"
    ),
    silent_on="a trust manager or verifier that delegates to a real check and can reject",
)
