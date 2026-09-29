"""The comms pack (ASI07): certificate checks switched off on the channels agents talk over."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agentic_gate import jsscan
from agentic_gate.model import FileText, Hit, Pack, Rule
from agentic_gate.pyast import assigned_false, dotted, is_false, settings, tree
from agentic_gate.textscan import find, scan_lines

PACK = Pack(
    id="comms",
    title="Inter-agent communication",
    covers="TLS certificate verification disabled in Python HTTP clients, the ssl module and Node.",
    asi=("ASI07",),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_HTTP_LIBS = ("requests", "httpx", "urllib3", "aiohttp", "boto")
_JS_REJECT = re.compile(r"\brejectUnauthorized\s*:\s*false\b")
_NODE_ENV = re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED[\s\"'\]=:]{1,8}0(?![\w.])")
_SSL_UNVERIFIED = frozenset({"ssl._create_unverified_context", "_create_unverified_context"})
_SSL_NONE = frozenset({"ssl.CERT_NONE", "CERT_NONE"})


def _verify_off(text: FileText) -> Iterator[Hit]:
    if not text.holds(*_HTTP_LIBS):
        return
    detail = "verify=False accepts any certificate, so the peer is never authenticated."
    for line_no, value in settings(text, "verify"):
        if is_false(value):
            yield Hit(line_no, detail)
    for line_no in assigned_false(text, "verify"):
        yield Hit(line_no, detail)


def _ssl_context(text: FileText) -> Iterator[Hit]:
    parsed = tree(text)
    for node in ast.walk(parsed) if parsed else ():
        if isinstance(node, ast.Name | ast.Attribute) and dotted(node) in _SSL_UNVERIFIED:
            yield Hit(node.lineno, "ssl._create_unverified_context() builds a context that trusts every certificate.")
        elif isinstance(node, ast.Name | ast.Attribute) and dotted(node) in _SSL_NONE:
            yield Hit(node.lineno, "ssl.CERT_NONE turns certificate validation off.")
    for line_no, value in settings(text, "check_hostname"):
        if is_false(value):
            yield Hit(line_no, "check_hostname False accepts a certificate for any host.")
    for line_no in assigned_false(text, "check_hostname"):
        yield Hit(line_no, "check_hostname = False accepts a certificate for any host.")


def _node_tls(text: FileText) -> Iterator[Hit]:
    if text.kind == "js":
        yield from find(jsscan.shape(text.text), _JS_REJECT, "rejectUnauthorized: false accepts any certificate.")
    yield from scan_lines(text, _NODE_ENV, "NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate checks process-wide.")


RULES: tuple[Rule, ...] = (
    Rule(
        id="comms-tls-verify-disabled",
        pack="comms",
        title="TLS verification off on an HTTP client",
        why="Without verification anyone on the network path can impersonate the peer and read or alter agent traffic.",
        kinds=("python",),
        scan=_verify_off,
        fix="remove verify=False; if a private CA signs the peer, pass verify='/path/to/ca.pem'.",
        refuses="verify=False on a requests, httpx, urllib3 or aiohttp call, client or session (also session.verify = False)",
        silent_on="verify=True, verify='/path/to/ca.pem', no verify argument",
        cwe=("CWE-295",),
        asi=("ASI07",),
        references=(*_OWASP, "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification"),
    ),
    Rule(
        id="comms-ssl-context-unverified",
        pack="comms",
        title="ssl context that does not verify the peer",
        why="A context that accepts any certificate authenticates nobody, so the encryption protects nothing from a man in the middle.",
        kinds=("python",),
        scan=_ssl_context,
        fix="use ssl.create_default_context() and leave check_hostname and verify_mode at their defaults.",
        refuses="ssl._create_unverified_context, ssl.CERT_NONE, check_hostname = False",
        silent_on="ssl.create_default_context(), CERT_REQUIRED",
        cwe=("CWE-295", "CWE-297"),
        asi=("ASI07",),
        references=(*_OWASP, "https://docs.python.org/3/library/ssl.html#security-considerations"),
    ),
    Rule(
        id="comms-node-tls-disabled",
        pack="comms",
        title="Node TLS verification off",
        why="One flag disables certificate checks for every HTTPS request the process makes.",
        kinds=("python", "js", "yaml", "shell", "env", "dockerfile"),
        scan=_node_tls,
        fix="remove the override; trust a private CA with NODE_EXTRA_CA_CERTS=/path/to/ca.pem instead.",
        refuses="rejectUnauthorized: false; NODE_TLS_REJECT_UNAUTHORIZED set to 0 in code, env files, YAML, shell or Dockerfiles",
        silent_on="rejectUnauthorized: true, NODE_EXTRA_CA_CERTS, NODE_TLS_REJECT_UNAUTHORIZED=1",
        cwe=("CWE-295",),
        asi=("ASI07",),
        references=(*_OWASP, "https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue"),
    ),
)
