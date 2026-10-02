"""Terraform and OpenTofu: policy documents, `jsonencode` and heredoc policies, and Azure role assignments."""

from __future__ import annotations

import re

from chock_scan import hcl, jsonc

from iamscan import azure
from iamscan.aws import judge
from iamscan.model import BLOCK
from iamscan.walk import Scan, Spot

JSONENCODE = re.compile(r"(?s)jsonencode\s*\((.*)\)")
HEREDOC = re.compile(r"(?s)<<-?\s*(\w+)[ \t]*\n(.*?)\n[ \t]*\1[ \t]*$")
INTERPOLATION = re.compile(r"\$\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}|%\{[^{}]*\}")
RISKY = re.compile(r"(?i)\b(?:effect|action|principal|statement)\b")
POLICY_DOCUMENT = ("aws_iam_policy_document",)
RENAMED = {"actions": "Action", "not_actions": "NotAction", "resources": "Resource", "not_resources": "NotResource"}


def scan_block(root: hcl.Block, scan_: Scan, *, nested: bool = True) -> None:
    """Every grant under a parsed Terraform body: judged where it is written.

    `nested` is False for the JSON syntax, where a value that can be read as blocks is also an attribute of its
    parent: the parent's attributes already hold what the nested blocks repeat.
    """
    for attr in root.attributes:
        _attribute(attr, scan_)
    for block in hcl.walk(root) if nested else root.blocks:
        _block(block, scan_)
        for attr in block.attributes:
            _attribute(attr, scan_)


def _block(block: hcl.Block, scan_: Scan) -> None:
    if block.type == "data" and block.labels[:1] == POLICY_DOCUMENT:
        for child in block.blocks:
            for statement in _statements(child):
                _judge(statement, block.line, scan_)
    elif block.type == "resource" and block.labels[:1] == ("azurerm_role_assignment",):
        attrs = {a.key: (a.expr, a.value) for a in block.attributes}
        if azure.terraform_assignment(attrs):
            scan_.add("azure-subscription-owner", BLOCK, attrs, Spot(block.line, "role_definition_name", (block.line,)))


def _statements(child: hcl.Block) -> list[hcl.Block]:
    """`statement` blocks, and the `content` of a `dynamic "statement"`, which is read as written."""
    if child.type == "statement":
        return [child]
    if child.type == "dynamic" and child.labels[:1] == ("statement",):
        return [b for b in child.blocks if b.type == "content"]
    return []


def _judge(block: hcl.Block, line: int, scan_: Scan) -> None:
    statement = {RENAMED[a.key]: _plain(a.value) for a in block.attributes if a.key in RENAMED}
    statement["Effect"] = next((_plain(a.value) for a in block.attributes if a.key == "effect"), "Allow")
    for name, label in (("principals", "Principal"), ("not_principals", "NotPrincipal")):
        grouped = [_principal(b) for b in block.children(name)]
        if grouped:
            statement[label] = {k: v for g in grouped for k, v in g.items()}
    conditions = [c for c in block.children("condition") if all(c.attr(k) for k in ("test", "variable", "values"))]
    if conditions:
        statement["Condition"] = {_text(c, "test"): {_text(c, "variable"): _values(c)} for c in conditions}
    for hit in judge(statement):
        at = next((a.line for a in block.attributes if RENAMED.get(a.key, "").lower() == hit.hint), block.line)
        scan_.add(hit.rule, hit.tier, statement, Spot(at, hit.hint, (at, block.line, line)))


def _principal(block: hcl.Block) -> dict:
    ids = block.attr("identifiers")
    return {_text(block, "type") or "AWS": _plain(ids.value) if ids else []}


def _text(block: hcl.Block, key: str) -> str:
    attr = block.attr(key)
    return attr.value if attr and isinstance(attr.value, str) else ""


def _values(block: hcl.Block) -> object:
    attr = block.attr("values")
    return _plain(attr.value) if attr else []


def _plain(value: object) -> object:
    """A literal as the walker reads it: tuples are lists, anything computed is dropped to an empty string."""
    if value is hcl.COMPUTED:
        return ""
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def _attribute(attr: hcl.Attribute, scan_: Scan) -> None:
    value = attr.value
    span = (attr.line, attr.line + attr.expr.count("\n"))
    if value is hcl.COMPUTED and (heredoc := HEREDOC.fullmatch(attr.expr.strip())):
        _template_json(heredoc.group(2), attr.line, span, scan_)
        return
    if value is hcl.COMPUTED and (call := JSONENCODE.fullmatch(attr.expr.strip())):
        inner = hcl.parse(f"x = {call.group(1)}\n").attributes[0]
        value = inner.value
        if value is hcl.COMPUTED and RISKY.search(attr.expr):
            scan_.unreadable("a jsonencode policy with a computed key cannot be read", attr.line)
            return
    scan_.walk(_plain(value), attr.line, span)


def _template_json(body: str, line: int, span: tuple[int, int], scan_: Scan) -> None:
    """A heredoc that interpolates is computed to the HCL reader; read its JSON with each `${}` made a placeholder."""
    for filler in ("TPL", '"TPL"'):
        text = INTERPOLATION.sub(filler, body)
        try:
            jsonc.loads(text)
        except jsonc.JsoncError:
            continue
        scan_.embedded(text, line, span, 0)
        return
    if RISKY.search(body):
        scan_.unreadable("a heredoc policy with interpolation cannot be read", line)
