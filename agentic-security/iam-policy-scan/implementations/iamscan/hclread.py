"""Terraform and OpenTofu: policy documents, `jsonencode` and heredoc policies, and Azure role assignments."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_scan import hcl, jsonc

from iamscan import azure
from iamscan.aws import judge
from iamscan.model import BLOCK
from iamscan.walk import Scan, Spot

JSONENCODE = re.compile(r"\bjsonencode\s*\(")
TRY_FACTOR = (
    8  # an expression's calls are parsed for at most this many times its length, so `)))` cannot stall the hook
)
TRY_FLOOR = 10_000
QUOTED_MIN = 2
UNESCAPED_QUOTE = re.compile(r'(?<!\\)(?:\\\\)*"')
QUOTE_ESCAPE = re.compile(r"\\(.)")
HEREDOC = re.compile(r"(?s)<<-?\s*(\w+)[ \t]*\n(.*?)\n[ \t]*\1[ \t]*$")
INTERPOLATION = re.compile(r"\$\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}|%\{[^{}]*\}")
RISKY = re.compile(r"(?i)\b(?:effect|action|principal|statement)\b")
RISKY_KEY = re.compile(r'(?i)"(?:effect|action|principal|statement)"')
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
    if value is hcl.COMPUTED and (text := _quoted(attr.expr)) is not None:
        _template_json(text, attr.line, span, scan_, strict=False)
    scan_.walk(_plain(value), attr.line, span)
    for inner, argument in _jsonencoded(attr.expr):
        if inner is hcl.COMPUTED and argument.lstrip().startswith(("{", "[")) and RISKY.search(argument):
            scan_.unreadable("a jsonencode policy with a computed key cannot be read", attr.line)
        else:
            scan_.walk(_plain(inner), attr.line, span)


def _quoted(expr: str) -> str | None:
    """The text of an expression that is one quoted string, its escapes undone; None for anything else."""
    text = expr.strip()
    if len(text) < QUOTED_MIN or text[0] != '"' or text[-1] != '"' or UNESCAPED_QUOTE.search(text[1:-1]):
        return None
    return QUOTE_ESCAPE.sub(lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), text[1:-1])


def _jsonencoded(expr: str) -> Iterator[tuple[object, str]]:
    """The value each `jsonencode(...)` in an expression spells, however it is wrapped or nested in another."""
    budget = [TRY_FACTOR * len(expr) + TRY_FLOOR]
    pending = [expr]
    while pending:
        text = pending.pop()
        end = 0
        for call in JSONENCODE.finditer(text):
            if call.start() < end:
                continue
            for close in _closers(text, call.end()):
                budget[0] -= close - call.end()
                if budget[0] < 0:
                    msg = "more jsonencode text than the gate reads in one expression"
                    raise ValueError(msg)
                argument = text[call.end() : close]
                try:
                    inner = hcl.parse(f"x = {argument}\n").attributes[0]
                except (hcl.HclError, IndexError):
                    continue
                end = close
                pending.append(argument)
                yield inner.value, argument
                break


def _closers(expr: str, start: int) -> Iterator[int]:
    """Each `)` after `start` where the parentheses so far balance, then the rest (a `)` may sit in a string)."""
    depth, rest = 0, []
    for at in range(start, len(expr)):
        if expr[at] == "(":
            depth += 1
        elif expr[at] == ")":
            if depth == 0:
                yield at
            else:
                rest.append(at)
            depth -= 1
    yield from rest


def _template_json(body: str, line: int, span: tuple[int, int], scan_: Scan, *, strict: bool = True) -> None:
    """A heredoc that interpolates is computed to the HCL reader; read its JSON with each `${}` made a placeholder."""
    for filler in ("TPL", '"TPL"'):
        text = INTERPOLATION.sub(filler, body)
        try:
            jsonc.loads(text)
        except jsonc.JsoncError:
            continue
        scan_.embedded(text, line, span, 0)
        return
    if strict and body.lstrip().startswith(("{", "[")) and RISKY_KEY.search(body):
        scan_.unreadable("a heredoc policy with interpolation cannot be read", line)
