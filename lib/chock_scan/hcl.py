"""HCL2 block scanner for Terraform, OpenTofu and Packer: blocks, labels, attributes and literal values, with lines.

Nothing is evaluated. An attribute keeps its expression as raw source text; `value` is the literal it
spells (str, int, float, bool, None, tuple, dict) and COMPUTED wherever it is anything else: a
reference, call, operator, template interpolation, for-expression, `count`, `for_each`. A `dynamic`
block is returned as written (type "dynamic", label the generated block type, its `content` nested):
a caller looking for a block type must also look there, and treat it as computed. Text this scanner
cannot read raises HclError (also exported here); it never yields a partial or empty result instead.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from .hcl_lex import BOM, COMPUTED, MAX_DEPTH, Computed, HclError, Lines, Token, tokens

__all__ = ["COMPUTED", "Attribute", "Block", "Computed", "HclError", "is_computed", "parse", "walk"]

CLOSE = {"(": ")", "[": "]", "{": "}"}
CLOSERS = frozenset(CLOSE.values())
TUPLE_STOPS = frozenset({",", "]"})
OBJECT_STOPS = frozenset({",", "}", "NL"})
KEYWORDS = {"true": True, "false": False, "null": None}


@dataclass(frozen=True)
class Attribute:
    key: str
    expr: str  # the expression's source text, verbatim (a comment inside brackets stays in it)
    line: int
    value: object  # the literal, or COMPUTED (in place of each part that is not a literal)

    @property
    def computed(self) -> bool:
        return is_computed(self.value)


@dataclass(frozen=True)
class Block:
    type: str
    labels: tuple[str, ...]
    line: int
    attributes: tuple[Attribute, ...]
    blocks: tuple[Block, ...]

    def attr(self, key: str) -> Attribute | None:
        return next((a for a in self.attributes if a.key == key), None)

    def children(self, block_type: str) -> tuple[Block, ...]:
        return tuple(b for b in self.blocks if b.type == block_type)


def parse(text: str) -> Block:
    """The file as a root Block (type "", line 1); a tfvars file is a root with attributes only."""
    attributes, blocks = _Parser(text).file()
    return Block("", (), 1, attributes, blocks)


def walk(block: Block) -> Iterator[Block]:
    """Every block under `block`, depth first, in source order (the root itself excluded)."""
    for child in block.blocks:
        yield child
        yield from walk(child)


def is_computed(value: object) -> bool:
    """True if `value` is COMPUTED or holds COMPUTED anywhere inside it."""
    if isinstance(value, tuple):
        return any(is_computed(v) for v in value)
    if isinstance(value, dict):
        return any(is_computed(v) for v in value.values())
    return value is COMPUTED


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text.removeprefix(BOM)
        self.toks = tokens(self.text)
        self.line = Lines(self.text)
        self.i = 0

    def peek(self) -> Token:
        return self.toks[self.i]

    def take(self) -> Token:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def file(self) -> tuple[tuple[Attribute, ...], tuple[Block, ...]]:
        found = self.body(0)
        if (tok := self.peek()).kind != "EOF":
            msg = f"unexpected {tok.text!r}"
            raise HclError(msg, self.line(tok.start))
        return found

    def body(self, depth: int) -> tuple[tuple[Attribute, ...], tuple[Block, ...]]:
        """Attributes and blocks up to EOF or a `}` (left for the caller); duplicate attributes refused."""
        attributes: list[Attribute] = []
        blocks: list[Block] = []
        keys: set[str] = set()
        while (tok := self.peek()).kind != "EOF" and tok.text != "}":
            if tok.kind == "NL":
                self.take()
                continue
            if tok.kind != "IDENT":
                msg = f"expected an attribute or block name, found {tok.text!r}"
                raise HclError(msg, self.line(tok.start))
            if self.toks[self.i + 1].text == "=" and self.toks[self.i + 1].kind == "PUNCT":
                attr = self.attribute()
                if attr.key in keys:
                    msg = f"attribute {attr.key!r} defined twice in one body"
                    raise HclError(msg, attr.line)
                keys.add(attr.key)
                attributes.append(attr)
            else:
                blocks.append(self.block(depth + 1))
        return tuple(attributes), tuple(blocks)

    def attribute(self) -> Attribute:
        name = self.take()
        self.take()
        first = self.i
        stack: list[str] = []
        while True:
            tok = self.peek()
            if tok.kind == "EOF" or (not stack and (tok.kind == "NL" or tok.text == "}")):
                break
            self.take()
            if tok.kind == "PUNCT":
                self.track(stack, tok, name.text)
        if stack:
            msg = f"{name.text}: unclosed bracket in the expression"
            raise HclError(msg, self.line(name.start))
        expr = self.toks[first : self.i]
        if not expr:
            msg = f"{name.text}: missing expression after '='"
            raise HclError(msg, self.line(name.start))
        raw = self.text[expr[0].start : expr[-1].end]
        return Attribute(name.text, raw, self.line(name.start), _literal(expr))

    def track(self, stack: list[str], tok: Token, name: str) -> None:
        """Keep the expression's open brackets on `stack`; a mismatch, a top-level '=' or too deep raises."""
        if tok.text in CLOSE:
            stack.append(CLOSE[tok.text])
            if len(stack) > MAX_DEPTH:
                msg = f"brackets nested deeper than {MAX_DEPTH}"
                raise HclError(msg, self.line(tok.start))
        elif tok.text in CLOSERS:
            if not stack or stack.pop() != tok.text:
                msg = f"unbalanced {tok.text!r}"
                raise HclError(msg, self.line(tok.start))
        elif tok.text == "=" and not stack:
            msg = f"a second '=' after {name} = (two attributes on one line?)"
            raise HclError(msg, self.line(tok.start))

    def block(self, depth: int) -> Block:
        name = self.take()
        if depth > MAX_DEPTH:
            msg = f"blocks nested deeper than {MAX_DEPTH}"
            raise HclError(msg, self.line(name.start))
        labels: list[str] = []
        while (tok := self.take()).text != "{" or tok.kind != "PUNCT":
            if tok.kind == "IDENT":
                labels.append(tok.text)
            elif tok.kind == "STRING" and isinstance(tok.value, str):
                labels.append(tok.value)
            else:
                msg = f"block {name.text}: expected a label or '{{', found {tok.text!r}"
                raise HclError(msg, self.line(tok.start))
        attributes, blocks = self.body(depth)
        if (close := self.take()).kind == "EOF":
            msg = f"block {name.text} is never closed"
            raise HclError(msg, self.line(name.start))
        if (after := self.peek()).kind not in ("NL", "EOF") and after.text != "}":
            msg = f"block {name.text}: {after.text!r} after its closing brace"
            raise HclError(msg, self.line(close.start))
        return Block(name.text, tuple(labels), self.line(name.start), attributes, blocks)


def _literal(expr: list[Token]) -> object:
    value, end = _value(expr, 0)
    return value if end == len(expr) else COMPUTED


def _value(toks: list[Token], i: int) -> tuple[object, int]:  # noqa: PLR0911 -- one return per literal form
    """The literal starting at toks[i] and the index after it; (COMPUTED, i) when it is not one."""
    tok = toks[i]
    if tok.kind in ("STRING", "HEREDOC"):
        return tok.value, i + 1
    if tok.kind == "NUMBER":
        return _number(tok.text), i + 1
    if _is(tok, "-") and i + 1 < len(toks) and toks[i + 1].kind == "NUMBER":
        return -_number(toks[i + 1].text), i + 2
    if tok.kind == "IDENT" and tok.text in KEYWORDS:
        return KEYWORDS[tok.text], i + 1
    if _is(tok, "["):
        return _sequence(toks, i)
    if _is(tok, "{"):
        return _mapping(toks, i)
    return COMPUTED, i


def _number(text: str) -> int | float:
    return float(text) if any(c in text for c in ".eE") else int(text)


def _is(tok: Token, text: str) -> bool:
    return tok.kind == "PUNCT" and tok.text == text


def _element(toks: list[Token], i: int, stops: frozenset[str]) -> tuple[object, int]:
    """One element, up to a top-level stop token ("NL" in stops: a newline too); COMPUTED unless a literal."""
    value, j = _value(toks, _skip_nl(toks, i))
    if "NL" not in stops:
        j = _skip_nl(toks, j)
    if _at_stop(toks[j], stops):
        return value, j
    depth = 0
    while depth or not _at_stop(toks[j], stops):
        depth += toks[j].kind == "PUNCT" and toks[j].text in CLOSE
        depth -= toks[j].kind == "PUNCT" and toks[j].text in CLOSERS
        j += 1
    return COMPUTED, j


def _at_stop(tok: Token, stops: frozenset[str]) -> bool:
    return (tok.kind == "NL" and "NL" in stops) or (tok.kind == "PUNCT" and tok.text in stops)


def _skip_nl(toks: list[Token], i: int) -> int:
    while toks[i].kind == "NL":
        i += 1
    return i


def _sequence(toks: list[Token], start: int) -> tuple[object, int]:
    """A tuple `[a, b]` of literals (COMPUTED in place of each element that is not one); `[for ...]` is COMPUTED."""
    items: list[object] = []
    i = _skip_nl(toks, start + 1)
    if toks[i].kind == "IDENT" and toks[i].text == "for":
        return COMPUTED, _close(toks, start)
    while not _is(toks[i], "]"):
        value, i = _element(toks, i, TUPLE_STOPS)
        items.append(value)
        i = _skip_nl(toks, i + _is(toks[i], ","))
    return tuple(items), i + 1


def _mapping(toks: list[Token], start: int) -> tuple[object, int]:
    """An object `{k = v, k: v}` with literal keys; a computed or repeated key makes the whole object COMPUTED."""
    items: dict[str, object] = {}
    i = _skip_nl(toks, start + 1)
    while not _is(toks[i], "}"):
        key = toks[i]
        name = key.text if key.kind == "IDENT" and key.text != "for" else key.value if key.kind == "STRING" else None
        if not isinstance(name, str) or name in items or not (_is(toks[i + 1], "=") or _is(toks[i + 1], ":")):
            return COMPUTED, _close(toks, start)
        value, i = _element(toks, i + 2, OBJECT_STOPS)
        items[name] = value
        i = _skip_nl(toks, i + _is(toks[i], ","))
    return items, i + 1


def _close(toks: list[Token], start: int) -> int:
    """The index after the bracket matching the opener at toks[start]."""
    depth = 0
    i = start
    while True:
        depth += toks[i].kind == "PUNCT" and toks[i].text in CLOSE
        depth -= toks[i].kind == "PUNCT" and toks[i].text in CLOSERS
        i += 1
        if not depth:
            return i
