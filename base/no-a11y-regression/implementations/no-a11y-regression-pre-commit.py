#!/usr/bin/env python3
"""Refuse a staged change that destroys an accessibility assertion an element already carried."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data"
# What each element must carry, and what may satisfy it. Adding a row adds a check, with no code.
SPEC = json.loads((_DATA / "element_requirements.json").read_text(encoding="utf-8"))
REQUIRED = SPEC["requirements"]
VOID = frozenset(SPEC["void_elements"])
# Props that carry a name on an element this table has no requirements for.
COMPONENT_NAME_PROPS = tuple(SPEC["component_name_props"])
MARKUP_SUFFIXES = tuple(SPEC["markup_suffixes"])
BOUND = SPEC["bound_attributes"]
GLYPH = SPEC["glyph_text"]
TEXT_PROPS = tuple(SPEC["component_text_props"])
# Names that are present but convey nothing, so their presence is not a fix.
NOISE = json.loads((_DATA / "uninformative_names.json").read_text(encoding="utf-8"))

# ── What an element asserts about its own meaning. Five values, nothing else. ─────────────────
SATISFIED = "satisfied"  # a person supplied what this element requires
SUPPRESSED = "suppressed"  # a person stated it means nothing: alt="", aria-hidden, role=presentation
MISSING = "missing"  # the requirement is unmet -- this is the violating state
EXEMPT = "exempt"  # no requirement applies to this element in this form
GONE = "gone"  # not present in this revision
UNEVALUATED = "unevaluated"  # a component child or a prop spread hides the name from this parser
NAMELESS = "nameless"  # a component carrying no name prop: we cannot know whether it needs one

#: States an author deliberately put an element into. One of these disappearing alongside a
#: deletion is what separates a block being removed from a violation being hidden.
_AUTHORED = (SATISFIED, SUPPRESSED)

# ── The only judgement in the program: authored once, reviewable as a diff. ───────────────────
# This gate never asks a question. A patch that correctly fixes a hundred images must cost zero
# interruptions, so a correct fix is silent and only a break refuses the commit. A warning is printed
# and never blocks: it names a new element or a weak name, which is not a regression.
DENY, WARN, RECORD, SILENT = "deny", "warn", "record", "silent"

TABLE: dict[tuple[str, str], tuple[str, str]] = {
    (SATISFIED, SATISFIED): (SILENT, "the requirement is met in both revisions"),
    (SATISFIED, SUPPRESSED): (DENY, "retracts a person's statement that this element carries meaning"),
    (SATISFIED, MISSING): (DENY, "the requirement was met and is now broken"),
    (SATISFIED, GONE): (SILENT, "the element was deleted -- ordinary product work"),
    (SUPPRESSED, SATISFIED): (RECORD, "a decorative element gained meaning"),
    (SUPPRESSED, SUPPRESSED): (SILENT, "unchanged"),
    (SUPPRESSED, MISSING): (DENY, "an explicit decorative marking was destroyed, leaving a violation"),
    (SUPPRESSED, GONE): (SILENT, "the element was deleted -- ordinary product work"),
    (MISSING, SATISFIED): (RECORD, "fixed: the requirement is now met"),
    (MISSING, SUPPRESSED): (RECORD, "declared decorative, which the reviewer sees in the diff"),
    (MISSING, MISSING): (SILENT, "still unmet; the change never claimed to fix it"),
    (MISSING, GONE): (DENY, "a violation removed by deleting the element rather than fixing it"),
    (GONE, SATISFIED): (SILENT, "a new, compliant element -- ordinary product work"),
    (GONE, SUPPRESSED): (SILENT, "a new decorative element -- ordinary product work"),
    (GONE, MISSING): (WARN, "a new element that does not meet its requirement (not a regression: it warns)"),
    (GONE, GONE): (SILENT, "unreachable"),
    # A component is never required to have a name, so only losing one is a break.
    (SATISFIED, NAMELESS): (DENY, "a name this element carried is gone from its markup"),
    (SUPPRESSED, NAMELESS): (DENY, "an explicit decorative marking was destroyed"),
}
# An exempt element carries no requirement and an unevaluated one hides whether it meets its
# own, so no transition into or out of either can be shown to break anything.
_QUIET = {
    EXEMPT: "no requirement applies to this element in this form",
    UNEVALUATED: "the name is not decidable from this markup, so nothing here is evidence of a break",
    NAMELESS: "absence of a name proves nothing about a component; only its removal does",
}
_STATES = (SATISFIED, SUPPRESSED, MISSING, GONE, EXEMPT, UNEVALUATED, NAMELESS)
for _state, _why in _QUIET.items():
    for _other in _STATES:
        TABLE.setdefault((_state, _other), (SILENT, _why))
        TABLE.setdefault((_other, _state), (SILENT, _why))

_ID_ATTRS = ("data-testid", "id", "name", "src", "href")
#: The attribute names of `Node` the aligner matches on, finest first, then by tag order.
_SIGNATURES = ("signature", "coarse")
#: The most element pairs difflib is asked to align at once; past it the cost is bounded by trimming and tag order.
ALIGN_LIMIT = 4_000_000
#: A `from` source that reads the element's own content rather than an attribute. "inner" is a
#: name-bearing child (<legend>, <caption>, <title>); "text" is the whole subtree, which per
#: accname includes those children too.
_TEXT_SOURCES = {"text": "text", "legend-text": "inner", "caption-text": "inner", "title-child": "inner"}
_NAME_BEARING_CHILDREN = ("legend", "caption", "title")
#: A descendant carrying one of these names the element that contains it.
_LENT_NAME_ATTRS = ("alt", "aria-label")
#: JSX and template syntax this parser tokenizes but cannot evaluate.
_EXPRESSION = "{"
#: A value the markup does not resolve: a JSX or template expression, or a __PLACEHOLDER__ a
#: build step fills in. Both are spellings of a variable, and neither reaches a reader.
_UNRESOLVED = re.compile(r"\{|__[A-Z0-9_]+__")
#: One unspaced token joined by punctuation no word uses inside itself: a segment copied out of the
#: src rather than a phrase someone wrote. The hyphen is deliberately absent -- it is the commonest
#: filename separator AND the commonest punctuation inside a word, so it cannot tell "hero-banner"
#: from "Sign-in" and would refuse the second. Spaces must be absent too, because prose does carry
#: a slash ("Speed in km/h"). Naming a file after what it shows is good practice, not a copy.
_PATH_SEGMENT = re.compile(r"\S*[/\\_]\S*")
#: A source tag name that is capitalised, dotted or hyphenated is not an HTML element:
#: React requires the capital, a namespaced component carries the dot, and the HTML spec
#: requires a hyphen in every custom element name and forbids one in its own.
_SOURCE_TAG_RE = re.compile(r"<\s*([^\s/>]+)")
#: A `<` that opens a tag: a name, then whitespace, a slash or the end, so `a <b)` and `a < b` are not tags.
_TAG_START = re.compile(r"<[A-Za-z][\w.:-]*(?=[\s/>])")
#: Stand in for a `>` and for whitespace inside an attribute expression while the tokenizer reads the tag.
_MASK_GT, _MASK_SP = "\ue000", "\ue001"
_UNMASK = str.maketrans({_MASK_GT: ">", _MASK_SP: " "})


def _norm(name: str) -> str:
    """A name compared across revisions: whitespace folded, case ignored."""
    return " ".join(name.lower().split())


def is_component(raw: str | None) -> bool:
    """True when the source names a component or custom element, not an HTML element."""
    match = _SOURCE_TAG_RE.match(raw or "")
    if match is None:
        return False
    source = match.group(1)
    return source[0].isupper() or "." in source or "-" in source


def mask_expressions(html: str) -> str:
    """Make each `{...}` attribute expression one token: the tokenizer would end the tag at its `>`.

    `onClick={() => go()}` is one attribute value. A tag that never closes is left as written, and a
    backslash escape inside the expression's strings is not read, which leaves such a tag as written too.
    """
    if "{" not in html:
        return html
    out, resume = list(html), 0
    for match in _TAG_START.finditer(html):
        if match.start() >= resume:
            resume = _mask_tag(html, match.end(), out)
    return "".join(out)


def _mask_tag(html: str, start: int, out: list[str]) -> int:
    """Mask the `>` and whitespace inside braces of the tag whose name ends at `start`; return where it stopped."""
    depth, quote, prev, hidden, i = 0, "", "", [], start
    while i < len(html):
        c = html[i]
        if depth:
            if c == ">" or c.isspace():
                hidden.append(i)
            elif quote:
                quote = "" if c == quote else quote
            elif c in "'\"`":
                quote = c
            else:
                depth += (c == "{") - (c == "}")
        elif quote:
            quote = "" if c == quote else quote
        elif c == ">":
            for j in hidden:
                out[j] = _MASK_GT if html[j] == ">" else _MASK_SP
            return i + 1
        elif c == "{":
            depth = 1
        elif c in "'\"" and prev == "=":
            quote = c
        if not (depth or quote or c.isspace()):
            prev = c
        i += 1
    return start


def read_attribute(key: str) -> tuple[str, bool]:
    """(the attribute a spelling means, whether its value is bound): `:alt` is `alt`, `htmlfor` is `for`."""
    if key in BOUND["aliases"]:
        return BOUND["aliases"][key], False
    for prefix in BOUND["prefixes"]:
        if key.startswith(prefix) and len(key) > len(prefix):
            return key[len(prefix) :], True
    for opener, closer in BOUND["brackets"]:
        name = key[len(opener) : -len(closer)]
        if key.startswith(opener) and key.endswith(closer) and name and not set("[]()") & set(name):
            return name, True
    return key, False


def attribute_value(text: str, *, is_bound: bool) -> str | None:
    """What an attribute's value reads as: None for no value at all, "" for an empty literal.

    A bound value is `{text}`, present and unknown, unless it is empty (no value) or an empty literal.
    A brace value that is an empty literal, `undefined` or `null` is the empty string too.
    """
    inner = text.strip()
    if not is_bound and not (inner.startswith("{") and inner.endswith("}")):
        return text
    if is_bound:
        if not inner:
            return None
    else:
        inner = inner[1:-1].strip()
    return "" if inner in BOUND["empty"] else ("{" + text + "}" if is_bound else text)


def read_attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    """Attributes by the name they bind. A bound value reads `{value}`, so it is present and never judged."""
    plain: dict[str, str] = {}
    bound: dict[str, str] = {}
    for key, value in attrs:
        name, is_bound = read_attribute(key.lower().translate(_UNMASK))
        read = attribute_value((value or "").translate(_UNMASK), is_bound=is_bound)
        if read is None:
            continue
        if is_bound:
            bound.setdefault(name, read)
        else:
            plain[name] = read
    return {**bound, **plain}


class Wrap:
    """The text a `<label>` carries, which names every control inside it."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._joined: str | None = ""

    @property
    def text(self) -> str:
        if self._joined is None:
            self._joined = " ".join(self._parts)
        return self._joined

    def add(self, text: str) -> None:
        self._parts.append(text)
        self._joined = None


@dataclass
class Node:
    """One element subject to a requirement, with the text and identity needed to match revisions."""

    tag: str
    attrs: dict[str, str]
    ordinal: int
    text: str = ""
    inner: str = ""
    hidden: bool = False  # an ancestor carries aria-hidden="true"
    child_elements: int = 0  # a name may come from any of them, and a component hides it
    spread: bool = False  # `{...props}`: the attributes are not knowable from the markup
    component: bool = False  # this table has no requirements for it; only a lost name counts
    wrap: Wrap | None = None  # the <label> without `for` this control sits inside
    enclosing: frozenset[str] = frozenset()  # the names the components around this one carry, normalised
    state: tuple[str, str, str] = ("", "", "")  # set by `scan`: (state, evidence, resolved name)
    start: int = 0  # where this element's text begins in the scanner's chunk list

    @property
    def signature(self) -> tuple:
        """What the aligner matches on: the element's identity and styling, never the name it carries."""
        ids = tuple(self.attrs.get(a, "") for a in _ID_ATTRS)
        return (self.tag, ids, self.attrs.get("class", ""), self.attrs.get("type", ""))

    @property
    def coarse(self) -> tuple:
        """The signature without its identity attributes, which an edit to `src` or `href` changes.

        It adds the state: of two same-tag elements left over, one deleted and one edited, the edited one
        is the one still in the state it was in, which errs toward silence.
        """
        return (self.tag, self.attrs.get("class", ""), self.attrs.get("type", ""), self.state[0])

    @property
    def ref(self) -> str:
        for a in _ID_ATTRS:
            if self.attrs.get(a):
                return f"{self.tag}[{a}={self.attrs[a]}]"
        return f"{self.tag}:{self.ordinal}"


class Scanner(HTMLParser):
    """Collect every element the spec has a requirement for, plus the labels that can satisfy one."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.nodes: list[Node] = []
        self.labels: dict[str, str] = {}
        self._counts: dict[str, int] = {}
        self._stack: list[int] = []
        self._label_for: str | None = None
        self._wraps: list[Wrap | None] = []  # open <label>s: a Wrap, or None when it names its control by `for`
        self._inner_depth = 0
        # Tags that opened a subtree hidden from assistive technology. Kept separately from
        # `_stack`, which holds only elements this table has requirements for -- a <nav> or <div>
        # carrying aria-hidden is in neither, and that is exactly what an agent reached for.
        self._hidden: list[str] = []
        self._glyphs: list[str] = []  # open icon-font elements: their text is a glyph name
        self._comps: list[tuple[str, str]] = []  # open components and the name each carries
        # Every text chunk once, with whether it is a legend/caption/title child's: an element's text is
        # the join of the chunks since it opened, taken when it closes, so no chunk is copied per ancestor.
        self._chunks: list[tuple[str, bool]] = []

    def _open(self, tag: str, attrs: list[tuple[str, str | None]], closed: bool, raw: str | None = None) -> None:
        a = read_attributes(attrs)
        inherited = bool(self._hidden)
        if a.get("aria-hidden") == SPEC["suppressing"]["aria-hidden"] and not closed and tag not in VOID:
            # Before the early returns below: an untracked wrapper still hides what it contains.
            # A nested subtree hidden by the same tag name ends at the inner close, which errs
            # toward silence -- the direction a gate that blocks commits must err in.
            self._hidden.append(tag)
        glyph = tag in GLYPH["tags"] or bool(set((a.get("class") or "").split()) & set(GLYPH["classes"]))
        if glyph and not closed and tag not in VOID:
            self._glyphs.append(tag)
        for i in self._stack:
            self.nodes[i].child_elements += 1
        if not (inherited or a.get("aria-hidden") == SPEC["suppressing"]["aria-hidden"]):
            self._lend_name(a, is_component(raw))  # an aria-hidden element lends nothing
        if tag == "label":
            if not closed:
                self._wraps.append(None if a.get("for") else Wrap())
            if a.get("for"):
                self._label_for = a["for"]
            return
        if tag in _NAME_BEARING_CHILDREN:
            self._inner_depth += 1
            return
        component = is_component(raw)
        enclosing = frozenset(_norm(name) for _, name in self._comps if name) if component else frozenset()
        if component and not closed:
            self._comps.append((tag, next((a[p] for p in COMPONENT_NAME_PROPS if a.get(p)), "")))
        # A component is compared only when the markup gives it a stable identity. Ordinal
        # position is not identity: inserting one would shift every later component onto a
        # different element's state, and invent a lost name out of the reordering.
        if component and not any(a.get(attr) for attr in _ID_ATTRS):
            return
        if not component and tag not in REQUIRED:
            return
        self._counts[tag] = self._counts.get(tag, 0) + 1
        spread = any(k.startswith(_EXPRESSION) for k in a)
        self.nodes.append(
            Node(
                tag=tag,
                attrs=a,
                ordinal=self._counts[tag],
                spread=spread,
                component=component,
                enclosing=enclosing,
                hidden=inherited,
                wrap=self._wraps[-1] if self._wraps and not component else None,
                start=len(self._chunks),
            )
        )
        if not closed and tag not in VOID:
            self._stack.append(len(self.nodes) - 1)

    def _lend(self, value: str) -> None:
        """Give every enclosing element and wrapping label this name."""
        self._chunks.append((value, False))
        for wrap in filter(None, self._wraps):
            wrap.add(value)

    def _lend_name(self, attrs: dict[str, str], component: bool) -> None:
        """Give every enclosing element the name this one carries, as accname's 2F does."""
        for attr in _LENT_NAME_ATTRS:
            if value := attrs.get(attr, "").strip():
                self._lend(value)
                return
        if component and any(attrs.get(p) for p in TEXT_PROPS):
            self._lend("{text}")  # a component that renders its own text

    def handle_starttag(self, tag, attrs):
        self._open(tag, attrs, closed=False, raw=self.get_starttag_text())

    def handle_startendtag(self, tag, attrs):
        self._open(tag, attrs, closed=True, raw=self.get_starttag_text())

    def handle_endtag(self, tag):
        if self._glyphs and self._glyphs[-1] == tag:
            self._glyphs.pop()
        if self._comps and self._comps[-1][0] == tag:
            self._comps.pop()
        if self._hidden and self._hidden[-1] == tag:
            self._hidden.pop()
        if tag == "label":
            self._label_for = None
            if self._wraps:
                self._wraps.pop()
        elif tag in _NAME_BEARING_CHILDREN:
            self._inner_depth = max(0, self._inner_depth - 1)
        elif self._stack and self.nodes[self._stack[-1]].tag == tag:
            self._finish(self._stack.pop())

    def _finish(self, index: int) -> None:
        """Fix the text of the element at `index`: every chunk since it opened."""
        node = self.nodes[index]
        taken = self._chunks[node.start :]
        node.text = " ".join(t for t, inner in taken if not inner)
        node.inner = " ".join(t for t, inner in taken if inner)

    def finish(self) -> None:
        """Close what the markup left open."""
        while self._stack:
            self._finish(self._stack.pop())

    def handle_data(self, data):
        text = data.strip()
        if not text or self._hidden or self._glyphs:  # aria-hidden text and a glyph's name name nothing
            return
        if self._label_for is not None:
            self.labels[self._label_for] = f"{self.labels.get(self._label_for, '')} {text}".strip()
            return
        for wrap in filter(None, self._wraps):
            wrap.add(text)
        self._chunks.append((text, bool(self._inner_depth)))


# ── The state function. It consults the spec table; it decides nothing. ───────────────────────
def _suppression(node: Node) -> str | None:
    """Why this element was deliberately removed from assistive technology, if it was.

    aria-hidden removes an element AND its subtree from the accessibility tree, whatever the
    element is, so `suppressible` does not gate it and an ancestor carrying it hides this one
    too. role and an emptied alt are assertions about one element, which is what that list names.
    """
    s = SPEC["suppressing"]
    if node.attrs.get("aria-hidden") == s["aria-hidden"]:
        return 'aria-hidden="true"'
    if node.hidden:
        return 'an ancestor carries aria-hidden="true"'
    if node.tag not in SPEC["suppressible"]:
        return None
    if node.attrs.get("role") in s["role"]:
        return f'role="{node.attrs["role"]}"'
    if node.tag in s["empty_alt"] and node.attrs.get("alt") == "" and "alt" in node.attrs:
        return 'alt=""'
    return None


def rule_for(node: Node) -> dict | None:
    """The requirement that actually applies, after only_when and by_type. None means exempt."""
    rule = REQUIRED[node.tag]
    if rule.get("optional"):
        return None
    when = rule.get("only_when")
    if when and (when["attr"] not in node.attrs or ("equals" in when and node.attrs[when["attr"]] != when["equals"])):
        return None
    override = rule.get("by_type", {}).get(node.attrs.get("type", "").lower())
    if override is None:
        return rule
    if override.get("needs") == "none":
        return None
    return {**rule, **override}


def component_state(node: Node) -> tuple[str, str, str]:
    """A component's state. It is never MISSING: this table has no requirement to miss."""
    if node.spread:
        return UNEVALUATED, "the attributes come from a spread, so the name is not in the markup", ""
    if (why := _suppression(node)) is not None:
        return SUPPRESSED, why, ""
    for prop in COMPONENT_NAME_PROPS:
        if value := node.attrs.get(prop, ""):
            return SATISFIED, f'{prop}="{value}"', value
        if prop in node.attrs:
            return SUPPRESSED, f'{prop}="" asserts this carries no name', ""
    if text := node.text or node.inner:
        return SATISFIED, f"text {text[:40]!r}", text
    return NAMELESS, f"<{node.tag}> carries no name prop, and may not need one", ""


def label_name(node: Node, labels: dict[str, str]) -> tuple[str, str] | None:
    """(evidence, name) from the <label> that names this control, by `for` or by wrapping it."""
    if node.attrs.get("id") and (lbl := labels.get(node.attrs["id"])):
        return f'<label for="{node.attrs["id"]}">{lbl}</label>', lbl
    if node.wrap is not None and node.wrap.text:
        return f"a wrapping <label> reading {node.wrap.text[:40]!r}", node.wrap.text
    return None


def state_of(node: Node, labels: dict[str, str]) -> tuple[str, str, str]:
    """Return (state, evidence, resolved name), walking the accepted sources in the spec's order."""
    if node.component:
        return component_state(node)
    rule = rule_for(node)
    if rule is None:
        return EXEMPT, f"<{node.tag}> carries no requirement in this form", ""
    if node.spread:
        return UNEVALUATED, "the attributes come from a spread, so the name is not in the markup", ""
    if (why := _suppression(node)) is not None:
        return SUPPRESSED, why, ""
    for src in rule["from"]:
        if src in _TEXT_SOURCES:
            val = node.text or node.inner if src == "text" else getattr(node, _TEXT_SOURCES[src])
            if val:
                return SATISFIED, f"{src} {val[:40]!r}", val
        elif src == "label-for":
            if (found := label_name(node, labels)) is not None:
                return SATISFIED, found[0], found[1]
        elif src == "implicit-default":
            return SATISFIED, f"the platform default name for type={node.attrs.get('type')}", node.tag
        elif node.attrs.get(src):
            return SATISFIED, f'{src}="{node.attrs[src]}"', node.attrs[src]
    if node.child_elements and "text" in rule["from"] and not rule.get("icon_only"):
        return UNEVALUATED, f"<{node.tag}> is named by a child this parser cannot resolve", ""
    return MISSING, f"needs {rule['needs']} from one of {rule['from']} (WCAG {rule['wcag']})", ""


def scan(html: str) -> list[Node]:
    """Parse one revision into its tracked elements in document order, each carrying its state."""
    scanner = Scanner()
    scanner.feed(mask_expressions(html))
    scanner.finish()
    for node in scanner.nodes:
        node.state = state_of(node, scanner.labels)
    return scanner.nodes


def labelled_by_its_own_text(node: Node) -> bool:
    """Whether this element's name is the label a reader sees, rather than a description of it.

    "Go", "OK" and "Q1" are honest labels; two characters of alt text describe no image. A
    component counts in: its props carry labels as often as descriptions and markup cannot say which.
    """
    return node.component or "text" in (REQUIRED.get(node.tag) or {}).get("from", [])


def uninformative(name: str, src: str, tag: str = "", *, labelled: bool = False) -> str | None:
    """Say why a supplied name conveys nothing, or None if it carries information."""
    if _UNRESOLVED.search(name):
        return None  # not a name: its spelling is a variable's or a build step's, not a reader's
    words = set(NOISE["words"]) | set((NOISE.get("by_tag") or {}).get(tag, []))
    bare = re.sub(r"[^a-z0-9 ]+", " ", name.lower()).strip()
    if not labelled and tag != "html" and len(bare) < NOISE["min_length"]:  # a lang code is short by design
        return f"{name!r} is too short to describe anything"
    if all(w in words or w.isdigit() for w in bare.split()):
        return f"{name!r} is placeholder wording, not a description"
    if name.lower().rsplit(".", 1)[-1] in NOISE["file_extensions"]:
        return f"{name!r} is a filename"
    if src and _PATH_SEGMENT.fullmatch(name.strip()) and bare.replace(" ", "") in re.sub(r"[/_\-.]", "", src.lower()):
        return f"{name!r} is a path segment, not a description"
    return None


def _zip_by_tag(before: list[Node], after: list[Node]) -> list[tuple[Node | None, Node | None]]:
    """In one replaced stretch, the n-th element of a tag before is the n-th of that tag after."""
    queued: dict[str, list[Node]] = {}
    for node in after:
        queued.setdefault(node.tag, []).append(node)
    taken = dict.fromkeys(queued, 0)
    pairs: list[tuple[Node | None, Node | None]] = []
    for node in before:
        n, match = taken.get(node.tag, 0), queued.get(node.tag, [])
        pairs.append((node, match[n] if n < len(match) else None))
        taken[node.tag] = n + (n < len(match))
    paired = {id(a) for _, a in pairs if a}
    return pairs + [(None, node) for node in after if id(node) not in paired]


def _trim(before: list[Node], after: list[Node], sig: str):
    """Pair what two long lists share at both ends, leaving the middle: (head, before, after, tail)."""
    n = min(len(before), len(after))
    i = 0
    while i < n and getattr(before[i], sig) == getattr(after[i], sig):
        i += 1
    j = 0
    while j < n - i and getattr(before[-1 - j], sig) == getattr(after[-1 - j], sig):
        j += 1
    head = list(zip(before[:i], after[:i], strict=True))
    tail = list(zip(before[len(before) - j :], after[len(after) - j :], strict=True))
    return head, before[i : len(before) - j], after[i : len(after) - j], tail


def pair_elements(before: list[Node], after: list[Node], level: int = 0) -> list[tuple[Node | None, Node | None]]:
    """Align two revisions' tracked elements: an unpaired `before` was deleted, an unpaired `after` is new.

    difflib matches the elements whose signature is unchanged, so inserting or deleting one moves nothing
    else. Each stretch it cannot match is aligned again on a signature without `src`, `href` and `id`
    (an edit to those is the same element), then by tag order. A pair of long lists is trimmed at both
    ends first, and a stretch still past the limit is paired by tag order alone, so the cost is bounded.
    """
    if not before or not after:
        return [(n, None) for n in before] + [(None, n) for n in after]
    sig = _SIGNATURES[level] if level < len(_SIGNATURES) else None
    if sig is None:
        return _zip_by_tag(before, after)
    head: list[tuple[Node | None, Node | None]] = []
    tail: list[tuple[Node | None, Node | None]] = []
    if len(before) * len(after) > ALIGN_LIMIT:
        head, before, after, tail = _trim(before, after, sig)
        if len(before) * len(after) > ALIGN_LIMIT:
            return head + _zip_by_tag(before, after) + tail
    pairs: list[tuple[Node | None, Node | None]] = []
    keys = ([getattr(n, sig) for n in before], [getattr(n, sig) for n in after])
    for op, i1, i2, j1, j2 in SequenceMatcher(None, *keys, autojunk=False).get_opcodes():
        if op == "equal":
            pairs += zip(before[i1:i2], after[j1:j2], strict=True)
        elif op == "replace":
            pairs += pair_elements(before[i1:i2], after[j1:j2], level + 1)
        else:
            pairs += [(n, None) for n in before[i1:i2]] + [(None, n) for n in after[j1:j2]]
    return head + pairs + tail


def _name_moved(before: Node | None, after: Node | None, bs: str, as_: str, name: str) -> str | None:
    """Why a component's lost name is not lost: an enclosing component now carries the same name."""
    if not (before and after and before.component and (bs, as_) == (SATISFIED, NAMELESS)):
        return None
    if (key := _norm(name)) in after.enclosing and key not in before.enclosing:
        return "the name moved to an enclosing component"
    return None


# ── The decision: one table lookup per element, plus one promotion rule. ──────────────────────
def evaluate(before_html: str, after_html: str) -> list[dict]:
    """Compare two revisions; every row carries the lookup key that produced its action."""
    rows = []
    for old, new in pair_elements(scan(before_html), scan(after_html)):
        bs, bw, b_name = old.state if old else (GONE, "not in this revision", "")
        as_, aw, a_name = new.state if new else (GONE, "not in this revision", "")
        action, why = TABLE[(bs, as_)]
        # Only judge a name this change actually supplied. Judging an untouched element is how a
        # gate starts refusing commits over code nobody edited.
        supplied = as_ == SATISFIED and bs != SATISFIED and a_name != b_name
        src, tag = (new.attrs.get("src", ""), new.tag) if new else ("", "")
        labelled = labelled_by_its_own_text(new) if new else False
        if supplied and (bad := uninformative(a_name, src, tag, labelled=labelled)) is not None:
            action, why = WARN, f"the value supplied conveys nothing: {bad}"
        if key_moved := _name_moved(old, new, bs, as_, b_name):
            action, why = SILENT, key_moved
        rows.append({"ref": (new or old).ref, "key": (bs, as_), "action": action, "why": why, "was": bw, "now": aw})

    # Deleting an unnamed element is how a violation gets resolved by deletion -- and it is also
    # what happens to every legacy block that holds one, when the block is correctly removed. The
    # two differ in what went with it: nobody hides a missing name by also deleting content that
    # carried one. So when an authored state disappeared from this same file, the block went and
    # the unnamed element went with it. `evaluate` is called per file, which is coarser than per
    # block and so errs toward silence -- the direction a gate that blocks commits must err in.
    if any(r["key"][1] == GONE and r["key"][0] in _AUTHORED for r in rows):
        for row in rows:
            if row["key"] == (MISSING, GONE):
                row["action"] = SILENT
                row["why"] = "deleted along with content that carried a name -- the block went, not just the violation"
    return rows


# ── The commit-time front end. Both revisions come from git; nothing is passed in. ────────────
def _git(*args: str) -> str:
    """Read one repo fact. A path git cannot show is a path with no content, so the answer is empty."""
    # Fixed argv, no shell: `args` is built from the spec's own suffix list and git's own output.
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, UnicodeError):
        return ""
    return proc.stdout or ""


def staged_markup() -> list[tuple[str, str]]:
    """Staged (path, path it was renamed from) this guard can read: markup, by the spec's suffixes.

    `-M` pairs a renamed file with its old path, so the new one is judged against what it was. A file
    that is not a rename is its own old path; a path whose old name is not markup has no old revision.
    """
    out = _git("diff", "--cached", "-M", "--name-status", "-z", "--diff-filter=ACMRT").split("\0")
    staged, i = [], 0
    while i < len(out) and out[i]:
        status = out[i]
        count = 2 if status[0] in "RC" else 1
        paths = out[i + 1 : i + 1 + count]
        i += 1 + count
        if len(paths) == count and paths[-1].endswith(MARKUP_SUFFIXES):
            staged.append((paths[-1], paths[0] if status[0] == "R" and paths[0].endswith(MARKUP_SUFFIXES) else paths[-1]))
    return staged


def main() -> int:
    """Refuse the commit when a staged file destroys an assertion it previously carried."""
    alarms: list[tuple[str, dict]] = []
    warnings: list[tuple[str, dict]] = []
    for path, was in staged_markup():
        before, after = _git("show", f"HEAD:{was}"), _git("show", f":{path}")
        try:
            rows = evaluate(before, after)
        except Exception as exc:  # noqa: BLE001 -- a parse failure is not evidence of a violation
            print(f"no-a11y-regression: skipped {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        alarms.extend((path, r) for r in rows if r["action"] == DENY)
        warnings.extend((path, r) for r in rows if r["action"] == WARN)

    for path, row in warnings:
        print(f"no-a11y-regression: warning: {path}: {row['ref']}   {row['why']}", file=sys.stderr)
    if not alarms:
        return 0

    print(
        f"BLOCKED: this change destroys an accessibility assertion in {len({p for p, _ in alarms})} file(s). "
        "The previous revision carried it and this one does not, which no violation report will show you "
        "-- a removed element and an emptied alt both score as fewer violations, not more.",
        file=sys.stderr,
    )
    for path, row in alarms:
        print(f"  {path}: {row['ref']}   {row['key'][0]} -> {row['key'][1]}", file=sys.stderr)
        print(f"      {row['why']}", file=sys.stderr)
        print(f"      was: {row['was']}", file=sys.stderr)
        print(f"      now: {row['now']}", file=sys.stderr)
    print(
        "Restore what the element carried, or -- if it truly is decorative -- say so where a "
        "reviewer sees it, in the diff.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
