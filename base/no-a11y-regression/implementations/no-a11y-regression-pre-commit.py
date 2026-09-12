#!/usr/bin/env python3
"""Refuse a staged change that destroys an accessibility assertion an element already carried."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
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
# interruptions, so a correct fix is silent and only a break refuses the commit.
DENY, RECORD, SILENT = "deny", "record", "silent"

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
    (GONE, MISSING): (DENY, "a new element that does not meet its requirement"),
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


def is_component(raw: str | None) -> bool:
    """True when the source names a component or custom element, not an HTML element."""
    match = _SOURCE_TAG_RE.match(raw or "")
    if match is None:
        return False
    source = match.group(1)
    return source[0].isupper() or "." in source or "-" in source


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
        self._inner_depth = 0
        # Tags that opened a subtree hidden from assistive technology. Kept separately from
        # `_stack`, which holds only elements this table has requirements for -- a <nav> or <div>
        # carrying aria-hidden is in neither, and that is exactly what an agent reached for.
        self._hidden: list[str] = []

    def _open(
        self, tag: str, attrs: list[tuple[str, str | None]], closed: bool, raw: str | None = None
    ) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        inherited = bool(self._hidden)
        if a.get("aria-hidden") == SPEC["suppressing"]["aria-hidden"] and not closed and tag not in VOID:
            # Before the early returns below: an untracked wrapper still hides what it contains.
            # A nested subtree hidden by the same tag name ends at the inner close, which errs
            # toward silence -- the direction a gate that blocks commits must err in.
            self._hidden.append(tag)
        for i in self._stack:
            self.nodes[i].child_elements += 1
        self._lend_name(a)
        if tag == "label" and a.get("for"):
            self._label_for = a["for"]
            return
        if tag in _NAME_BEARING_CHILDREN:
            self._inner_depth += 1
            return
        component = is_component(raw)
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
                hidden=inherited,
            )
        )
        if not closed and tag not in VOID:
            self._stack.append(len(self.nodes) - 1)

    def _lend_name(self, attrs: dict[str, str]) -> None:
        """Give every enclosing element the name this one carries, as accname's 2F does."""
        for attr in _LENT_NAME_ATTRS:
            if value := attrs.get(attr, "").strip():
                for i in self._stack:
                    self.nodes[i].text = f"{self.nodes[i].text} {value}".strip()
                return

    def handle_starttag(self, tag, attrs):
        self._open(tag, attrs, closed=False, raw=self.get_starttag_text())

    def handle_startendtag(self, tag, attrs):
        self._open(tag, attrs, closed=True, raw=self.get_starttag_text())

    def handle_endtag(self, tag):
        if self._hidden and self._hidden[-1] == tag:
            self._hidden.pop()
        if tag == "label":
            self._label_for = None
        elif tag in _NAME_BEARING_CHILDREN:
            self._inner_depth = max(0, self._inner_depth - 1)
        elif self._stack and self.nodes[self._stack[-1]].tag == tag:
            self._stack.pop()

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return
        if self._label_for is not None:
            self.labels[self._label_for] = f"{self.labels.get(self._label_for, '')} {text}".strip()
            return
        for i in self._stack:
            if self._inner_depth:
                self.nodes[i].inner = f"{self.nodes[i].inner} {text}".strip()
            else:
                self.nodes[i].text = f"{self.nodes[i].text} {text}".strip()


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
    if node.child_elements:
        return UNEVALUATED, f"<{node.tag}> may be named by a child this parser cannot resolve", ""
    return NAMELESS, f"<{node.tag}> carries no name prop, and may not need one", ""


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
            if node.attrs.get("id") and (lbl := labels.get(node.attrs["id"])):
                return SATISFIED, f'<label for="{node.attrs["id"]}">{lbl}</label>', lbl
        elif src == "implicit-default":
            return SATISFIED, f"the platform default name for type={node.attrs.get('type')}", node.tag
        elif node.attrs.get(src):
            return SATISFIED, f'{src}="{node.attrs[src]}"', node.attrs[src]
    if node.child_elements and "text" in rule["from"]:
        return UNEVALUATED, f"<{node.tag}> is named by a child this parser cannot resolve", ""
    return MISSING, f"needs {rule['needs']} from one of {rule['from']} (WCAG {rule['wcag']})", ""


def scan(html: str) -> tuple[dict[str, tuple[str, str, str]], dict[str, Node]]:
    """Parse one revision into {ref: (state, evidence, name)} and {ref: node}."""
    s = Scanner()
    s.feed(html)
    return {n.ref: state_of(n, s.labels) for n in s.nodes}, {n.ref: n for n in s.nodes}


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
    if not labelled and len(bare) < NOISE["min_length"]:
        return f"{name!r} is too short to describe anything"
    if all(w in words or w.isdigit() for w in bare.split()):
        return f"{name!r} is placeholder wording, not a description"
    if name.lower().rsplit(".", 1)[-1] in NOISE["file_extensions"]:
        return f"{name!r} is a filename"
    if src and _PATH_SEGMENT.fullmatch(name.strip()) and bare.replace(" ", "") in re.sub(r"[/_\-.]", "", src.lower()):
        return f"{name!r} is a path segment, not a description"
    return None


# ── The decision: one table lookup per element, plus one promotion rule. ──────────────────────
def evaluate(before_html: str, after_html: str) -> list[dict]:
    """Compare two revisions; every row carries the lookup key that produced its action."""
    b_states, _ = scan(before_html)
    a_states, a_nodes = scan(after_html)
    rows = []
    for ref in sorted(b_states.keys() | a_states.keys()):
        bs, bw, b_name = b_states.get(ref, (GONE, "not in this revision", ""))
        as_, aw, a_name = a_states.get(ref, (GONE, "not in this revision", ""))
        action, why = TABLE[(bs, as_)]
        # Only judge a name this change actually supplied. Judging an untouched element is how a
        # gate starts refusing commits over code nobody edited.
        supplied = as_ == SATISFIED and bs != SATISFIED and a_name != b_name
        node = a_nodes.get(ref)
        src, tag = (node.attrs.get("src", ""), node.tag) if node else ("", "")
        labelled = labelled_by_its_own_text(node) if node else False
        if supplied and (bad := uninformative(a_name, src, tag, labelled=labelled)) is not None:
            action, why = DENY, f"the value supplied conveys nothing: {bad}"
        rows.append({"ref": ref, "key": (bs, as_), "action": action, "why": why, "was": bw, "now": aw})

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


def staged_markup() -> list[str]:
    """Staged paths this guard can read: markup, by the suffixes the spec enumerates."""
    out = _git("diff", "--cached", "--name-only", "--diff-filter=ACMRT")
    return [p.strip() for p in out.splitlines() if p.strip().endswith(MARKUP_SUFFIXES)]


def main() -> int:
    """Refuse the commit when a staged file destroys an assertion it previously carried."""
    alarms: list[tuple[str, dict]] = []
    for path in staged_markup():
        before, after = _git("show", f"HEAD:{path}"), _git("show", f":{path}")
        try:
            rows = evaluate(before, after)
        except Exception as exc:  # noqa: BLE001 -- a parse failure is not evidence of a violation
            print(f"no-a11y-regression: skipped {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        alarms.extend((path, r) for r in rows if r["action"] == DENY)

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
