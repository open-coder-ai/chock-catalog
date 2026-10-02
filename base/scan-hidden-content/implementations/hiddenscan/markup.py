"""HTML (in HTML, SVG, XML and Markdown files) read for the URLs its tags load and the text its styling hides."""

from __future__ import annotations

import bisect
import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from hiddenscan import css as hidden_css
from hiddenscan.motion import Motion
from hiddenscan.vocab import visible

#: Attributes whose URL the renderer fetches by itself: loading the page is the request.
EMBED_ATTRS = {
    "src",
    "srcset",
    "data",
    "action",
    "formaction",
    "poster",
    "background",
    "lowsrc",
    "dynsrc",
    "imagesrcset",
}
#: Tags whose href (or xlink:href) is fetched too; an anchor's is not.
EMBED_HREF_TAGS = {"link", "image", "use", "feimage", "base", "script"}
URL_ATTRS = EMBED_ATTRS | {"href", "xlink:href", "cite", "longdesc", "ping"}
VOID = set(
    [
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
        "param",
        "keygen",
    ]
)
#: An end tag does not close an element outside these: the browser ignores it (table scope).
SCOPE = {"td", "th", "table", "caption", "template", "html", "select", "object", "marquee", "applet"}
SCOPE |= {"foreignobject", "desc", "title", "mi", "mo", "mn", "ms", "mtext", "annotation-xml"}
#: Table parts a browser drops when no table is open.
TABLE_PARTS = {"td", "th", "tr", "caption", "thead", "tbody", "tfoot", "col", "colgroup"}
FOREIGN = {"svg", "math"}
ARIA = "aria-hidden wrapping long text"
NOT_DRAWN = "SVG metadata, defs, symbol, clipPath or mask (not drawn as text)"
#: desc and title are not here: screen readers present them, so they are not hidden from a person.
NOT_DRAWN_TAGS = {"metadata", "defs", "symbol", "clippath", "mask"}
#: These hide text from some readers only; they count once the text is this long.
LONG_ONLY = {ARIA: 100}
KEPT_TEXT = 2000
OFF_SVG = -999


@dataclass
class Frame:
    tag: str
    line: int
    reason: str | None
    background: str | None
    text: list[str] = field(default_factory=list)
    size: int = 0
    kept: int = 0
    digest: Any = field(default_factory=hashlib.sha256)


@dataclass
class Collected:
    urls: list[tuple[int, str, bool]] = field(default_factory=list)  # (line, URL, fetched without a click)
    hidden: list[tuple[int, str, str, str, str]] = field(default_factory=list)  # (line, tag, reason, shown, key)
    data_html: list[int] = field(default_factory=list)


def _srcset(value: str) -> list[str]:
    return [part.split()[0] for part in value.split(",") if part.split()]


def style_blocks(text: str) -> list[tuple[int, str]]:
    """(offset, content) of each `<style>` element, found by plain search so the scan stays linear."""
    lower, out, at = text.lower(), [], 0
    while (start := lower.find("<style", at)) != -1:
        opened = lower.find(">", start)
        if opened == -1:
            break
        end = lower.find("</style", opened)
        end = len(text) if end == -1 else end
        out.append((opened + 1, text[opened + 1 : end]))
        at = end
    return out


def hidden_selectors(sheets: list[str], motion: Motion) -> dict[str, str]:
    """`.class` and `#id` names that a style rule anywhere in the file hides, with the reason."""
    out: dict[str, str] = {}
    for sheet in sheets:
        for _, selector, decls in hidden_css.rules(sheet):
            if not hidden_css.no_text(selector) and (reason := hidden_css.hidden(decls, None, motion=motion)):
                out.update(dict.fromkeys(hidden_css.selector_targets(selector), reason))
    return out


class Collector(HTMLParser):
    """Collects attribute URLs, hidden elements with their text, and hidden rules in style elements."""

    def __init__(self, *, xml: bool, rules: dict[str, str], motion: Motion) -> None:
        super().__init__(convert_charrefs=True)
        self.xml, self.rules, self.motion = xml, rules, motion
        self.out = Collected()
        self.stack: list[Frame] = []
        # Bookkeeping that keeps each tag O(1): open positions per tag name, the open frames that hide,
        # and how many SVG or MathML elements are open (there `/>` closes an element, as in XML).
        self.where: dict[str, list[int]] = {}
        self.hiding: list[Frame] = []
        self.foreign = 0

    def _attrs(self, attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        first: dict[str, str] = {}
        for name, value in attrs:
            first.setdefault(name.lower(), value if value is not None else "")
        return first

    def _urls(self, tag: str, attrs: dict[str, str], line: int) -> None:
        for name, value in attrs.items():
            if "data:" in value.lower() and "text/html" in value.lower().replace(" ", ""):
                self.out.data_html.append(line)
            if name not in URL_ATTRS:
                continue
            embed = name in EMBED_ATTRS or (name in ("href", "xlink:href") and tag in EMBED_HREF_TAGS)
            values = _srcset(value) if name.endswith("srcset") else [value.strip()]
            self.out.urls += [(line, url, embed) for url in values if url]
        for _, url in hidden_css.urls(attrs.get("style", "")):
            self.out.urls.append((line, url, True))

    def _reason(self, tag: str, attrs: dict[str, str], under: str | None) -> tuple[str | None, str | None]:
        """(why the element hides its text, the background behind its children)."""
        if not attrs and tag not in NOT_DRAWN_TAGS:
            return None, under
        svg = self.xml or self.foreign > 0 or tag in FOREIGN
        decls = hidden_css.declarations(attrs.get("style", ""))
        named = ("display", "visibility", "opacity", "font-size") + (("fill", "fill-opacity") if svg else ())
        for name in named:
            if name in attrs and name not in decls:
                decls[name] = attrs[name].strip().lower()
        if "color" in attrs and tag == "font" and "color" not in decls:
            decls["color"] = attrs["color"].strip().lower()
        if "bgcolor" in attrs and "background-color" not in decls:
            decls["background-color"] = attrs["bgcolor"].strip().lower()
        behind = hidden_css.background(decls) or under
        targets = [f"#{i.lower()}" for i in attrs.get("id", "").split()[:1]]
        targets += [f".{c.lower()}" for c in attrs.get("class", "").split()]
        far = svg and any((hidden_css.number(attrs.get(a, "")) or (0, ""))[0] <= OFF_SVG for a in ("x", "y"))
        found = (
            ("hidden attribute" if "hidden" in attrs else None)
            or hidden_css.hidden(decls, under or self._page(), svg=svg, motion=self.motion)
            or ("positioned off screen" if far else None)
            or next(
                (f"hidden by a style rule ({self.rules[t]})" for t in targets if self._ruled(t, decls)),
                None,
            )
            or (NOT_DRAWN if svg and tag in NOT_DRAWN_TAGS else None)
            or (ARIA if attrs.get("aria-hidden", "").strip().lower() == "true" else None)
        )
        return found, behind

    def _ruled(self, target: str, decls: dict[str, str]) -> bool:
        """Whether a style rule hides this element: its class or id is hidden, and its own animation does
        not play a keyframe of the file that shows what the rule hides."""
        return target in self.rules and not self.motion.reveals(decls, self.rules[target])

    def _page(self) -> str | None:
        """The page behind text no element gives a background: white in HTML and Markdown (inline SVG too);
        unknown in a standalone SVG or XML file, which paints its background with shapes."""
        return None if self.xml else hidden_css.DEFAULT_BACKGROUND

    def _open(self, tag: str, attrs: list[tuple[str, str | None]], *, push: bool) -> None:
        line = self.getpos()[0]
        named = self._attrs(attrs)
        self._urls(tag, named, line)
        # The background behind the text, when an element declares one. Unset, an HTML page is white; an SVG
        # paints its background with shapes this reader does not place, so there it stays unknown.
        under = self.stack[-1].background if self.stack else None
        if tag in TABLE_PARTS and not self.where.get("table") and not (self.xml or self.foreign):
            return  # a browser drops a table part outside a table
        reason, behind = self._reason(tag, named, under)
        if any(f.reason not in LONG_ONLY or reason in LONG_ONLY for f in self.hiding):
            reason = None  # already inside hidden text: the outer element is the finding
        # Outside SVG and XML a browser ignores `/>` on an element that is not void.
        if tag not in VOID and (push or not (self.xml or self.foreign or tag in FOREIGN)):
            frame = Frame(tag, line, reason, behind)
            self.where.setdefault(tag, []).append(len(self.stack))
            self.stack.append(frame)
            self.foreign += tag in FOREIGN
            if reason:
                self.hiding.append(frame)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open(tag, attrs, push=True)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open(tag, attrs, push=False)

    def handle_endtag(self, tag: str) -> None:
        if not self.where.get(tag):
            return
        cut = self.where[tag][-1]
        barrier = max((self.where[t][-1] for t in SCOPE if self.where.get(t) and t != tag), default=-1)
        if not self.xml and tag not in SCOPE and barrier > cut:
            return  # an end tag outside the open table cell is ignored, as browsers ignore it
        while len(self.stack) > cut:
            frame = self.stack.pop()
            self.where[frame.tag].pop()
            self.foreign -= frame.tag in FOREIGN
            if frame.reason:
                self.hiding.pop()
            self._finish(frame)

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1].tag in ("style", "script"):
            if self.stack[-1].tag == "style":
                self._style(data)
            return  # a style sheet or a script is not text a reader sees
        words = None
        for frame in self.hiding:
            words = (
                words if words is not None else "".join(unicodedata.normalize("NFKC", visible(data)).casefold().split())
            )
            frame.size += len(words)
            frame.digest.update(words.encode("utf-8", "surrogatepass"))
            if frame.kept < KEPT_TEXT:
                frame.text.append(data[: KEPT_TEXT - frame.kept])
                frame.kept += len(frame.text[-1])

    def _style(self, sheet: str) -> None:
        line = self.getpos()[0]
        breaks = [m.start() for m in re.finditer("\n", sheet)]
        for offset, selector, decls in hidden_css.rules(sheet):
            if not hidden_css.no_text(selector) and (reason := hidden_css.hidden(decls, None, motion=self.motion)):
                at = line + bisect.bisect_left(breaks, offset + len(selector))
                self.out.hidden.append((at, "style", reason, selector, " ".join(selector.split())))
        for offset, url in hidden_css.urls(sheet):
            self.out.urls.append((line + bisect.bisect_left(breaks, offset), url, True))

    def _finish(self, frame: Frame) -> None:
        if not frame.reason or not frame.size or frame.size < LONG_ONLY.get(frame.reason, 1):
            return
        shown = " ".join("".join(frame.text).split())[:80]
        self.out.hidden.append((frame.line, frame.tag, frame.reason, shown, frame.digest.hexdigest()[:16]))

    def close(self) -> None:
        super().close()
        for frame in reversed(self.stack):
            self._finish(frame)
        self.stack, self.where, self.hiding = [], {}, []


def collect(text: str, *, xml: bool = False) -> Collected:
    sheets = [sheet for _, sheet in style_blocks(text)]
    motion = Motion(sheets, text)
    parser = Collector(xml=xml, rules=hidden_selectors(sheets, motion), motion=motion)
    parser.feed(text)
    parser.close()
    return parser.out
