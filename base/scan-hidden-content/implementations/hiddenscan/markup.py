"""HTML (in HTML, SVG, XML and Markdown files) read for the URLs its tags load and the text its styling hides."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser

from hiddenscan import css as hidden_css

#: Attributes whose URL the renderer fetches by itself: loading the page is the request.
EMBED_ATTRS = {
    "src",
    "srcset",
    "data",
    "action",
    "formaction",
    "poster",
    "background",
    "xlink:href",
    "lowsrc",
    "dynsrc",
    "imagesrcset",
}
#: Tags whose href is fetched too (a stylesheet, an SVG image, a `use` reference); an anchor's is not.
EMBED_HREF_TAGS = {"link", "image", "use", "feimage", "base"}
URL_ATTRS = EMBED_ATTRS | {"href", "cite", "longdesc", "ping"}
VOID = {
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
}
ARIA = "aria-hidden wrapping long text"
#: aria-hidden hides text from assistive technology only; it counts once the text is this long.
LONG_ARIA = 100
KEPT_TEXT = 2000


@dataclass
class Frame:
    tag: str
    line: int
    reason: str | None
    background: str | None
    text: list[str] = field(default_factory=list)
    size: int = 0
    kept: int = 0


@dataclass
class Collected:
    urls: list[tuple[int, str, bool]] = field(default_factory=list)  # (line, URL, fetched without a click)
    hidden: list[tuple[int, str, str, str]] = field(default_factory=list)  # (line, tag, reason, text)
    data_html: list[int] = field(default_factory=list)


def _srcset(value: str) -> list[str]:
    return [part.split()[0] for part in value.split(",") if part.split()]


class Collector(HTMLParser):
    """Collects attribute URLs, hidden elements with their text, and hidden rules in style elements."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out = Collected()
        self.stack: list[Frame] = []
        # Bookkeeping that keeps each tag O(1): open positions per tag name, and the open frames that hide.
        self.where: dict[str, list[int]] = {}
        self.hiding: list[Frame] = []

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
            embed = name in EMBED_ATTRS or (name == "href" and tag in EMBED_HREF_TAGS)
            values = _srcset(value) if name.endswith("srcset") else [value.strip()]
            self.out.urls += [(line, url, embed) for url in values if url]
        for _, url in hidden_css.urls(attrs.get("style", "")):
            self.out.urls.append((line, url, True))

    def _reason(self, tag: str, attrs: dict[str, str], under: str | None) -> tuple[str | None, str | None]:
        """(why the element hides its text, the background behind its children)."""
        decls = hidden_css.declarations(attrs.get("style", ""))
        for name in ("display", "visibility", "opacity", "font-size"):
            if name in attrs and name not in decls:
                decls[name] = attrs[name].strip().lower()
        if tag == "font" and "color" in attrs and "color" not in decls:
            decls["color"] = attrs["color"].strip().lower()
        behind = hidden_css.background(decls) or under
        if "hidden" in attrs:
            return "hidden attribute", behind
        if reason := hidden_css.hidden(decls, under):
            return reason, behind
        if attrs.get("aria-hidden", "").strip().lower() == "true":
            return ARIA, behind
        return None, behind

    def _open(self, tag: str, attrs: list[tuple[str, str | None]], *, push: bool) -> None:
        line = self.getpos()[0]
        named = self._attrs(attrs)
        self._urls(tag, named, line)
        under = self.stack[-1].background if self.stack else hidden_css.DEFAULT_BACKGROUND
        reason, behind = self._reason(tag, named, under)
        if any(f.reason != ARIA or reason == ARIA for f in self.hiding):
            reason = None  # already inside hidden text: the outer element is the finding
        if push and tag not in VOID:
            frame = Frame(tag, line, reason, behind)
            self.where.setdefault(tag, []).append(len(self.stack))
            self.stack.append(frame)
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
        while len(self.stack) > cut:
            frame = self.stack.pop()
            self.where[frame.tag].pop()
            if frame.reason:
                self.hiding.pop()
            self._finish(frame)

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1].tag == "style":
            self._style(data)
        for frame in self.hiding:
            frame.size += len("".join(data.split()))
            if frame.kept < KEPT_TEXT:
                frame.text.append(data[: KEPT_TEXT - frame.kept])
                frame.kept += len(frame.text[-1])

    def _style(self, css: str) -> None:
        line = self.getpos()[0]
        for offset, selector, decls in hidden_css.rules(css):
            if hidden_css.no_text(selector):
                continue
            if reason := hidden_css.hidden(decls, None):
                at = line + css.count("\n", 0, offset + len(selector))
                self.out.hidden.append((at, "style", reason, selector))
        for offset, url in hidden_css.urls(css):
            self.out.urls.append((line + css.count("\n", 0, offset), url, True))

    def _finish(self, frame: Frame) -> None:
        if not frame.reason or not frame.size or (frame.reason == ARIA and frame.size < LONG_ARIA):
            return
        self.out.hidden.append((frame.line, frame.tag, frame.reason, " ".join("".join(frame.text).split())))

    def close(self) -> None:
        super().close()
        for frame in reversed(self.stack):
            self._finish(frame)
        self.stack, self.where, self.hiding = [], {}, []


def collect(text: str) -> Collected:
    parser = Collector()
    parser.feed(text)
    parser.close()
    return parser.out
