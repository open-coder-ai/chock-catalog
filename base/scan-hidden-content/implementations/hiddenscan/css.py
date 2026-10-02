"""CSS read just far enough to tell whether a declaration block hides its text, and which URLs it loads."""

from __future__ import annotations

import re

from hiddenscan.colours import COLOUR_TOKEN, NUM, color

COMMENT = re.compile(r"/\*[\s\S]*?(?:\*/|$)")
HEX_ESCAPE = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n]?")
CHAR_ESCAPE = re.compile(r"\\(.)")
IMPORTANT = re.compile(r"!\s*important\s*$")
#: Anchored at the start or just after a brace, so a long run without one is read once, not once per character.
RULE = re.compile(r"(?:^|(?<=[{}]))([^{}]*)\{([^{}]*)\}")
URL_FUNC = re.compile(
    r"url\(\s*(['\"]?)([^'\")\s]*)\1\s*\)|@import\s+(['\"])([^'\"]*)\3|image-set\(\s*(['\"])([^'\"]*)\5",
    re.IGNORECASE,
)
NUMBER = re.compile(r"^(-?(?:\d+\.?\d*|\.\d+))([a-z%]*)$")
GLOBAL = {"inherit", "initial", "unset", "revert", "revert-layer"}
DISPLAY = GLOBAL | set(
    [
        "none",
        "block",
        "inline",
        "inline-block",
        "flex",
        "inline-flex",
        "grid",
        "inline-grid",
        "table",
        "inline-table",
        "table-row",
        "table-cell",
        "table-caption",
        "table-column",
        "table-column-group",
        "table-header-group",
        "table-footer-group",
        "table-row-group",
        "list-item",
        "contents",
        "flow-root",
        "flow",
        "run-in",
        "ruby",
        "ruby-text",
        "ruby-base",
        "ruby-text-container",
        "ruby-base-container",
        "math",
    ]
)
FONT_SIZES = GLOBAL | set(
    ["xx-small", "x-small", "small", "medium", "large", "x-large", "xx-large", "xxx-large", "larger", "smaller", "math"]
)
OFFSCREEN = ("left", "top", "right", "bottom", "text-indent", "margin-left", "margin-top")
#: The page a reader sees when nothing sets a background.
DEFAULT_BACKGROUND = "#ffffff"
LAST_CODE_POINT = 0x10FFFF
SURROGATES = range(0xD800, 0xE000)
#: Offsets past these put a box out of any viewport.
OFF_PX, OFF_EM, OFF_VW, FAR_PX = -999, -50, -50, 9999
#: Properties a keyframe may change to show what a block hides.
FAINT = 0.05


def unescape(text: str) -> str:
    """CSS escapes decoded (`\\64 isplay` is `display`) so an escaped property is read as written for the browser."""

    def code(m: re.Match[str]) -> str:
        value = int(m.group(1), 16)
        return chr(value) if 0 < value <= LAST_CODE_POINT and value not in SURROGATES else "�"

    return CHAR_ESCAPE.sub(r"\1", HEX_ESCAPE.sub(code, text))


def number(value: str) -> tuple[float, str] | None:
    m = NUMBER.match(value.strip())
    return (float(m.group(1)), m.group(2)) if m else None


VALID = {
    "display": lambda v: all(word in DISPLAY for word in v.split()),
    "visibility": lambda v: v in GLOBAL | {"visible", "hidden", "collapse"},
    "content-visibility": lambda v: v in GLOBAL | {"visible", "hidden", "auto"},
    "opacity": lambda v: v in GLOBAL or number(v) is not None,
    "fill-opacity": lambda v: v in GLOBAL or number(v) is not None,
    "font-size": lambda v: v in FONT_SIZES or number(v) is not None or "(" in v,
    "color": lambda v: color(v) is not None or v in GLOBAL | {"currentcolor"} or "(" in v,
    "background-color": lambda v: color(v) is not None or v in GLOBAL | {"currentcolor"} or "(" in v,
    "-webkit-text-fill-color": lambda v: color(v) is not None or v in GLOBAL | {"currentcolor"} or "(" in v,
    "fill": lambda v: color(v) is not None or v in GLOBAL | {"currentcolor", "none"} or "(" in v,
}


def _valid(name: str, value: str) -> bool:
    """Whether a browser keeps this declaration: an invalid one is dropped and the earlier one stands."""
    return bool(value) and VALID.get(name, bool)(value)


def declarations(block: str) -> dict[str, str]:
    """Property to value, lower-cased, comments and `!important` dropped; the last valid declaration wins."""
    out: dict[str, str] = {}
    for part in unescape(COMMENT.sub(" ", block)).split(";"):
        name, colon, value = part.partition(":")
        name, value = name.strip().lower(), IMPORTANT.sub("", value.strip().lower()).strip()
        if colon and _valid(name, value):
            out[name] = value
    return out


def background(decls: dict[str, str]) -> str | None:
    """The background colour a block declares, from background-color or the first colour in background."""
    if "background-color" in decls:
        return color(decls["background-color"])
    for piece in COLOUR_TOKEN.findall(decls.get("background", "")):
        if found := color(piece):
            return found
    return None


def tiny_font(value: str) -> bool:
    """A font size nobody reads: zero in any unit, 1px/1pt or less, a tenth of an em, a tenth of the parent."""
    size = number(value.split(maxsplit=1)[0].split("/", maxsplit=1)[0]) if value.split() else None
    if size is None:
        return False
    amount, unit = size
    limits = {"px": 1, "pt": 1, "em": 0.1, "rem": 0.1, "ex": 0.2, "ch": 0.2, "%": 10, "vw": 0.1, "vh": 0.1}
    return amount <= 0 or amount <= limits.get(unit, 0)


def _far(value: str) -> bool:
    size = number(value)
    if not size:
        return False
    amount, unit = size
    if unit in ("px", "") and amount >= FAR_PX:
        return True
    return amount <= (OFF_EM if unit in ("em", "rem") else OFF_VW if unit in ("vw", "vh", "%") else OFF_PX)


def _offscreen(decls: dict[str, str]) -> bool:
    if any(_far(decls.get(prop, "")) for prop in OFFSCREEN):
        return True
    translate = re.findall(
        r"translate[xy]?\(\s*([^,)\s]+)", decls.get("transform", "") + " " + decls.get("translate", "")
    )
    if any(_far(t) for t in translate):
        return True
    clip = decls.get("clip", "").replace(",", " ")
    if re.fullmatch(r"rect\(\s*(?:0(?:px)?\s+){3}0(?:px)?\s*\)|rect\(\s*(?:1px\s+){3}1px\s*\)", clip):
        return True
    return bool(re.fullmatch(r"inset\(\s*(?:50|100)%\s*\)|circle\(\s*0(?:px|%)?\s*\)", decls.get("clip-path", "")))


def _scaled_away(transform: str) -> bool:
    return any(abs(float(s)) <= FAINT for s in re.findall(rf"scale[xy]?\(\s*(-?{NUM})\s*[,)]", transform))


def _collapsed(decls: dict[str, str]) -> bool:
    zero = any((number(decls.get(p, "")) or (1, ""))[0] == 0 for p in ("height", "max-height", "width", "max-width"))
    return zero and decls.get("overflow", "").split()[:1] in (["hidden"], ["clip"])


def _faint(value: str) -> bool:
    opacity = number(value)
    return bool(opacity) and opacity[0] <= (FAINT * 100 if opacity[1] == "%" else FAINT)


def hidden(decls: dict[str, str], under: str | None, *, svg: bool = False, motion: object = None) -> str | None:
    """Why a declaration block hides its text, or None. `under` is the background behind the text, when
    known; without it, only a colour equal to the block's own background or transparent counts. In SVG
    the text colour is `fill`. With `motion` (a motion.Motion), a block a keyframe of the file shows is not hidden."""
    if not decls:
        return None
    source = (
        "fill"
        if svg and "fill" in decls
        else "-webkit-text-fill-color"
        if "-webkit-text-fill-color" in decls
        else "color"
    )
    text = color(decls.get(source, ""))
    behind = background(decls) or under
    checks = (
        (decls.get("display") == "none", "display none"),
        (
            decls.get("visibility") in ("hidden", "collapse") or decls.get("content-visibility") == "hidden",
            "visibility hidden",
        ),
        (_faint(decls.get("opacity", "")) or (svg and _faint(decls.get("fill-opacity", ""))), "opacity 0"),
        (svg and decls.get("fill") == "none", "fill none"),
        (tiny_font(decls.get("font-size", "")) or tiny_font(decls.get("font", "")), "font size 0 or 1"),
        (
            _scaled_away(decls.get("transform", "") + (f" scale({decls['scale']})" if "scale" in decls else "")),
            "scaled to 0",
        ),
        (_offscreen(decls) or _collapsed(decls), "positioned off screen, clipped or collapsed"),
        (text == "transparent" or (text is not None and text == behind), "text colour equal to background"),
    )
    reason = next((reason for hit, reason in checks if hit), None)
    return None if reason and motion is not None and motion.reveals(decls, reason) else reason


def no_text(selector: str) -> bool:
    """A keyframe step (from, to, 40%) or a ::before/::after box styles no text of the document."""
    if re.fullmatch(r"(?:from|to|[\d.]+%)(?:\s*,\s*(?:from|to|[\d.]+%))*", selector.strip().lower()):
        return True
    return all(re.search(r"::?(?:before|after|marker|placeholder)\s*$", part) for part in selector.split(","))


def rules(css: str) -> list[tuple[int, str, dict[str, str]]]:
    """(offset, selector, declarations) of each innermost rule in a style sheet."""
    clean = COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), css)
    return [(m.start(), m.group(1).strip(), declarations(m.group(2))) for m in RULE.finditer(clean)]


def selector_targets(selector: str) -> list[str]:
    """The `.class` and `#id` names a selector's parts end in, lower-cased; other selectors name none."""
    out = []
    for part in selector.split(","):
        last = part.strip().split()[-1:] or [""]
        out += [m.lower() for m in re.findall(r"[.#][\w-]+", last[0])]
    return out


def urls(css: str) -> list[tuple[int, str]]:
    """(offset, URL) of each `url()`, `@import` and `image-set()` in CSS text."""
    clean = unescape(css)
    return [(m.start(), next(g for g in m.group(2, 4, 6) if g is not None)) for m in URL_FUNC.finditer(clean)]
