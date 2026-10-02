"""CSS read just far enough to tell whether a declaration block hides its text, and which URLs it loads."""

from __future__ import annotations

import re

COMMENT = re.compile(r"/\*[\s\S]*?(?:\*/|$)")
HEX_ESCAPE = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n]?")
CHAR_ESCAPE = re.compile(r"\\(.)")
IMPORTANT = re.compile(r"!\s*important\s*$")
#: Anchored at the start or just after a brace, so a long run without one is read once, not once per character.
RULE = re.compile(r"(?:^|(?<=[{}]))([^{}]*)\{([^{}]*)\}")
URL_FUNC = re.compile(r"url\(\s*(['\"]?)([^'\")\s]*)\1\s*\)|@import\s+(['\"])([^'\"]*)\3", re.IGNORECASE)
NUMBER = re.compile(r"^(-?(?:\d+\.?\d*|\.\d+))([a-z%]*)$")
NAMED = {"white": "#ffffff", "black": "#000000", "transparent": "transparent"}
RGB = re.compile(r"^rgba?\(\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*(?:[,/]\s*([\d.]+%?)\s*)?\)$")
HEX = re.compile(r"^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$")
OFFSCREEN = ("left", "top", "right", "bottom", "text-indent", "margin-left", "margin-top")
#: The page a reader sees when nothing sets a background.
DEFAULT_BACKGROUND = "#ffffff"
LAST_CODE_POINT = 0x10FFFF
SURROGATES = range(0xD800, 0xE000)
#: Offsets past these put a box out of any viewport.
OFF_PX, OFF_EM = -999, -50


def unescape(text: str) -> str:
    """CSS escapes decoded (`\\64 isplay` is `display`) so an escaped property is read as written for the browser."""

    def code(m: re.Match[str]) -> str:
        value = int(m.group(1), 16)
        return chr(value) if 0 < value <= LAST_CODE_POINT and value not in SURROGATES else "�"

    return CHAR_ESCAPE.sub(r"\1", HEX_ESCAPE.sub(code, text))


def declarations(block: str) -> dict[str, str]:
    """Property to value, lower-cased, comments and `!important` dropped; the last declaration wins."""
    out: dict[str, str] = {}
    for part in unescape(COMMENT.sub(" ", block)).split(";"):
        name, colon, value = part.partition(":")
        if colon:
            out[name.strip().lower()] = IMPORTANT.sub("", value.strip().lower()).strip()
    return out


def color(value: str) -> str | None:
    """A colour as #rrggbb or 'transparent'; None for anything else (hsl, variables, keywords)."""
    value = value.strip()
    if value in NAMED:
        return NAMED[value]
    if m := RGB.match(value):
        alpha = m.group(4)
        if alpha is not None and _number(alpha.rstrip("%")) == 0:
            return "transparent"
        channels = [min(int(m.group(i)), 255) for i in (1, 2, 3)]
        return "#" + "".join(f"{c:02x}" for c in channels)
    if m := HEX.match(value):
        digits = m.group(1)
        if len(digits) in (3, 4):
            digits = "".join(c * 2 for c in digits)
        return "transparent" if digits[6:] == "00" else "#" + digits[:6]
    return None


def background(decls: dict[str, str]) -> str | None:
    """The background colour a block declares, from background-color or the first colour in background."""
    if "background-color" in decls:
        return color(decls["background-color"])
    for token in decls.get("background", "").split():
        if found := color(token):
            return found
    return None


def _number(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def _length(value: str) -> tuple[float, str] | None:
    m = NUMBER.match(value.strip())
    return (float(m.group(1)), m.group(2)) if m else None


def tiny_font(value: str) -> bool:
    """A font size nobody reads: zero in any unit, 1px/1pt or less, a tenth of an em, a tenth of the parent."""
    size = _length(value.split(maxsplit=1)[0].split("/", maxsplit=1)[0]) if value.split() else None
    if size is None:
        return False
    number, unit = size
    limits = {"px": 1, "pt": 1, "em": 0.1, "rem": 0.1, "ex": 0.2, "ch": 0.2, "%": 10, "vw": 0.1, "vh": 0.1}
    return number <= 0 or number <= limits.get(unit, 0)


def _offscreen(decls: dict[str, str]) -> bool:
    for prop in OFFSCREEN:
        size = _length(decls.get(prop, ""))
        if size and (size[0] <= OFF_PX or (size[1] in ("em", "rem") and size[0] <= OFF_EM)):
            return True
    clip = decls.get("clip", "").replace(",", " ")
    if re.fullmatch(r"rect\(\s*(?:0(?:px)?\s+){3}0(?:px)?\s*\)|rect\(\s*(?:1px\s+){3}1px\s*\)", clip):
        return True
    return bool(re.fullmatch(r"inset\(\s*(?:50|100)%\s*\)|circle\(\s*0(?:px|%)?\s*\)", decls.get("clip-path", "")))


def hidden(decls: dict[str, str], under: str | None) -> str | None:
    """Why a declaration block hides its text, or None. `under` is the background behind the text,
    when known; without it, only a colour equal to the block's own background or transparent counts."""
    opacity = _length(decls.get("opacity", ""))
    text = color(decls.get("color", ""))
    behind = background(decls) or under
    checks = (
        (decls.get("display") == "none", "display none"),
        (decls.get("visibility") in ("hidden", "collapse"), "visibility hidden"),
        (bool(opacity) and opacity[0] <= (5 if opacity[1] == "%" else 0.05), "opacity 0"),
        (tiny_font(decls.get("font-size", "")) or tiny_font(decls.get("font", "")), "font size 0 or 1"),
        (bool(re.fullmatch(r"scale\(\s*0(?:\.0*)?\s*\)", decls.get("transform", ""))), "scaled to 0"),
        (_offscreen(decls), "positioned off screen or clipped"),
        (text == "transparent" or (text is not None and text == behind), "text colour equal to background"),
    )
    return next((reason for hit, reason in checks if hit), None)


def no_text(selector: str) -> bool:
    """A keyframe step (from, to, 40%) or a ::before/::after box styles no text of the document."""
    if re.fullmatch(r"(?:from|to|[\d.]+%)(?:\s*,\s*(?:from|to|[\d.]+%))*", selector.strip().lower()):
        return True
    return all(re.search(r"::?(?:before|after|marker|placeholder)\s*$", part) for part in selector.split(","))


def rules(css: str) -> list[tuple[int, str, dict[str, str]]]:
    """(offset, selector, declarations) of each innermost rule in a style sheet."""
    clean = COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), css)
    return [(m.start(), m.group(1).strip(), declarations(m.group(2))) for m in RULE.finditer(clean)]


def urls(css: str) -> list[tuple[int, str]]:
    """(offset, URL) of each `url()` and `@import` in CSS text."""
    clean = unescape(css)
    return [(m.start(), m.group(2) if m.group(2) is not None else m.group(4)) for m in URL_FUNC.finditer(clean)]
