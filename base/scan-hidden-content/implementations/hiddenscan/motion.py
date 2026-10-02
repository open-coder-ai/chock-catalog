"""CSS animations read far enough to tell whether one can show text a declaration block hides."""

from __future__ import annotations

import re

from hiddenscan import css

KEYFRAME_TOKENS = re.compile(r"@(?:-webkit-)?keyframes\s+([\w-]+)\s*\{|\{|\}")
#: animation and animation-name declarations anywhere in a file: inline styles, style sheets.
ANIMATION_DECL = re.compile(r"animation(?:-name)?\s*:\s*([^;}\"'<>]{1,500})")
TIME = re.compile(r"(-?(?:\d+\.?\d*|\.\d+))(ms|s)(?![\w-])")
WORD = re.compile(r"[\w-]+")
#: Past this delay an animation that would show the text is not counted as showing it.
MAX_DELAY_SECONDS = 5.0
#: The properties each hiding reason is set by: a keyframe shows the text only by changing one of them.
REASON_PROPS = {
    "display none": {"display"},
    "visibility hidden": {"visibility", "content-visibility"},
    "opacity 0": {"opacity", "fill-opacity"},
    "fill none": {"fill"},
    "font size 0 or 1": {"font-size", "font"},
    "scaled to 0": {"transform", "scale"},
    "positioned off screen, clipped or collapsed": {
        "left",
        "top",
        "right",
        "bottom",
        "text-indent",
        "margin-left",
        "margin-top",
        "transform",
        "translate",
        "clip",
        "clip-path",
        "height",
        "max-height",
        "width",
        "max-width",
        "overflow",
    },
    "text colour equal to background": {"color", "-webkit-text-fill-color", "fill", "background", "background-color"},
}


def _shows(prop: str, value: str) -> bool:
    """Whether one keyframe declaration sets its property to a value that shows text."""
    if prop in ("opacity", "fill-opacity"):
        amount = css.number(value)
        return bool(amount) and amount[0] > (css.FAINT * 100 if amount[1] == "%" else css.FAINT)
    if prop in ("visibility", "content-visibility"):
        return value in ("visible", "auto")
    if prop == "display":
        return value != "none"
    if prop in ("font-size", "font"):
        return not css.tiny_font(value)
    return css.hidden({prop: value}, None) is None


def _seconds(match: re.Match[str]) -> float:
    return float(match.group(1)) / (1000 if match.group(2) == "ms" else 1)


def running(decls: dict[str, str]) -> bool:
    """Whether a block declares an animation that plays: not paused, not of zero duration, not delayed for
    longer than MAX_DELAY_SECONDS. A duration or delay not set here may come from another rule."""
    shorthand = decls.get("animation", "")
    if not shorthand and "animation-name" not in decls:
        return False
    if "paused" in (shorthand + " " + decls.get("animation-play-state", "")).split():
        return False
    times = [_seconds(m) for m in TIME.finditer(shorthand)]
    duration = [_seconds(m) for m in TIME.finditer(decls.get("animation-duration", ""))] or times[:1]
    delay = [_seconds(m) for m in TIME.finditer(decls.get("animation-delay", ""))] or times[1:2]
    return not (duration and duration[0] <= 0) and not (delay and delay[0] > MAX_DELAY_SECONDS)


class Motion:
    """The keyframes of one file, each with the properties it shows, and the names the file applies."""

    def __init__(self, sheets: list[str], text: str) -> None:
        self.shows: dict[str, set[str]] = {}
        for sheet in sheets:
            self._keyframes(css.COMMENT.sub(" ", sheet).lower())
        lowered = css.COMMENT.sub(" ", text).lower()
        self.named = {word for m in ANIMATION_DECL.finditer(lowered) for word in WORD.findall(m.group(1))}

    def _keyframes(self, sheet: str) -> None:
        frames: list[tuple[str, int, int]] = []  # (name, depth, body start)
        depth = 0
        for m in KEYFRAME_TOKENS.finditer(sheet):
            if m.group(1):
                depth += 1
                frames.append((m.group(1), depth, m.end()))
            elif m.group(0) == "{":
                depth += 1
            else:
                if frames and frames[-1][1] == depth:
                    name, _, start = frames.pop()
                    shown = self.shows.setdefault(name, set())
                    body = sheet[start : m.start()]
                    shown.update(p for _, _, decls in css.rules(body) for p, v in decls.items() if _shows(p, v))
                depth = max(depth - 1, 0)

    def reveals(self, decls: dict[str, str], reason: str) -> bool:
        """Whether this block plays a keyframe of the file that shows what `reason` hides. A block that
        names no keyframe of its own counts when a keyframe the file applies somewhere shows it."""
        if not running(decls):
            return False
        props = REASON_PROPS.get(reason, set())
        words = set(WORD.findall(decls.get("animation-name", "") + " " + decls.get("animation", "")))
        own = [name for name in words if name in self.shows]
        if own:
            return any(self.shows[name] & props for name in own)
        return any(name in self.named and shown & props for name, shown in self.shows.items())
