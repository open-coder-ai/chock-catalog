"""CSS colours as #rrggbb or transparent: the named colours, hex, rgb() in numbers or percent, and hsl()."""

from __future__ import annotations

import colorsys
import re

from hiddenscan.vocab import vocab

NUM = r"(?:\d+(?:\.\d*)?|\.\d+)"
RGB = re.compile(rf"^rgba?\(\s*({NUM}%?)\s*[, ]\s*({NUM}%?)\s*[, ]\s*({NUM}%?)\s*(?:[,/]\s*({NUM}%?)\s*)?\)$")
HSL = re.compile(rf"^hsla?\(\s*({NUM})(?:deg)?\s*[, ]\s*({NUM})%\s*[, ]\s*({NUM})%\s*(?:[,/]\s*({NUM}%?)\s*)?\)$")
HEX = re.compile(r"^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$")
COLOUR_TOKEN = re.compile(r"(?:rgba?|hsla?)\([^)]*\)|#[0-9a-f]+|[a-z]+")
FULL = 255


def _channel(text: str) -> int:
    value = float(text.rstrip("%")) * (FULL / 100 if text.endswith("%") else 1)
    return max(0, min(FULL, round(value)))


def _alpha_zero(text: str | None) -> bool:
    return text is not None and float(text.rstrip("%")) == 0


def _rgb(value: str) -> str | None:
    if m := RGB.match(value):
        if _alpha_zero(m.group(4)):
            return "transparent"
        return "#" + "".join(f"{_channel(m.group(i)):02x}" for i in (1, 2, 3))
    if m := HSL.match(value):
        if _alpha_zero(m.group(4)):
            return "transparent"
        hue, sat, light = float(m.group(1)) % 360 / 360, float(m.group(2)) / 100, float(m.group(3)) / 100
        red, green, blue = colorsys.hls_to_rgb(hue, min(light, 1), min(sat, 1))
        return "#" + "".join(f"{round(c * FULL):02x}" for c in (red, green, blue))
    return None


def _hex(value: str) -> str | None:
    if not (m := HEX.match(value)):
        return None
    digits = m.group(1)
    if len(digits) in (3, 4):
        digits = "".join(c * 2 for c in digits)
    return "transparent" if digits[6:] == "00" else "#" + digits[:6]


def color(value: str) -> str | None:
    """A colour as #rrggbb or 'transparent'; None for anything else (variables, system colours, keywords)."""
    value = value.strip()
    if value == "transparent":
        return value
    return vocab().colours.get(value) or _rgb(value) or _hex(value)
