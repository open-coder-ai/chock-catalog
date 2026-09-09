"""The one visual language every open-coder-ai figure is drawn in."""

# Enforcement is ordinal: advisory < in-agent < enforced. Never reorder these.
ENFORCEMENT = {
    "light": ["#86b6ef", "#2a78d6", "#104281"],
    "dark": ["#9ec5f4", "#3987e5", "#184f95"],
}

# agentseam grades five levels; the ramp is the same hue walked further.
LEVELS = {
    "light": ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281"],
    "dark": ["#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95"],
}

# Absence is not a low score, so it is never a ramp colour.
NEUTRAL = {"light": "#d8d7d2", "dark": "#383835"}

SURFACE = {"light": "#fcfcfb", "dark": "#1a1a19"}
TEXT = {"light": "#0b0b0b", "dark": "#ffffff"}
TEXT_SECONDARY = {"light": "#52514e", "dark": "#c3c2b7"}

STROKE_WIDTH = 2
CORNER = 4
GAP = 2  # surface showing between adjacent fills
GRID_OPACITY = 0.3

SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace"

THEMES = ("light", "dark")


def theme(name):
    """Every colour of one theme, resolved."""
    return {
        "enforcement": ENFORCEMENT[name],
        "levels": LEVELS[name],
        "neutral": NEUTRAL[name],
        "surface": SURFACE[name],
        "text": TEXT[name],
        "secondary": TEXT_SECONDARY[name],
    }


def esc(s):
    """XML-escape a label."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def open_svg(width, height, t, title, desc):
    """An accessible root element: the title and description are the alt text."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
        'viewBox="0 0 %d %d" role="img" aria-labelledby="t d">\n'
        "  <title id=\"t\">%s</title>\n  <desc id=\"d\">%s</desc>\n"
        '  <rect width="%d" height="%d" fill="%s"/>\n'
        % (width, height, width, height, esc(title), esc(desc), width, height, t["surface"])
    )


def close_svg():
    return "</svg>\n"


def box(x, y, w, h, fill, stroke=None, rx=CORNER):
    stroke_attr = ' stroke="%s" stroke-width="%d"' % (stroke, STROKE_WIDTH) if stroke else ""
    return '  <rect x="%g" y="%g" width="%g" height="%g" rx="%d" fill="%s"%s/>\n' % (
        x, y, w, h, rx, fill, stroke_attr,
    )


def text(x, y, s, fill, size=13, family=SANS, weight="400", anchor="start"):
    return (
        '  <text x="%g" y="%g" font-family="%s" font-size="%g" font-weight="%s" '
        'fill="%s" text-anchor="%s">%s</text>\n'
        % (x, y, family, size, weight, fill, anchor, esc(s))
    )


def arrow(x1, y1, x2, y2, colour, head=6):
    """A straight connector with a solid head, drawn in one path."""
    out = '  <line x1="%g" y1="%g" x2="%g" y2="%g" stroke="%s" stroke-width="%d" stroke-linecap="round"/>\n' % (
        x1, y1, x2, y2, colour, STROKE_WIDTH,
    )
    if y2 > y1 and x1 == x2:  # down
        pts = "%g,%g %g,%g %g,%g" % (x2, y2, x2 - head, y2 - head, x2 + head, y2 - head)
    elif y2 < y1 and x1 == x2:  # up
        pts = "%g,%g %g,%g %g,%g" % (x2, y2, x2 - head, y2 + head, x2 + head, y2 + head)
    elif x2 > x1:  # right
        pts = "%g,%g %g,%g %g,%g" % (x2, y2, x2 - head, y2 - head, x2 - head, y2 + head)
    else:  # left
        pts = "%g,%g %g,%g %g,%g" % (x2, y2, x2 + head, y2 - head, x2 + head, y2 + head)
    return out + '  <polygon points="%s" fill="%s"/>\n' % (pts, colour)


def write_pair(stem, render):
    """`render(theme_colours, theme_name) -> svg string`, written once per theme."""
    written = []
    for name in THEMES:
        path = "%s-%s.svg" % (stem, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render(theme(name), name))
        written.append(path)
    return written


def wrap(s, width):
    """Greedy wrap to `width` characters, so a label fits its box without a font metric."""
    words, lines, line = s.split(), [], ""
    for w in words:
        candidate = (line + " " + w).strip()
        if len(candidate) > width and line:
            lines.append(line)
            line = w
        else:
            line = candidate
    if line:
        lines.append(line)
    return lines
