"""Which lines of a network security config sit inside its <base-config> element.

`<base-config>` sets the fallback that applies to every domain a `<domain-config>` does not name
specifically -- a per-domain override, meant for one known local host, is a different and far
narrower decision than the app-wide default, so both rules that read this file must tell the two
apart rather than fire on either one.
"""

from __future__ import annotations

from chock_security.decision import FileText

_OPEN = "<base-config"
_CLOSE = "</base-config>"


def base_config_lines(text: FileText) -> set[int]:
    """Every line number (1-based) that sits inside a `<base-config>` element, its own opening
    and self-closing line included. Nothing here nests a `<base-config>` inside another, so a
    single depth counter is exact, not an approximation."""
    if not text.holds("<network-security-config"):
        return set()
    lines: set[int] = set()
    depth = 0
    for line_no, line in enumerate(text.lines, 1):
        stripped = line.strip()
        opens = stripped.startswith(_OPEN)
        if opens:
            depth += 1
        if depth > 0:
            lines.add(line_no)
        if opens and stripped.endswith("/>"):
            depth = max(depth - 1, 0)
        elif stripped.startswith(_CLOSE):
            depth = max(depth - 1, 0)
    return lines
