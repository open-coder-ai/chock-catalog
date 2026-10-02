"""Gemfile and gemspec: gem declarations by regex; Ruby is code, so only the literal forms are read."""

from __future__ import annotations

import re

_GEM = re.compile(r"""^\s*gem\s*\(?\s*['"]([^'"\s]+)['"]""")
_SPEC = re.compile(r"""\badd_(?:runtime_|development_)?dependency\s*\(?\s*['"]([^'"\s]+)['"]""")


def gemfile_names(text: str) -> list[str]:
    """Gem names from `gem 'x'` lines and gemspec add_dependency calls, skipping comments and =begin blocks."""
    names: list[str] = []
    block = False
    for line in text.removeprefix("\ufeff").splitlines():
        if line.startswith("=begin"):
            block = True
        elif line.startswith("=end"):
            block = False
        elif not block and not line.lstrip().startswith("#") and (m := _GEM.match(line) or _SPEC.search(line)):
            names.append(m.group(1))
    return names
