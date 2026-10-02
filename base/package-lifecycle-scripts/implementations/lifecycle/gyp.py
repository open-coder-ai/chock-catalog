"""binding.gyp: a gyp build with no native sources (Phantom Gyp), and command expansions that fetch or decode."""

from __future__ import annotations

import os
import posixpath
import re

from chock_scan import safe_read

from lifecycle import BLOCK, Hit, norm
from lifecycle.signals import danger

STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'')
NATIVE = re.compile(r"(?i)\.(?:c|cc|cpp|cxx|c\+\+|m|mm)$")
ACTION = re.compile(r"""['"]action['"]\s*:\s*\[([^\]]*)\]""")
#: node-addon-api and nan print their include folder this way; it runs no download and no decode.
SAFE_EXPAND = re.compile(r"""^<!@?\(\s*node\s+-p\s+(["'])require\((["'])[\w@./-]+\2\)(?:\.\w+)*\1\s*\)$""")


def _strings(text: str) -> list[tuple[int, str]]:
    """Every quoted string outside `#` comment lines, unescaped, with its offset."""
    code = "".join(
        " " * len(line) if line.lstrip().startswith("#") else line for line in text.splitlines(keepends=True)
    )
    found = []
    for match in STRING.finditer(code):
        raw = match.group(1) if match.group(1) is not None else match.group(2)
        found.append((match.start(), re.sub(r"\\(.)", r"\1", raw)))
    return found


def _inside(root: str, rel: str) -> str | None:
    """The absolute path of `rel` under the repository root, or None when it would leave it."""
    if not root or rel.startswith("../") or rel == ".." or posixpath.isabs(rel):
        return None
    return os.path.join(root, *rel.split("/"))


def _exists(rel: str, writes: dict[str, str], root: str) -> bool:
    if rel in writes:
        return True
    full = _inside(root, rel)
    return bool(full) and os.path.isfile(full)


def has_native(base: str, text: str, writes: dict[str, str], root: str) -> bool:
    """A source the gyp file names with a C, C++ or Objective-C extension exists in the change or the tree.

    A source spelled through a gyp variable (`<(dir)/x.cc`) cannot be resolved and does not count.
    """
    for _, value in _strings(text):
        if NATIVE.search(value) and "<" not in value:
            rel = posixpath.normpath(posixpath.join(base or ".", value))
            if _exists(rel, writes, root):
                return True
    return False


def native_sources(base: str, writes: dict[str, str], root: str) -> bool:
    """package.json `gypfile: true`: a binding.gyp beside it (in the change or on disk) with native sources."""
    rel = posixpath.join(base, "binding.gyp") if base else "binding.gyp"
    text = writes.get(rel)
    if text is None:
        full = _inside(root, rel)
        try:
            text = safe_read.read_text(full) if full else None
        except safe_read.UnreadableError:
            text = None
    return text is not None and has_native(base, text, writes, root)


def binding_gyp(path: str, text: str, writes: dict[str, str], root: str) -> list[Hit]:
    base = posixpath.dirname(path)
    hits = []
    if not has_native(base, text, writes, root):
        hits.append(
            Hit(
                1,
                "gyp-no-native",
                "binding.gyp",
                "",
                BLOCK,
                "binding.gyp builds no C/C++ source that exists: npm runs node-gyp on install",
            )
        )
    spans = [(m.start(1), m.end(1)) for m in ACTION.finditer(text)]
    for offset, value in _strings(text):
        in_action = any(start <= offset < end for start, end in spans)
        if not (value.startswith("<!") or in_action) or SAFE_EXPAND.match(value.strip()):
            continue
        if why := danger(value):
            line = text.count("\n", 0, offset) + 1
            hits.append(Hit(line, "gyp-command", "command", norm(value), BLOCK, f"gyp command {why}"))
    return hits
