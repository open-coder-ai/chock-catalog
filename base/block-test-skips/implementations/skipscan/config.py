"""Runner configuration that hides tests: pytest options that deselect, jest ignore patterns that widen."""

from __future__ import annotations

import re

from skipscan import CONFIG
from skipscan.scan import group, line_of

PYTEST_FILES = frozenset({"pytest.ini", ".pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"})
JEST_FILE = re.compile(r"^(?:jest\.config\.[cm]?[jt]s(?:on)?|package\.json)$")
#: `--deselect`, `--ignore`/`--ignore-glob` (not `--ignore-installed`), and `-k` with a `not`.
OPTIONS = re.compile(r"(?<![\w-])--(?:deselect|ignore(?:-glob)?)(?![\w-])|(?<![\w-])-k\b.*\bnot\b")
JEST_KEY = re.compile(r"\btestPathIgnorePatterns\b[\"']?\s*[:=]\s*")
#: Jest's own default: restating it hides nothing.
JEST_DEFAULT = frozenset({"/node_modules/"})


def config_kind(name: str) -> str | None:
    """Which runner config a file is, by its base name."""
    if name in PYTEST_FILES:
        return "pytest-config"
    return "jest-config" if JEST_FILE.match(name) else None


def _pytest_hits(text: str) -> list[tuple[int, str, str | None]]:
    return [
        (number, CONFIG, None)
        for number, line in enumerate(text.splitlines(), 1)
        if not line.lstrip().startswith(("#", ";")) and OPTIONS.search(line)
    ]


def _jest_hits(text: str) -> list[tuple[int, str, str | None]]:
    """One hit per ignore pattern, so a pattern added to the list is new; a computed value is one hit."""
    lines = text.splitlines()
    hits: list[tuple[int, str, str | None]] = []
    for match in JEST_KEY.finditer(text):
        number = line_of(text, match.start())
        if lines[number - 1].lstrip().startswith(("//", "*", "/*")):
            continue
        if text[match.end() : match.end() + 1] != "[":
            hits.append((number, CONFIG, None))
            continue
        end, values = group(text, match.end())
        hits += [
            (line_of(text, at), CONFIG, f"testPathIgnorePatterns|{value}")
            for at, value in values
            if value not in JEST_DEFAULT
        ]
        if _residue(text, match.end() + 1, end - 1, values):
            # A regex literal, a spread or a name: not a string this gate can compare, so the whole list is one key.
            hits.append((number, CONFIG, "testPathIgnorePatterns|" + " ".join(text[match.end() : end].split())))
    return hits


def _residue(text: str, start: int, end: int, values: list[tuple[int, str]]) -> str:
    """What is inside the list besides its string entries, commas and blanks."""
    chars = list(text[start:end])
    for at, value in values:
        chars[at - start : at - start + len(value) + 2] = [" "] * (len(value) + 2)
    return re.sub(r"[\s,]", "", "".join(chars))


def config_hits(kind: str, text: str) -> list[tuple[int, str, str | None]]:
    return _pytest_hits(text) if kind == "pytest-config" else _jest_hits(text)
