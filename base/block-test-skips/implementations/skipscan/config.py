"""Runner configuration that hides tests: pytest options that deselect, jest ignore patterns that widen."""

from __future__ import annotations

import re

from skipscan import CONFIG
from skipscan.scan import PY_BREAK, group, line_index, split_lines

PYTEST_FILES = frozenset(
    {"pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "pyproject.toml", "setup.cfg", "tox.ini"}
)
JEST_FILE = re.compile(r"^(?:jest\.config(?:\.[\w-]+)*\.[cm]?[jt]s(?:on)?|package\.json)$")
#: `--deselect`, `--ignore`/`--ignore-glob` (not `--ignore-installed`), and `-k` (`-vk` too) with a `not`.
OPTIONS = re.compile(r"(?<![\w-])--(?:deselect|ignore(?:-glob)?)(?![\w-])|(?<![\w-])-[A-Za-z]*k\b.*\bnot\b")
#: A section header, `[pytest]`, `[tool:pytest]`, `[tool.pytest.ini_options]`, `[testenv]`.
SECTION = re.compile(r"^\[{1,2}([\w.:\- \"']+)\]{1,2}\s*(?:[#;].*)?$")
#: Outside a pytest section only a line that runs pytest counts, so `flake8 --ignore=E501` is not judged.
#: `PYTEST_ADDOPTS` set from tox `setenv` or hatch `env-vars` counts too, by the same word.
RUNS_PYTEST = re.compile(r"\bpy\.?test\b|\bPYTEST_ADDOPTS\b", re.IGNORECASE)
#: pytest's own sections: `[pytest]`, `[tool:pytest]`, `[tool.pytest.ini_options]` (not `[testenv:pytest-lint]`).
PYTEST_SECTION = re.compile(r"^(?:pytest|tool[:.]pytest\b.*)$")
JEST_KEY = re.compile(r"\btestPathIgnorePatterns\b[\"']?\s*[:=]\s*")
#: Jest's own default: restating it hides nothing.
JEST_DEFAULT = frozenset({"/node_modules/"})


def config_kind(name: str) -> str | None:
    """Which runner config a file is, by its base name."""
    if name in PYTEST_FILES:
        return "pytest-config"
    return "jest-config" if JEST_FILE.match(name) else None


def _code(line: str) -> str:
    """The line before a `#` or `;` comment that starts outside quotes, after a blank or at the start."""
    quote = ""
    for index, char in enumerate(line):
        if quote:
            quote = "" if char == quote else quote
        elif char in "'\"":
            quote = char
        elif char in "#;" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _pytest_hits(text: str) -> list[tuple[int, str, str | None]]:
    hits: list[tuple[int, str, str | None]] = []
    section = ""
    for number, line in enumerate(split_lines(text, PY_BREAK), 1):
        if header := SECTION.match(line):
            # TOML allows `[ tool.pytest.ini_options ]` and `[tool."pytest".ini_options]`; pytest honours both.
            section = re.sub(r"\s*([.:])\s*", r"\1", header.group(1).strip()).replace('"', "").replace("'", "")
            continue
        code = _code(line)
        if OPTIONS.search(code) and (PYTEST_SECTION.match(section) or RUNS_PYTEST.search(code)):
            hits.append((number, CONFIG, None))
    return hits


def _jest_hits(text: str) -> list[tuple[int, str, str | None]]:
    """One hit per ignore pattern, so a pattern added to the list is new; a computed value is one hit."""
    lines = split_lines(text)
    line_of = line_index(text)
    hits: list[tuple[int, str, str | None]] = []
    for match in JEST_KEY.finditer(text):
        number = line_of(match.start())
        if lines[number - 1].lstrip().startswith(("//", "*", "/*")):
            continue
        if text[match.end() : match.end() + 1] != "[":
            hits.append((number, CONFIG, None))
            continue
        end, values = group(text, match.end())
        hits += [
            (line_of(at), CONFIG, f"testPathIgnorePatterns|{value}")
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
