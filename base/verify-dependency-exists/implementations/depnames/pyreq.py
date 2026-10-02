"""Python requirement lines: requirements and constraints files, setup.cfg and setup.py literals. Names only."""

from __future__ import annotations

import ast
import configparser
import re

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_TAIL = re.compile(r"\s*(?:$|\[|[=<>!~;(@,])")
_OPTION = re.compile(r"(?<!\s)\s+--?[A-Za-z]")
_INCLUDE = re.compile(r"^(?:-r|-c|--requirement=|--constraint=|--requirement\s+|--constraint\s+)\s*(\S.*)$")
_EDITABLE = re.compile(r"^(?:-e\s*|--editable(?:\s+|=))(\S.*)$")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|(?:git|hg|svn|bzr)\+)")
_USERINFO = re.compile(r"//[^/@]*@")
_LOCAL_SUFFIXES = (".whl", ".zip", ".tar.gz", ".tgz")
_SETUP_KEYS = frozenset({"install_requires", "setup_requires", "tests_require"})
_CFG_KEYS = ("install_requires", "setup_requires", "tests_require")


def logical_lines(text: str) -> list[str]:
    """Requirement lines as pip reads them: continuations joined, comments and blanks dropped."""
    out: list[str] = []
    joined = ""
    for raw in [*text.removeprefix("\ufeff").splitlines(), ""]:
        line = raw.rstrip()
        if line.endswith("\\") and not line.lstrip().startswith("#"):
            joined += line[:-1] + " "
            continue
        full = re.sub(r"(^|\s)#.*$", "", joined + line).strip()
        joined = ""
        if full:
            out.append(full)
    return out


def _local(spec: str) -> bool:
    """A path or archive on disk, which no registry is asked about."""
    low = spec.lower()
    archive = low.endswith(_LOCAL_SUFFIXES) and "://" not in low and "@" not in low
    return spec.startswith((".", "/", "~")) or low.startswith("file:") or archive


def _target(spec: str) -> str | None:
    """The name a requirement target stands for: an egg name or URL for a link, None for a local path or file."""
    if _local(spec):
        return None
    if egg := _EGG.search(spec):
        return egg.group(1)
    return _USERINFO.sub("//", spec.split("#", 1)[0])


def _named(target: str | None) -> tuple[str, str] | None:
    return ("name", target) if target else None


def parse_line(line: str) -> tuple[str, str] | None:
    """("include", path) for -r/-c, ("name", value) for a requirement, None for an option or a local path."""
    if m := _INCLUDE.match(line):
        return "include", m.group(1).split()[0]
    if m := _EDITABLE.match(line):
        spec = _OPTION.split(m.group(1), 1)[0].strip()
        return _named(_target(spec) if _SCHEME.match(spec) or _EGG.search(spec) else None)
    if line.startswith("-"):
        return None
    spec = _OPTION.split(line, 1)[0].strip()
    if _local(spec) or _SCHEME.match(spec):
        return _named(_target(spec))
    m = _NAME.match(spec)
    return ("name", m.group(0)) if m and _TAIL.match(spec, m.end()) else None


def requirement_names(text: str) -> list[str]:
    """Every requirement name in requirement-file text."""
    parsed = (parse_line(line) for line in logical_lines(text))
    return [value for kind, value in filter(None, parsed) if kind == "name"]


def includes(text: str) -> list[str]:
    """Every -r/-c path in requirement-file text, as written."""
    parsed = (parse_line(line) for line in logical_lines(text))
    return [value for kind, value in filter(None, parsed) if kind == "include"]


def setup_cfg_names(text: str) -> list[str]:
    """install_requires, setup_requires, tests_require and every extras_require entry of a setup.cfg."""
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(text.removeprefix("\ufeff"))
    values = [parser.get("options", key, fallback="") for key in _CFG_KEYS]
    if parser.has_section("options.extras_require"):
        values += [value for _, value in parser.items("options.extras_require")]
    return [name for value in values for name in requirement_names(value)]


def _literals(node: ast.expr) -> list[str]:
    """The string elements of a literal list, tuple or set; a computed value yields nothing."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if not isinstance(node, ast.List | ast.Tuple | ast.Set):
        return []
    return [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]


def _is_setup(func: ast.expr) -> bool:
    """`setup(...)` or `anything.setup(...)`."""
    return (isinstance(func, ast.Name) and func.id == "setup") or (
        isinstance(func, ast.Attribute) and func.attr == "setup"
    )


def setup_py_names(text: str) -> list[str]:
    """Names in literal install_requires, setup_requires, tests_require and extras_require of a setup() call.

    The file is parsed, never run; a list built by code (concatenation, a variable, a comprehension) is not read.
    """
    names: list[str] = []
    for node in ast.walk(ast.parse(text.removeprefix("\ufeff"))):
        if not (isinstance(node, ast.Call) and _is_setup(node.func)):
            continue
        for kw in node.keywords:
            if kw.arg in _SETUP_KEYS:
                specs = _literals(kw.value)
            elif kw.arg == "extras_require" and isinstance(kw.value, ast.Dict):
                specs = [s for value in kw.value.values for s in _literals(value)]
            else:
                continue
            names += [name for spec in specs for name in requirement_names(spec)]
    return names
