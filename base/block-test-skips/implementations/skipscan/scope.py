"""The test or class enclosing each line, computed once per file: from the syntax tree for Python, else outline."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable

#: A declaration a skip sits under: a type, method or function (Kotlin backtick names and C#/Java
#: modifiers included), or a describe/it/test block's title.
DECLARES = re.compile(
    r"\b(?:class|struct|record|interface|object|void|func|fun|fn|def|function|module|mod)\s+(?:\([^)]*\)\s*)?(\w+)"
    r"|\bfun\s+`([^`]+)`"
    r"|\b(?:public|private|protected|internal|static|async|override|virtual|final|suspend)\s+"
    r"(?:[\w<>\[\],.?]+\s+)*?(\w+)\s*\("
    r"|\b(?:describe|context|it|test|specify)(?:\.\w+)?[\s(]\s*['\"`]([^'\"`]+)"
)
ANNOTATIONS = ("@", "#[", "# [", "[")
#: A line that looks like a method or test declaration DECLARES cannot name: its text names it instead.
SIGNATURE = re.compile(r"\w\s*\(")


def declared(line: str) -> str | None:
    """The test or type a line declares, if it does."""
    found = DECLARES.search(line)
    return next((group for group in found.groups() if group), None) if found else None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def outline_scopes(lines: list[str]) -> list[str]:
    """Per line: the declarations above it indented less than it; an annotation adds what it marks.

    What it marks is the next line that is not an annotation, named by its declaration or, when it
    looks like a signature this cannot name, by its own text, so two unnamed targets still differ.
    """
    targets = [""] * len(lines)
    below = ""
    for index in range(len(lines) - 1, -1, -1):
        own = declared(lines[index])
        if lines[index].lstrip().startswith(ANNOTATIONS):
            # `@Test void a() {...}` marks itself.
            targets[index] = below = own or below
        else:
            text = " ".join(lines[index].split())
            below = own or (text if SIGNATURE.search(text) else "")
    stack: list[tuple[int, str]] = []
    scopes: list[str] = []
    for index, line in enumerate(lines):
        indent = _indent(line)
        names = [name for depth, name in stack if depth < indent]
        if line.lstrip().startswith(ANNOTATIONS):
            names.append(targets[index])
        scopes.append(".".join(name for name in names if name))
        name = declared(line) if line.strip() else None
        if name:
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, name))
    return scopes


def python_scopes(text: str) -> Callable[[int], str] | None:
    """Line -> dotted names of the classes and functions holding it, a decorator counting as its function's."""
    try:
        parsed = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    holders = sorted(
        (min([n.lineno, *(d.lineno for d in n.decorator_list)]), n.end_lineno or n.lineno, n.name)
        for n in ast.walk(parsed)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
    )
    return lambda number: ".".join(name for start, end, name in holders if start <= number <= end)


def scopes_for(path: str, text: str) -> Callable[[int], str]:
    """A lookup from line number to enclosing scope for one file."""
    if path.endswith(".py") and (named := python_scopes(text)) is not None:
        return named
    outline = outline_scopes(text.splitlines())
    return lambda number: outline[number - 1]
