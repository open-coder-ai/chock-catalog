"""Rewrite a line so keyword_values reads the assignments source code and embedded strings spell differently.

The rewrite only feeds detection; nothing is written back and line numbers do not change.
- every file: an escaped quote (`\\"`, `\\'`) becomes the quote, so JSON-in-a-string and notebook
  cells (`"api_key = \\"v\\"\\n"`) read as the assignment they hold;
- source code: a string prefix before a quote (`f"`, `b'`, `r"`, `@"`, `$"`) is dropped, a type
  annotation between key and `=` is dropped (`apiKey: string = "v"`, `let key: &str = "v"`,
  `var key string = "v"` in Go), and `#define KEY "v"` reads as `KEY = "v"`.

`typed(line, column, value)` says whether the value at that column is the type of a function parameter, in text
that is not itself source code (a signature inside a YAML or JSON string): a type name is no secret.

`opened(line, column)` says whether a value at that column is a string literal's text in source
code: its own opening quote sits right before it (after an auth word), or the line before it holds
an unclosed quote (the key is itself inside a literal: a connection string, a URL query).
"""

from __future__ import annotations

import re

_ESCAPED_QUOTE = re.compile(r"\\([\"'])")
_PREFIX = re.compile(r"(?<![\w\"'])(?:[fFbBrRuU]{1,2}|@\$?|\$@?)(?=[\"'])")
#: A declaration with a type annotation, at a statement start or after a declaring keyword, so a
#: `case token: x = v` keeps its key. Every quantifier is bounded and possessive: a long line of
#: `a:` and blanks costs linear time.
_ANNOTATION = re.compile(
    r"(\A[ \t]{0,64}+|[;{(,][ \t]{0,16}+|\b(?:let|const|var|val|private|public|protected|readonly|static|mut|final)"
    r"[ \t]{1,16}+)([A-Za-z_]\w{0,127}+)[ \t]{0,16}+:[ \t]{0,16}+(?:&'\w{1,16}+[ \t]{1,4}+)?"
    r"[&\w<>\[\].,]{1,60}+(?:[ \t]{1,4}+(?:\|[ \t]{1,4}+)?[&\w<>\[\].,]{1,30}+){0,3}+[ \t]{0,16}+=(?![=>])"
)
#: Go's `var name Type =` (and const); in C# `const string Name =` the type comes first, so Go only.
_GO_VAR = re.compile(r"\b(?:var|const)[ \t]{1,16}+([A-Za-z_]\w{0,127}+)[ \t]{1,16}+[\w.*\[\]]{1,60}+[ \t]{0,16}+=(?!=)")
_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+(?=[\"'])")
_OPENED = re.compile(r"[\"'`](?:(?i:bearer|basic|token|bot)[ \t]{1,16})?\Z")
_QUOTES = "\"'`"
#: A parameter name and its colon at the end of a function signature's opened parameter list; the
#: window and every quantifier are bounded, and the repeated alternatives exclude each other.
_PARAMETER = re.compile(
    r"\b(?:def|fn|func|function|fun)[ \t]{1,8}[A-Za-z_]\w{0,63}[ \t]{0,8}\((?:[^()]|\([^()]{0,64}\)){0,300}"
    r"[A-Za-z_]\w{0,63}[ \t]{0,4}:[ \t]{0,8}\Z"
)
_WINDOW = 400
#: A type name holds at most this many runs of digits (`Ed25519PrivateKey`: one); a random value holds more.
_DIGIT_RUNS = 2
_DIGITS = re.compile(r"[0-9]+")
#: A type as a signature spells it: dotted lowercase scope, then CamelCase words or a short lowercase
#: name, with type arguments of the same; a random credential has no such case pattern.
_NAME = r"(?:[a-z_][a-z0-9_]{0,30}\.){0,4}(?:(?:[A-Z][a-z]{0,20}[0-9]{0,6}){1,8}|[a-z]{2,8})"
_TYPE = re.compile(rf"{_NAME}(?:\[{_NAME}(?:,[ \t]?{_NAME}){{0,3}}\]?)?")


def rewrite(line: str, *, language: str | None) -> str:
    """The line as detection reads it (see the module docstring); language is a source file's suffix."""
    line = _ESCAPED_QUOTE.sub(r"\1", line)
    if language is None:
        return line
    line = _PREFIX.sub("", line)
    line = _DEFINE.sub(r"\1 = ", line)
    if language == "go":
        line = _GO_VAR.sub(r"\1 =", line)
    return _ANNOTATION.sub(r"\1\2 =", line)


def opened(line: str, column: int) -> bool:
    """True when the value at column is inside a string literal of a source-code line."""
    before = line[:column]
    return _OPENED.search(before[-24:]) is not None or any(before.count(q) % 2 for q in _QUOTES)


def typed(line: str, column: int, value: str) -> bool:
    """True when value, at column, is a type following `name:` inside a function signature's parameters."""
    if len(_DIGITS.findall(value)) > _DIGIT_RUNS:
        return False
    return _TYPE.fullmatch(value) is not None and _PARAMETER.search(line[max(0, column - _WINDOW) : column]) is not None
