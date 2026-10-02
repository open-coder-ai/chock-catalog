"""Rewrite a line so keyword_values reads the assignments source code and embedded strings spell differently.

The rewrite only feeds detection; nothing is written back and line numbers do not change.
- every file: an escaped quote (`\\"`, `\\'`) becomes the quote, so JSON-in-a-string and notebook
  cells (`"api_key = \\"v\\"\\n"`) read as the assignment they hold;
- source code: a string prefix before a quote (`f"`, `b'`, `r"`, `@"`, `$"`) is dropped, a type
  annotation between key and `=` is dropped (`apiKey: string = "v"`, `let key: &str = "v"`,
  `var key string = "v"`), and `#define KEY "v"` reads as `KEY = "v"`.

`opened(line, column)` says whether a value at that column is a string literal's text in source
code: its own opening quote sits right before it (after an auth word), or the line before it holds
an unclosed quote (the key is itself inside a literal: a connection string, a URL query).
"""

from __future__ import annotations

import re

_ESCAPED_QUOTE = re.compile(r"\\([\"'])")
_PREFIX = re.compile(r"(?<![\w\"'])(?:[fFbBrRuU]{1,2}|@\$?|\$@?)(?=[\"'])")
_ANNOTATION = re.compile(r"\b([A-Za-z_]\w*)[ \t]*:[ \t]*[&\w<>\[\]., ]{1,60}?[ \t]*=(?![=>])")
_GO_VAR = re.compile(r"\b(?:var|const)[ \t]+([A-Za-z_]\w*)[ \t]+[\w.*\[\]]{1,60}[ \t]*=(?!=)")
_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+(?=[\"'])")
_OPENED = re.compile(r"[\"'`](?:(?i:bearer|basic|token|bot)[ \t]{1,16})?\Z")
_QUOTES = "\"'`"


def rewrite(line: str, *, source_code: bool) -> str:
    """The line as detection reads it (see the module docstring)."""
    line = _ESCAPED_QUOTE.sub(r"\1", line)
    if not source_code:
        return line
    line = _PREFIX.sub("", line)
    line = _DEFINE.sub(r"\1 = ", line)
    line = _GO_VAR.sub(r"\1 =", line)
    return _ANNOTATION.sub(r"\1 =", line)


def opened(line: str, column: int) -> bool:
    """True when the value at column is inside a string literal of a source-code line."""
    before = line[:column]
    return _OPENED.search(before[-24:]) is not None or any(before.count(q) % 2 for q in _QUOTES)
