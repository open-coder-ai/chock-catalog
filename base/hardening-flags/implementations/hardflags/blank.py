"""Split a build file into its code and its comments, offset for offset, so a flag in a comment is not a finding."""

from __future__ import annotations

import re

SHELL_KINDS = frozenset({"shell", "docker", "yaml", "autoconf"})
#: Quote characters per kind, each with whether a backslash escapes inside it.
QUOTES = {
    "cmake": {'"': True},
    "meson": {"'": True},
    "toml": {'"': True, "'": False},
    "shell": {'"': True, "'": False},
}
TRIPLE = frozenset({"meson", "toml"})
BRACKET = re.compile(r"\[(=*)\[")
CHAR = re.compile(r"'(?:\\.[^']{0,8}|[^\\'])'")
RAW = re.compile(r'(?<![\w"])(?:b|c)?r(#*)"')
DNL = re.compile(r"(?<![\w])dnl(?![\w])")
WORD_START = " \t\r\n;&|("


def split(kind: str, text: str) -> tuple[str, str]:
    """(code, comments): both as long as `text`, newlines kept, each blank where the other has text.

    A kernel config writes settings as comments (`# CONFIG_X is not set`), so its code stays whole.
    """
    if kind == "kernel":
        spans = _to_eol(text, lambda line: line.find("#"))
    elif kind == "rust":
        spans = _rust_spans(text)
    elif kind == "make":
        spans = _make_spans(text)
    else:
        spans = _hash_spans(text, kind)
        if kind == "autoconf":
            spans += _to_eol(text, lambda line: m.start() if (m := DNL.search(line)) else -1)
    code, note = list(text), [ch if ch == "\n" else " " for ch in text]
    for start, end in spans:
        for i in range(start, end):
            if text[i] != "\n":
                code[i], note[i] = " ", text[i]
    return (text if kind == "kernel" else "".join(code)), "".join(note)


def _to_eol(text: str, cut) -> list[tuple[int, int]]:
    """From the offset `cut(line)` names (or nowhere, when negative) to the end of each line."""
    out, pos = [], 0
    for line in text.split("\n"):
        at = cut(line)
        if at is not None and at >= 0:
            out.append((pos + at, pos + len(line)))
        pos += len(line) + 1
    return out


def _skip_string(text: str, i: int, quote: str, *, escapes: bool, triple: bool) -> int:
    """The index after the string that opens at `i`."""
    if triple and text.startswith(quote * 3, i):
        end = text.find(quote * 3, i + 3)
        return len(text) if end < 0 else end + 3
    i += 1
    while i < len(text) and text[i] != quote:
        i += 2 if escapes and text[i] == "\\" else 1
    return min(i + 1, len(text))


def _after(text: str, marker: str, start: int) -> int:
    end = text.find(marker, start)
    return len(text) if end < 0 else end + len(marker)


def _eol(text: str, start: int) -> int:
    end = text.find("\n", start)
    return len(text) if end < 0 else end


def _hash_spans(text: str, kind: str) -> list[tuple[int, int]]:
    """`#` comments of cmake, meson, toml and shell-like files, each with its own quoting rules."""
    shell = kind in SHELL_KINDS
    quotes = QUOTES["shell" if shell else kind]
    spans, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch in quotes:
            i = _skip_string(text, i, ch, escapes=quotes[ch], triple=kind in TRIPLE)
        elif ch == "\\" and (shell or kind == "cmake"):
            i += 2
        elif ch == "[" and kind == "cmake" and (m := BRACKET.match(text, i)):
            i = _after(text, "]" + m.group(1) + "]", m.end())
        elif ch == "#" and (not shell or i == 0 or text[i - 1] in WORD_START):
            m = BRACKET.match(text, i + 1) if kind == "cmake" else None
            end = _after(text, "]" + m.group(1) + "]", m.end()) if m else _eol(text, i)
            spans.append((i, max(end, i)))
            i = max(end, i + 1)
        else:
            i += 1
    return spans


def odd_backslashes(line: str) -> bool:
    """True when the line ends in a backslash that is not itself escaped: it continues onto the next line."""
    body = line.rstrip("\r")
    return (len(body) - len(body.rstrip("\\"))) % 2 == 1


def _make_spans(text: str) -> list[tuple[int, int]]:
    """Make joins lines first, so a comment ending in a backslash runs on; recipe lines go to the shell."""
    spans, pos, in_comment, recipe, carry = [], 0, False, False, False
    for line in text.split("\n"):
        if not carry:
            recipe = line.startswith("\t")
        cut = 0 if in_comment else _make_cut(line, recipe=recipe)
        if cut is not None:
            spans.append((pos + cut, pos + len(line)))
            in_comment = True
        carry = odd_backslashes(line)
        in_comment = in_comment and carry
        pos += len(line) + 1
    return spans


def _make_cut(line: str, *, recipe: bool) -> int | None:
    """Where a comment starts in a Make line: an unescaped `#`, or in a recipe the shell's own."""
    if recipe:
        found = _hash_spans(line, "shell")
        return found[0][0] if found else None
    for m in re.finditer("#", line):
        if not odd_backslashes(line[: m.start()]):
            return m.start()
    return None


def _rust_spans(text: str) -> list[tuple[int, int]]:
    """`//` and nested `/* */` comments; strings, raw strings and character literals are left alone."""
    spans, i = [], 0
    while i < len(text):
        two = text[i : i + 2]
        if text[i] == '"':
            i = _skip_string(text, i, '"', escapes=True, triple=False)
        elif raw := RAW.match(text, i):
            i = _after(text, '"' + raw.group(1), raw.end())
        elif char := CHAR.match(text, i):
            i = char.end()
        elif two == "//":
            end = _eol(text, i)
            spans.append((i, end))
            i = end
        elif two == "/*":
            end, depth = i + 2, 1
            while end < len(text) and depth:
                pair = text[end : end + 2]
                depth += {"/*": 1, "*/": -1}.get(pair, 0)
                end += 2 if pair in ("/*", "*/") else 1
            spans.append((i, end))
            i = end
        else:
            i += 1
    return spans
