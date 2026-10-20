"""Backslash escapes as bash reads them in `echo -e`, `printf FORMAT`, `printf %b` and `$'...'` (stdlib only)."""

from __future__ import annotations

from typing import NamedTuple

_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_SIMPLE["\\"] = "\\"
_QUOTES = "\"'?"  # `printf FORMAT` and `$'...'` turn `\"`, `\'` and `\?` into the character; `echo -e` and `%b` keep the backslash
_OCTAL, _HEX = "01234567", "0123456789abcdefABCDEF"
_WIDTH = {"x": 2, "u": 4, "U": 8}
_LAST = 0x10FFFF
_SURROGATES = range(0xD800, 0xE000)


class Decoded(NamedTuple):
    """What the escapes print, whether each one was a form the decoder knows, and whether `\\c` ended the output."""

    text: str
    known: bool
    stop: bool


def _digits(text: str, at: int, allowed: str, most: int) -> tuple[str, int]:
    end = at
    while end < len(text) and end - at < most and text[end] in allowed:
        end += 1
    return text[at:end], end


def decode(text: str, mode: str) -> Decoded:
    """`mode` is `echo` (`echo -e`: octal only as `\\0NNN`), `b` (`%b`, and the loose reading of `echo`: `\\NNN` too), `fmt`
    (a `printf` format) or `ansi` (`$'...'`: like `fmt`, and `\\cX` is a control character).

    A form the decoder does not know (`\\q`, `\\x` with no digit, a code point past Unicode) is kept as written
    and makes the result unknown, so the caller must not take it for the whole script.
    """
    out: list[str] = []
    known, at = True, 0
    while at < len(text):
        char = text[at]
        if char != "\\" or at + 1 >= len(text):
            out.append(char)
            at += 1
            continue
        code, at = text[at + 1], at + 2
        if code in _SIMPLE:
            out.append(_SIMPLE[code])
        elif code == "c" and mode == "ansi" and at < len(text):
            out.append("\x7f" if text[at] == "?" else chr(ord(text[at]) & 0x1F))
            at += 1
        elif code == "c" and mode not in ("fmt", "ansi"):
            return Decoded("".join(out), known, stop=True)
        elif code in _QUOTES and mode in ("fmt", "ansi"):
            out.append(code)
        elif code in _OCTAL and (mode != "echo" or code == "0"):
            # `%b` and `echo` take three digits after a leading 0; a format string and `$'...'` three in all, `%b` two after any other
            zero = code == "0" and mode in ("b", "echo")
            more, at = _digits(text, at, _OCTAL, 3 if zero else 2)
            out.append(chr((int(more or "0", 8) if zero else int(code + more, 8)) & 255))
        elif code in _WIDTH:
            found, at = _digits(text, at, _HEX, _WIDTH[code])
            value = int(found, 16) if found else _LAST + 1
            valid = bool(found) and value <= _LAST and value not in _SURROGATES
            known &= valid
            out.append(chr(value) if valid else f"\\{code}{found}")
        else:
            out.append(
                code if mode == "ansi" else f"\\{code}"
            )  # `$'\\q'` is `\\q` in bash; the guard drops the backslash
            known &= code == "c" or (mode == "echo" and code in _OCTAL)
    return Decoded("".join(out).replace("\0", ""), known, stop=False)
