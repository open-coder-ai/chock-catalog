"""Where a GO* module setting is written in a build, script, env, CI or JSON file, and what its value may be.

Each setting is found by its name and separator; its value is then read in one of three ways, by the quote
around it: inside an outer string the setting itself sits in (echo "GOSUMDB=off" >> $GITHUB_ENV), up to the
value's own closing quote (GOFLAGS="-mod=readonly -insecure", "GOSUMDB":"off"), or as one bare shell word.
Where the reading is not certain (an unclosed quote, a character glued on that a shell keeps and a comment
ends, text glued after a closing quote) every candidate is judged, the strictest result stands, and a value
that none of them faults asks: never an allow on a guess.
"""

from __future__ import annotations

import re

from reg_core import REDIRECT, UNREADABLE, Ctx, add
from reg_go import NAMES, go_setting

#: NAME and its separator, with a quote right before NAME (an outer string, or a JSON key's own quote).
SETTING = re.compile(
    rf"""(?<![\w$])(?<!\$\{{)(?P<outer>["']?)(?P<name>{NAMES})(?P<sep>["']\s*:\s*|["']?\s*[:?+]?=\s*|["']?\s*:\s+)"""
)
#: Dockerfile ENV and ARG also take `NAME value`.
ENV_LINE = re.compile(rf"^\s*(?:ENV|ARG)\s+(?P<name>{NAMES})(?P<sep>\s+)", re.IGNORECASE)
MAX_WORD = 4096
#: One bare shell word: quoted pieces and plain characters, bounded.
WORD = re.compile(
    rf"""(?:\$\{{\{{[^}}\n]{{0,{MAX_WORD}}}\}}\}}|"[^"\n]{{0,{MAX_WORD}}}"|'[^'\n]{{0,{MAX_WORD}}}'|[^\s"']){{0,{MAX_WORD + 1}}}"""
)
#: GOFLAGS-style flags after a bare value: a YAML plain scalar runs on, a shell passes them as words.
FLAGS = re.compile(r"(?:[ \t]+--?[\w=.,${}-]+)*")
#: Where a shell keeps going but a comment, a command separator or a flow collection ends the value.
TERMINATOR = re.compile(r"[#;\]}]")
EXPANSION = re.compile(r"\$\{\{[^}\n]*\}\}|\$\{[^}\n]*\}|\$\([^)\n]*\)")
#: The leading part of an unclosed value that is certainly its own: no quote, expansion, escape or terminator.
SIMPLE = re.compile(r"[A-Za-z0-9._/:@,|*?\[\]+=%~-]*")
QUOTES = re.compile("[\"']")
YAML_JSON = re.compile(r"\.(?:ya?ml|json)$", re.IGNORECASE)
MAX_CODEPOINT = 0x10FFFF
ESCAPED = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")
#: Past this many GO* settings in one file the file is refused rather than read.
MAX_SETTINGS = 1000


def go_env(ctx: Ctx) -> None:
    """Every GO* setting on every non-comment line, judged by go_setting under each reading of its value."""
    seen = 0
    for number, raw in enumerate(ctx.lines, 1):
        if raw.lstrip().startswith(("#", "//")):
            continue
        for match in (*ENV_LINE.finditer(raw), *SETTING.finditer(raw)):
            seen += 1
            if seen > MAX_SETTINGS:
                add(ctx, UNREADABLE, number, ("GO*", "too many"), f"more than {MAX_SETTINGS} GO* settings")
                return
            _judge(ctx, number, raw, match)


def _judge(ctx: Ctx, number: int, raw: str, match: re.Match[str]) -> None:
    name = match["name"]
    readings, certain = _value(ctx, raw, match)
    if readings is None:
        add(ctx, UNREADABLE, number, (name, "long word"), f"{name} is followed by a word too long to read")
        return
    before = len(ctx.out)
    for value in dict.fromkeys(readings):
        go_setting(ctx, number, name, value)
    # Two readings that agree report one finding.
    added = {(f["rule"], f["key"]): f for f in ctx.out[before:]}
    ctx.out[before:] = list(added.values())
    if not certain and len(ctx.out) == before:
        add(
            ctx,
            REDIRECT,
            number,
            (name, readings[0][:200]),
            f"{name} is not read with certainty here; a person checks it",
        )


def _value(ctx: Ctx, raw: str, match: re.Match[str]) -> tuple[list[str] | None, bool]:
    """(the candidate values, whether the reading is certain); (None, False) for a word past MAX_WORD."""
    pos = match.end()
    outer = match.groupdict().get("outer") or ""
    if outer and outer in match["sep"]:
        outer = ""  # a JSON key's own closing quote: the key's string has ended
    quote = raw[pos : pos + 1] if raw[pos : pos + 1] in ("'", '"') else ""
    if quote:
        return _quoted(ctx, raw, pos, quote, outer)
    if outer:
        return _in_string(raw, pos, outer)
    word = WORD.match(raw, pos)[0]
    if len(word) > MAX_WORD:
        return None, False
    if word.startswith("#") and raw[pos - 1 : pos].isspace():
        return [""], True  # NAME= # comment: the value is empty
    # Bounded: the flags after a bare value are read within MAX_WORD characters, so a line of many settings
    # stays linear.
    tail = FLAGS.match(raw[pos + len(word) : pos + len(word) + MAX_WORD])[0]
    word = _unbracket(word)
    plain = word if "$" in word else QUOTES.sub("", word)
    # Inside ${...} and ${{ ... }} a '}' or ';' is the expansion's own, not the end of the value.
    cut = TERMINATOR.search(EXPANSION.sub(lambda m: "x" * len(m[0]), word))
    if cut is None:
        return [plain + tail], True
    # A shell keeps `a#,*` as one word; a comment, a command separator or a flow collection ends it there.
    return [plain + tail, QUOTES.sub("", word[: cut.start()]) + tail], False


def _unbracket(word: str) -> str:
    """Drop a ']' or '}' that closes a flow collection the word did not open."""
    while word[-1:] in ("]", "}") and word.count(word[-1]) > word.count("[" if word[-1] == "]" else "{"):
        word = word[:-1]
    return word


def _in_string(raw: str, pos: int, outer: str) -> tuple[list[str] | None, bool]:
    """A setting inside an outer string (echo "NAME=value" >> file, sh -c "NAME=value cmd"): the text up to the
    string's closing quote, its first word (a command may follow it), and what a shell glues on after the
    quote or, after a trailing ',' or '|', passes as the next word. The whole text and its first word cover
    every way a shell reads the string itself, so the reading is uncertain only when the string is not closed
    within MAX_WORD or something is glued on after it."""
    end = raw.find(outer, pos, pos + MAX_WORD)
    if end < 0 and len(raw) > pos + MAX_WORD:
        return None, False
    whole = raw[pos:end] if end >= 0 else raw[pos:]
    # The first word ends at whitespace outside ${...} and ${{ ... }} expansions.
    masked = EXPANSION.sub(lambda m: "x" * len(m[0]), whole)
    space = re.search(r"\s", masked)
    readings = [whole, whole[: space.start()] if space else whole]
    certain = end >= 0
    if end >= 0:
        after = raw[end + 1 : end + 1 + MAX_WORD]
        glued = WORD.match(after)[0]
        nxt = WORD.match(after.lstrip())[0] if whole.endswith((",", "|")) else ""
        for extra in (glued, nxt):
            if extra and extra[0] not in ">|&;)" and not _separator(extra, after):
                readings.append(whole + QUOTES.sub("", extra))
                certain = False
    return readings, certain


def _quoted(ctx: Ctx, raw: str, pos: int, quote: str, outer: str) -> tuple[list[str] | None, bool]:
    """A value that opens with its own quote: up to its closing quote, and what a shell glues on after it."""
    end = raw.find(quote, pos + 1, pos + 1 + MAX_WORD)
    if end < 0 and len(raw) > pos + 1 + MAX_WORD:
        return None, False  # a quoted value longer than MAX_WORD is refused, never judged in part
    if end < 0:
        inner = _unescape(ctx, raw[pos + 1 :], quote)
        return [inner, _simple(inner)], False
    inner = _unescape(ctx, raw[pos + 1 : end], quote)
    after = raw[end + 1 : end + 1 + MAX_WORD]
    glued = WORD.match(after)[0]
    if not glued or glued[:1] == outer or _separator(glued, after) or ctx.path.lower().endswith(".json"):
        return [inner], True
    return [inner, inner + QUOTES.sub("", glued)], False


def _separator(glued: str, after: str) -> bool:
    """A ',' ']' or '}' right after a closing quote that ends a JSON or YAML flow item rather than joining it."""
    return glued[:1] in (",", "]", "}") and after[1:2] in ("", " ", "\t", '"', "}", "]")


def _unescape(ctx: Ctx, text: str, quote: str) -> str:
    """A double-quoted YAML or JSON string's \\xXX, \\uXXXX and \\UXXXXXXXX escapes resolved, as the loader
    resolves them; shell strings are left as written (go_setting asks about an escape it cannot read)."""
    if quote != '"' or not YAML_JSON.search(ctx.path):
        return text
    return ESCAPED.sub(_codepoint, text)


def _codepoint(match: re.Match[str]) -> str:
    """The character an escape names; one past the Unicode range stays as written (the loader refuses it)."""
    point = int(match[1] or match[2] or match[3], 16)
    return chr(point) if point <= MAX_CODEPOINT else match[0]


def _simple(text: str) -> str:
    return SIMPLE.match(text)[0]
