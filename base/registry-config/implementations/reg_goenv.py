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
        end = raw.find(outer, pos)
        return ([raw[pos:end]], True) if end >= 0 else ([raw[pos:], _simple(raw[pos:])], False)
    word = WORD.match(raw, pos)[0]
    if len(word) > MAX_WORD:
        return None, False
    if word.startswith("#") and raw[pos - 1 : pos].isspace():
        return [""], True  # NAME= # comment: the value is empty
    tail = FLAGS.match(raw, pos + len(word))[0]
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


def _quoted(ctx: Ctx, raw: str, pos: int, quote: str, outer: str) -> tuple[list[str], bool]:
    """A value that opens with its own quote: up to its closing quote, and what a shell glues on after it."""
    end = raw.find(quote, pos + 1)
    if end < 0:
        inner = raw[pos + 1 :]
        return [inner, _simple(inner)], False
    inner = raw[pos + 1 : end]
    after = raw[end + 1 :]
    glued = WORD.match(after)[0][:MAX_WORD]
    separator = glued[:1] in (",", "]", "}") and after[1:2] in ("", " ", "\t", '"', "}", "]")
    if not glued or glued[:1] == outer or separator or ctx.path.lower().endswith(".json"):
        return [inner], True
    return [inner, inner + QUOTES.sub("", glued)], False


def _simple(text: str) -> str:
    return SIMPLE.match(text)[0]
