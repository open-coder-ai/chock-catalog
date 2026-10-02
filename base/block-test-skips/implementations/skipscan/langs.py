"""Line rules per test language: skip, disable, focus and assumption markers outside Python."""

from __future__ import annotations

import re
from collections.abc import Callable

from skipscan import SKIP
from skipscan.scan import blank_code, group, line_index, split_lines

C_COMMENTS = ("//", "*", "/*")
#: v1's one pattern, still applied to a test-path file whose extension no table below names.
LEGACY = re.compile(
    r"@pytest\.mark\.skip\b|@pytest\.mark\.skipif\b|@unittest\.skip|\b(it|describe|test)\.skip\("
    r"|\bx(it|describe)\(|\b(it|describe|test)\.only\(|@Disabled\b|@Ignore\b|\bt\.Skip(Now|f)?\("
)
RULES: dict[str, tuple[re.Pattern[str], tuple[str, ...]]] = {
    "js": (
        re.compile(
            r"\b(?:it|describe|test|context|suite|specify|bench)(?:\s*\??\.\s*\w+)*\s*\??\.\s*"
            r"(?:skip|only|todo|fixme|skipIf|runIf)\b(?=\s*[(.`])"
            r"|\b(?:it|test)\s*\??\.\s*fails?\b(?=\s*[(.`])"
            r"|(?<![\w$.])[xf](?:it|describe|test|context|specify)(?:\s*\.\s*each)?\s*[(`]|\bthis\.skip\s*\("
        ),
        C_COMMENTS,
    ),
    "jvm": (
        re.compile(
            r"@(?:[\w.]+\.)?(?:Disabled\w*|Ignore(?:If)?\b|Enabled(?:If|On|For|In)\w*)"
            r"|\b(?:Assume|Assumptions)\.\w+\s*\("
            r"|(?<![\w.])(?:assume(?:True|False|That|NotNull|NoException)|assumingThat)\s*\("
            r"|@Test\s*\([^)]*\benabled\s*=\s*false|\.config\s*\([^)]*\benabled\s*=\s*false"
            r"|\b(?:SkipException|AssumptionViolatedException|TestAbortedException)\b"
            r"|(?<![\w$.])x(?:it|describe|test|context|should)\s*\("
        ),
        C_COMMENTS,
    ),
    # A testing receiver (t, b, tb, tt, tc, f, or a suite's T()); `testing.Short()` is judged by its block below.
    "go": (re.compile(r"(?:\b(?:t|b|tb|tt|tc|f)|\bT\(\))\s*\.\s*Skip(?:Now|f)?\s*\("), C_COMMENTS),
    "rust": (re.compile(r"#\s*\[\s*ignore\b|#\s*\[\s*cfg_attr\s*\(.*\bignore\b"), C_COMMENTS),
    # Statement-initial calls and example metadata only: `:pending` and `skip:` elsewhere are ordinary Ruby.
    "ruby": (
        re.compile(
            r"^\s*(?:(?:::)?RSpec\s*\.\s*)?(?:x(?:it|describe|context|specify|example|scenario|feature)"
            r"|f(?:it|describe|context|specify|example|scenario|feature)|focus)\b(?!\s*(?:(?:\|\||&&|[-+*/|&])?=[^=>~]|[.?!:]))"
            r"|^\s*(?:skip|pending)\b(?!\s*(?:(?:\|\||&&|[-+*/|&])?=[^=>~]|<<(?![~-]?['\"\w])|[.?!:)\]]))"
            r"|^\s*(?:(?:::)?RSpec\s*\.\s*)?(?:it|specify|example|scenario|describe|context|feature)\b.*"
            r"(?:,\s*:(?:skip|pending|focus)\b|\b(?:skip|pending|focus):(?!\s*(?:false|nil)\b))"
        ),
        ("#",),
    ),
    "php": (re.compile(r"\bmarkTest(?:Skipped|Incomplete)\s*\("), (*C_COMMENTS, "#")),
    "csharp": (
        re.compile(
            r"\[\s*(?:[\w.]+\.)?(?:Fact|Theory)(?:Attribute)?\s*\([^\]]*\bSkip\s*="
            r"|[\[,]\s*(?:[\w.]+\.)?(?:Ignore|Explicit)(?:Attribute)?\b"
            r"|\bSkip\.(?:If|IfNot|Unless|When)\s*\(|\bAssert\.(?:Ignore|Inconclusive)\s*\(|\bAssume\.\w+\s*\("
        ),
        C_COMMENTS,
    ),
    "swift": (
        re.compile(
            r"\bXCTSkip(?:If|Unless)?\b|\bXCTExpectFailure\s*\(|@(?:Test|Suite)\b.*\.(?:disabled\s*\(|enabled\s*\(\s*if:)"
        ),
        C_COMMENTS,
    ),
    "legacy": (LEGACY, ("#", *C_COMMENTS)),
}
EXTENSIONS = {
    **dict.fromkeys((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"), "js"),
    **dict.fromkeys((".java", ".kt", ".kts", ".groovy", ".scala"), "jvm"),
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
}
#: String literals, blanked before a line is matched, so a test's title that says "skip" is not a skip.
QUOTED = re.compile(r'"(?:\\.|[^"\\])*"' r"|'(?:\\.|[^'\\])*'" r"|`(?:\\.|[^`\\])*`")
#: A table-driven test, `it.each(...)` or a template table, whose group is followed by `.skip`/`.only`.
EACH = re.compile(r"\b(?:it|describe|test)(?:\.\w+)*\.each\s*(?=[(`])")
EACH_TAIL = re.compile(r"\s*\.(?:skip|only)\b")


#: A Go `if` whose condition calls `testing.Short()`: a skip only when its block returns or skips.
SHORT = re.compile(r"\bif\b[^{\n]*\btesting\.Short\s*\(\s*\)[^{\n]*\{")
#: A bare `return` (a helper's `return 10` scales, it does not skip) or a skip call.
SHORT_EXIT = re.compile(r"\breturn\s*(?:[;}\r\n]|$)|\.\s*Skip")


def _each_hits(text: str, line_of: Callable[[int], int]) -> list[int]:
    """`.each(...).skip` in code; `text` is blanked, so a comment or string cannot open a table."""
    hits = []
    for match in EACH.finditer(text):
        end, _ = group(text, match.end()) if text[match.end()] == "(" else _template(text, match.end())
        if end >= len(text):
            # An unclosed table runs to the end, and so would every one after it.
            break
        tail = EACH_TAIL.match(text, end)
        if tail:
            hits.append(line_of(tail.end()))
    return hits


def _short_hits(text: str, line_of: Callable[[int], int]) -> list[int]:
    hits = []
    for match in SHORT.finditer(text):
        end, _ = group(text, match.end() - 1)
        if SHORT_EXIT.search(text, match.end(), end):
            hits.append(line_of(match.start()))
    return hits


def _template(text: str, start: int) -> tuple[int, list[tuple[int, str]]]:
    close = text.find("`", start + 1)
    return (len(text) if close < 0 else close + 1), []


def _is_comment(line: str, comments: tuple[str, ...]) -> bool:
    """A line that is only comment; `/* x */ code` is code."""
    stripped = line.lstrip()
    if stripped.startswith("/*") and "*/" in stripped:
        return not stripped.split("*/", 1)[1].strip()
    return stripped.startswith(comments)


def line_hits(lang: str, text: str) -> list[tuple[int, str, None]]:
    """Each line of a test file that holds one of its language's markers, comment lines aside."""
    pattern, comments = RULES[lang]
    lines = split_lines(text)
    numbers = [
        number
        for number, line in enumerate(lines, 1)
        if not _is_comment(line, comments) and pattern.search(line if lang == "legacy" else QUOTED.sub('""', line))
    ]
    extra = {"js": _each_hits, "go": _short_hits}.get(lang)
    if extra:
        numbers += extra(blank_code(text), line_index(text))
    return [(number, SKIP, None) for number in sorted(set(numbers))]
