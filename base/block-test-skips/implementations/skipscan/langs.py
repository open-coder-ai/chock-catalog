"""Line rules per test language: skip, disable, focus and assumption markers outside Python."""

from __future__ import annotations

import re

from skipscan import SKIP
from skipscan.scan import group, line_of

C_COMMENTS = ("//", "*", "/*")
#: v1's one pattern, still applied to a test-path file whose extension no table below names.
LEGACY = re.compile(
    r"@pytest\.mark\.skip\b|@pytest\.mark\.skipif\b|@unittest\.skip|\b(it|describe|test)\.skip\("
    r"|\bx(it|describe)\(|\b(it|describe|test)\.only\(|@Disabled\b|@Ignore\b|\bt\.Skip(Now|f)?\("
)
RULES: dict[str, tuple[re.Pattern[str], tuple[str, ...]]] = {
    "js": (
        re.compile(
            r"\b(?:it|describe|test|context|suite|specify|bench)(?:\.\w+)*\.(?:skip|only|todo|fixme|skipIf|runIf)\b"
            r"|\b(?:it|test)\.fails?\b|(?<![\w$.])[xf](?:it|describe|test|context|specify)\s*\(|\bthis\.skip\s*\("
        ),
        C_COMMENTS,
    ),
    "jvm": (
        re.compile(
            r"@(?:Disabled|Ignore)\w*|@Enabled(?:If|On|For|In)\w*|\b(?:Assume|Assumptions)\.\w+\s*\("
            r"|(?<![\w.])(?:assume(?:True|False|That|NotNull|NoException)|assumingThat)\s*\("
            r"|@Test\s*\([^)]*\benabled\s*=\s*false|\.config\s*\([^)]*\benabled\s*=\s*false|\bSkipException\b"
            r"|(?<![\w$.])x(?:it|describe|test|context|should)\s*\("
        ),
        C_COMMENTS,
    ),
    "go": (re.compile(r"\.Skip(?:Now|f)?\s*\(|\btesting\.Short\s*\(\s*\)"), C_COMMENTS),
    "rust": (re.compile(r"#\[\s*ignore\b|#\[\s*cfg_attr\s*\(.*\bignore\b"), ("//",)),
    "ruby": (
        re.compile(
            r"(?<![\w.:@$])(?:x(?:it|describe|context|specify|example|scenario|feature)"
            r"|f(?:it|describe|context|specify|example)|focus)\b(?!\s*=[^=>~])"
            r"|(?<![\w.:@$])(?:skip|pending)\b(?![?!:]|\s*=[^=>~])"
            r"|(?<![\w:]):(?:skip|pending|focus)\b|\b(?:skip|pending|focus):\s"
        ),
        ("#",),
    ),
    "php": (re.compile(r"\bmarkTest(?:Skipped|Incomplete)\s*\("), (*C_COMMENTS, "#")),
    "csharp": (
        re.compile(
            r"\[\s*(?:Fact|Theory)\s*\([^\]]*\bSkip\s*=|[\[,]\s*(?:Ignore|Explicit)\b"
            r"|\bSkip\.(?:If|IfNot|Unless|When)\s*\(|\bAssert\.(?:Ignore|Inconclusive)\s*\(|\bAssume\.\w+\s*\("
        ),
        C_COMMENTS,
    ),
    "swift": (re.compile(r"\bXCTSkip(?:If|Unless)?\b|\bXCTExpectFailure\s*\(|\.disabled\s*\("), C_COMMENTS),
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


def _each_hits(text: str) -> list[int]:
    hits = []
    for match in EACH.finditer(text):
        end, _ = group(text, match.end()) if text[match.end()] == "(" else _template(text, match.end())
        tail = EACH_TAIL.match(text, end)
        if tail:
            hits.append(line_of(text, tail.end()))
    return hits


def _template(text: str, start: int) -> tuple[int, list[tuple[int, str]]]:
    close = text.find("`", start + 1)
    return (len(text) if close < 0 else close + 1), []


def line_hits(lang: str, text: str) -> list[tuple[int, str, None]]:
    """Each line of a test file that holds one of its language's markers, comment lines aside."""
    pattern, comments = RULES[lang]
    numbers = [
        number
        for number, line in enumerate(text.splitlines(), 1)
        if not line.lstrip().startswith(comments)
        and pattern.search(line if lang == "legacy" else QUOTED.sub('""', line))
    ]
    if lang == "js":
        numbers += _each_hits(text)
    return [(number, SKIP, None) for number in sorted(set(numbers))]
