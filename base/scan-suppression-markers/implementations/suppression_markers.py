"""Inline suppression markers: the comment or annotation a scanner reads as "do not report this line"."""

from __future__ import annotations

import re

# Every literal below is split by a character class ([o], [s], ...) or by `\s*`, so this file never
# holds the marker it looks for: the policy's own folder must not trip its own gate.

#: A comment opener before the marker: a marker quoted in prose or a string is not one. A `*` counts
#: only as the first character of a line (a block-comment continuation), never as multiplication.
_OPENER = re.compile(r"#|//|/\*|--|<!--|^\s*\*")
_OPENER_OR_QUOTE = re.compile(r"#|//|/\*|--|<!--|^\s*\*|'")
_SEC_TOKENS = (
    r"injection|xss|traversal|xxe|ssrf|deserializ|predictable_random|hard_?cod|weak_|trust_?all|"
    r"unencrypted|insecure|cipher|crypto|password|security"
)
_ESLINT_SEC = (
    r"(?:\bsecurity(?:-node)?/|\bno-unsanitized/|\bno-secrets/|\bxss/|@microsoft/sdl/|\bno-eval\b|"
    r"\bno-implied-eval\b|\bno-new-func\b|\breact/no-danger)"
)
_BLOCK_OPEN = re.compile(r"/\*")
#: An ESLint directive that turns rules off: a disable, or inline config (not eslint-enable). ESLint
#: accepts the bare word at the end of the comment's first line, its rules on the lines below.
_ESLINT_DIRECTIVE = re.compile(r"\s*eslint(?:-disable\b|\s|$)")
_ESLINT_RULE = re.compile(_ESLINT_SEC)
_I = re.IGNORECASE
#: How far past its anchor a rule looks for the rule id or code that makes it a security one.
WINDOW = 300

#: (rule id, prefilter word, anchor, tail, flags, opener needed before the anchor). A rule with a
#: tail matches when the tail is found within WINDOW characters after an anchor, and before the next
#: anchor, so the windows never overlap and a line is judged in linear time. The first rule a line
#: matches names its finding.
_TABLE: tuple[tuple[str, str, str, str | None, int, re.Pattern[str] | None], ...] = (
    ("nosec", "nosec", r"(?:#|//|/\*|--|<!--)[^\S\n]{0,40}(?:#[^\S\n]{0,40})?n[o]sec\b", None, _I, None),
    # Ruff and flake8-bandit codes are S###; S101 (assert) is test hygiene, not a security finding.
    (
        "noqa-security",
        "noqa",
        r"#[^\S\n]{0,40}(?:(?:ruff|flake8)\s*:\s*)?n[o]qa\s*:",
        r"^[^#]*?\bS(?!101\b)\d{3}\b",
        _I,
        None,
    ),
    ("nolint-gosec", "nolint", r"//[^\S\n]{0,40}n[o]lint\s*:", r"\bg[o]sec\b", 0, None),
    ("nosonar", "nosonar", r"\bN[O]SONAR\b", None, 0, _OPENER),
    # Semgrep honours its marker anywhere on the line after whitespace, comment or not.
    ("nosemgrep", "nosem", r"(?:^|\s)n[o]sem(?:grep)?\b", None, _I, None),
    ("eslint-disable-security", "eslint", r"eslint-disabl[e](?:-next-line|-line)?\b", _ESLINT_SEC, 0, _OPENER),
    (
        "eslint-config-off",
        "eslint",
        r"/\*\s*e[s]lint\s",
        _ESLINT_SEC + r"[\w/-]*[\"']?\s*:\s*\[?\s*[\"']?(?:of[f]|0)\b",
        0,
        None,
    ),
    ("checkov-skip", "checkov", r"\b(?:checkov|bridgecrew)\s*:\s*s[k]ip\b", None, _I, _OPENER),
    ("checkov-annotation", "checkov", r"\bcheckov\.io/s[k]ip\d*\s*:", None, _I, None),
    ("tfsec-trivy-ignore", "tfsec", r"\b(?:tfsec|trivy)\s*:\s*i[g]nore\b", None, _I, _OPENER),
    ("kics-ignore", "kics", r"\bkics-scan\s+(?:i[g]nore|disable)", None, _I, _OPENER),
    ("hadolint-ignore", "hadolint", r"\bhadolint\s+(?:global\s+)?i[g]nore\b", None, _I, _OPENER),
    ("cfn-nag-suppress", "suppress", r"^\s*(?:-\s*)?[\"']?rules_to_s[u]ppress[\"']?\s*:", None, 0, None),
    ("cfn-lint-ignore", "ignore_checks", r"^\s*(?:-\s*)?[\"']?ignore_c[h]ecks[\"']?\s*:", None, 0, None),
    ("zizmor-ignore", "zizmor", r"\bzizmor\s*:\s*i[g]nore\b", None, _I, _OPENER),
    # gitleaks and TruffleHog look for their marker anywhere on the line, comment or not.
    ("gitleaks-allow", "gitleaks", r"\bgitleaks\s*:\s*a[l]low\b", None, _I, None),
    ("trufflehog-ignore", "trufflehog", r"\btrufflehog\s*:\s*i[g]nore\b", None, _I, None),
    # detect-secrets' marker, which scan-secrets also honours. chock's own waivers are left to the
    # engine, which ignores one an agent adds unless that line is already committed in HEAD.
    (
        "pragma-allowlist-secret",
        "pragma",
        r"\bpragma\s*:\s*(?:a[l]low|w[h]ite)list[ -](?:nextline[ -])?s[e]cret\b",
        None,
        _I,
        _OPENER_OR_QUOTE,
    ),
    ("codeql-suppress", "codeql", r"(?:#|//|/\*)\s*(?:lgtm|codeql)\s*\[", None, _I, None),
    ("devskim-ignore", "devskim", r"\bDevSkim\s*:\s*i[g]nore\b", None, _I, _OPENER),
    ("deepcode-ignore", "deepcode", r"\bdeepcode\s+i[g]nore\b", None, _I, _OPENER),
    ("bearer-disable", "bearer", r"\bbearer\s*:\s*d[i]sable\b", None, _I, _OPENER),
    ("psalm-suppress-taint", "suppress", r"@psalm-s[u]ppress\s+Tainted", None, 0, None),
    ("rubocop-disable-security", "rubocop", r"\brubocop\s*:\s*(?:disable|todo)\b", r"\bSecurity/", 0, _OPENER),
    ("rust-allow-unsafe-code", "unsafe", r"#!?\[\s*(?:allow|expect)\s*\(", r"^[^)\]]*?\bunsafe_c[o]de\b", 0, None),
    (
        "suppress-security-annotation",
        "suppress",
        r"@Suppress(?:FBWarnings|Warnings)?\s*\(",
        r"^[^)]*?(?:" + _SEC_TOKENS + r")",
        _I,
        None,
    ),
    (
        "suppress-message-security",
        "suppress",
        r"\bSuppressMessage(?:Attribute)?\s*\(\s*\"(?:Microsoft\.)?S[e]curity\"",
        None,
        0,
        None,
    ),
    ("suppress-message-security", "suppress", r"\bSuppressMessage", r"\"CA(?:2100|23\d\d|3\d{3}|5\d{3})\b", 0, None),
    (
        "pragma-warning-security",
        "pragma",
        r"#\s*pragma\s+warning\s+disable\b",
        r"\b(?:CA(?:2100|23\d\d|3\d{3}|5\d{3})|SCS\d{4})\b",
        0,
        None,
    ),
)
_COMPILED = tuple(
    (rule, word, re.compile(anchor, flags), re.compile(tail, flags) if tail else None, opener)
    for rule, word, anchor, tail, flags, opener in _TABLE
)
#: The lowercase words the rules contain (written split, so this file holds none whole), each mapped
#: to the rules' word key. One case-sensitive literal search over the lowercased line says which
#: rules can match it: far faster than a case-insensitive search, and a line with none is skipped.
_WORDS = {
    "no" + "sec": "nosec",
    "no" + "qa": "noqa",
    "no" + "lint": "nolint",
    "no" + "sonar": "nosonar",
    "no" + "sem": "nosem",
    "es" + "lint": "eslint",
    "che" + "ckov": "checkov",
    "bridge" + "crew": "checkov",
    "tf" + "sec": "tfsec",
    "tri" + "vy": "tfsec",
    "ki" + "cs": "kics",
    "hado" + "lint": "hadolint",
    "ignore_" + "checks": "ignore_checks",
    "ziz" + "mor": "zizmor",
    "git" + "leaks": "gitleaks",
    "truffle" + "hog": "trufflehog",
    "pra" + "gma": "pragma",
    "lg" + "tm": "codeql",
    "code" + "ql": "codeql",
    "dev" + "skim": "devskim",
    "deep" + "code": "deepcode",
    "bea" + "rer": "bearer",
    "rubo" + "cop": "rubocop",
    "unsafe_" + "code": "unsafe",
    "sup" + "press": "suppress",
}
PREFILTER = re.compile("|".join(map(re.escape, sorted(_WORDS, key=len, reverse=True))))


def has_marker_word(text: str) -> bool:
    """Whether any rule could match somewhere in `text`."""
    return bool(PREFILTER.search(text.lower()))


#: The markers a secret scanner honours in any file it reads, prose included.
SECRET_RULES = frozenset({"gitleaks-allow", "trufflehog-ignore", "pragma-allowlist-secret"})


def lines_of(text: str) -> list[str]:
    """Lines as scanners split them: on newline only, a trailing carriage return dropped. Not
    str.splitlines, which also breaks on form feed, U+0085 and U+2028 and would hide a marker after one."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def _hit(line: str, anchor: re.Pattern[str], tail: re.Pattern[str] | None, opener_at: int) -> bool:
    """Whether an anchor (after the opener, when one is needed) carries its tail in its window."""
    anchors = [found for found in anchor.finditer(line) if found.start() > opener_at]
    if tail is None or not anchors:
        return bool(anchors)
    for here, after in zip(anchors, [*anchors[1:], None], strict=True):
        stop = min(here.end() + WINDOW, after.start() if after else len(line))
        if tail.search(line[here.end() : stop]):
            return True
    return False


def marker_rule(line: str) -> str | None:
    """The rule a line's suppression marker breaks, or None when it carries none."""
    words = {_WORDS[found.group()] for found in PREFILTER.finditer(line.lower())}
    if not words:
        return None
    first: dict[re.Pattern[str], int] = {}
    for rule, word, anchor, tail, opener in _COMPILED:
        if word not in words:
            continue
        if opener is not None and opener not in first:
            first[opener] = hit.start() if (hit := opener.search(line)) else len(line)
        if _hit(line, anchor, tail, first[opener] if opener else -1):
            return rule
    return None


def eslint_block_lines(lines: list[str]) -> list[int]:
    """1-based numbers of the continuation lines of an unclosed `/* eslint... ` (or `/*` then an
    `eslint` directive on the next line) disable or config comment that name a security rule."""
    found: list[int] = []
    state = ""  # "", "maybe" (a bare /* opened), "eslint" (inside a disable or config block)
    for number, line in enumerate(lines, 1):
        body = line.split("*/", 1)[0]
        if state == "maybe" and _ESLINT_DIRECTIVE.match(body):
            state = "eslint"
        if state == "eslint" and _ESLINT_RULE.search(body):
            found.append(number)
        if state and "*/" in line:
            state = ""
        elif not state and (opened := _BLOCK_OPEN.search(line, line.rfind("*/") + 2 if "*/" in line else 0)):
            directive = _ESLINT_DIRECTIVE.match(line[opened.end() :])
            state = "eslint" if directive else ("maybe" if not line[opened.end() :].strip() else "")
        elif state == "maybe" and body.strip():
            state = ""
    return found
