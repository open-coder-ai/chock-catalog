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
_ESLINT_OPEN = re.compile(r"/\*\s*eslint(?:-disable|-enable)?\b")
_ESLINT_RULE = re.compile(_ESLINT_SEC)
_I = re.IGNORECASE

#: (rule id, pattern, flags, opener needed before the match). The first rule a line matches names it.
_TABLE: tuple[tuple[str, str, int, re.Pattern[str] | None], ...] = (
    ("nosec", r"(?:#|//|/\*|--|<!--)\s*#?\s*n[o]sec\b", _I, None),
    # Ruff and flake8-bandit codes are S###; S101 (assert) is test hygiene, not a security finding.
    ("noqa-security", r"#\s*(?:(?:ruff|flake8)\s*:\s*)?n[o]qa\s*:[^#\n]*\bS(?!101\b)\d{3}\b", _I, None),
    ("nolint-gosec", r"//\s*n[o]lint\s*:[^\n]*\bg[o]sec\b", 0, None),
    ("nosonar", r"\bN[O]SONAR\b", 0, _OPENER),
    # Semgrep honours its marker anywhere on the line after whitespace, comment or not.
    ("nosemgrep", r"(?:^|\s)n[o]sem(?:grep)?\b", _I, None),
    ("eslint-disable-security", r"eslint-disabl[e](?:-next-line|-line)?\b[^\n]*?" + _ESLINT_SEC, 0, _OPENER),
    ("eslint-config-off", r"/\*\s*eslint\s[^\n]*?" + _ESLINT_SEC + r"[\w/-]*\s*:\s*[\"']?(?:of[f]|0)\b", 0, None),
    ("checkov-skip", r"\b(?:checkov|bridgecrew)\s*:\s*s[k]ip\b", _I, _OPENER),
    ("checkov-annotation", r"\bcheckov\.io/s[k]ip\d*\s*:", _I, None),
    ("tfsec-trivy-ignore", r"\b(?:tfsec|trivy)\s*:\s*i[g]nore\b", _I, _OPENER),
    ("kics-ignore", r"\bkics-scan\s+(?:i[g]nore|disable)", _I, _OPENER),
    ("hadolint-ignore", r"\bhadolint\s+(?:global\s+)?i[g]nore\b", _I, _OPENER),
    ("cfn-nag-suppress", r"^\s*-?\s*[\"']?rules_to_s[u]ppress[\"']?\s*:", 0, None),
    ("cfn-lint-ignore", r"^\s*-?\s*[\"']?ignore_c[h]ecks[\"']?\s*:", 0, None),
    ("zizmor-ignore", r"\bzizmor\s*:\s*i[g]nore\b", _I, _OPENER),
    # gitleaks and TruffleHog look for their marker anywhere on the line, comment or not.
    ("gitleaks-allow", r"\bgitleaks\s*:\s*a[l]low\b", _I, None),
    ("trufflehog-ignore", r"\btrufflehog\s*:\s*i[g]nore\b", _I, None),
    # detect-secrets' marker, which scan-secrets also honours. chock's own waivers are left to the
    # engine, which ignores one an agent adds unless that line is already committed in HEAD.
    (
        "pragma-allowlist-secret",
        r"\bpragma\s*:\s*(?:a[l]low|w[h]ite)list[ -](?:nextline[ -])?s[e]cret\b",
        _I,
        _OPENER_OR_QUOTE,
    ),
    ("codeql-suppress", r"(?:#|//|/\*)\s*(?:lgtm|codeql)\s*\[", _I, None),
    ("devskim-ignore", r"\bDevSkim\s*:\s*i[g]nore\b", _I, _OPENER),
    ("deepcode-ignore", r"\bdeepcode\s+i[g]nore\b", _I, _OPENER),
    ("bearer-disable", r"\bbearer\s*:\s*d[i]sable\b", _I, _OPENER),
    ("psalm-suppress-taint", r"@psalm-s[u]ppress\s+Tainted", 0, None),
    ("rubocop-disable-security", r"\brubocop\s*:\s*(?:disable|todo)\b[^\n]*\bSecurity/", 0, _OPENER),
    ("rust-allow-unsafe-code", r"#!?\[\s*(?:allow|expect)\s*\([^)\]]*\bunsafe_c[o]de\b", 0, None),
    ("suppress-security-annotation", r"@Suppress(?:FBWarnings|Warnings)?\s*\([^)]*(?:" + _SEC_TOKENS + r")", _I, None),
    (
        "suppress-message-security",
        r"\bSuppressMessage(?:Attribute)?\s*\(\s*\"(?:Microsoft\.)?S[e]curity\"|"
        r"\bSuppressMessage[^\n]*\"CA(?:2100|23\d\d|3\d{3}|5\d{3})\b",
        0,
        None,
    ),
    (
        "pragma-warning-security",
        r"#\s*pragma\s+warning\s+disable\b[^\n]*\b(?:CA(?:2100|23\d\d|3\d{3}|5\d{3})|SCS\d{4})\b",
        0,
        None,
    ),
)
MARKERS = tuple((rule, re.compile(pattern, flags), opener) for rule, pattern, flags, opener in _TABLE)


def lines_of(text: str) -> list[str]:
    """Lines as scanners split them: on newline only, a trailing carriage return dropped. Not
    str.splitlines, which also breaks on form feed, U+0085 and U+2028 and would hide a marker after one."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def marker_rule(line: str) -> str | None:
    """The rule a line's suppression marker breaks, or None when it carries none.

    The opener is looked for only before each match, never by a leading `.*?`, so a long line
    with many `*` or `--` (a minified bundle) stays linear."""
    for rule, pattern, opener in MARKERS:
        for found in pattern.finditer(line):
            if opener is None or opener.search(line, 0, found.start()):
                return rule
    return None


def eslint_block_lines(lines: list[str]) -> list[int]:
    """1-based numbers of the continuation lines of an unclosed `/* eslint... ` comment that name a
    security rule: a disable spread over several lines silences the rule as surely as one line."""
    found, open_block = [], False
    for number, line in enumerate(lines, 1):
        if open_block:
            if _ESLINT_RULE.search(line.split("*/", 1)[0]):
                found.append(number)
            open_block = "*/" not in line
        else:
            opened = _ESLINT_OPEN.search(line)
            open_block = bool(opened) and "*/" not in line[opened.end() :]
    return found
