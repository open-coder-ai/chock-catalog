"""Inline suppression markers: the comment or annotation a scanner reads as "do not report this line"."""

from __future__ import annotations

import re

# Every literal below is split by a character class ([o], [s], ...) or by `\s*`, so this file never
# holds the marker it looks for: the policy's own folder must not trip its own gate.
_C = r"(?:#|//|/\*|--|<!--|\*)"
#: A comment opener somewhere before the marker: a marker quoted in prose or a string is not one.
_IN = _C + r"[^\n]*?"
_SEC_TOKENS = (
    r"injection|xss|traversal|xxe|ssrf|deserializ|predictable_random|hard_?cod|weak_|trust_?all|"
    r"unencrypted|insecure|cipher|crypto|password|security|unsafe"
)

#: (rule id, pattern). The first rule a line matches names its finding.
MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (rule, re.compile(pattern, flags))
    for rule, pattern, flags in (
        ("nosec", _C + r"\s*#?\s*n[o]sec\b", re.IGNORECASE),
        # Ruff and flake8-bandit codes are S###; S101 (assert) is test hygiene, not a security finding.
        ("noqa-security", r"#\s*n[o]qa\s*:[^#\n]*\bS(?!101\b)\d{3}\b", re.IGNORECASE),
        ("nolint-gosec", r"//\s*n[o]lint\s*:[^\n]*\bg[o]sec\b", 0),
        ("nosonar", _IN + r"\bN[O]SONAR\b", 0),
        ("nosemgrep", _C + r"\s*n[o]sem(?:grep)?\b", re.IGNORECASE),
        (
            "eslint-disable-security",
            _IN + r"eslint-disabl[e](?:-next-line|-line)?\b[^\n]*?(?:\bsecurity(?:-node)?/|\bno-unsanitized/|"
            r"\bno-secrets/|\bxss/|@microsoft/sdl/|\bno-eval\b|\bno-implied-eval\b|\bno-new-func\b|"
            r"\breact/no-danger)",
            0,
        ),
        ("checkov-skip", _IN + r"\b(?:checkov|bridgecrew)\s*:\s*s[k]ip\b", re.IGNORECASE),
        ("tfsec-trivy-ignore", _IN + r"\b(?:tfsec|trivy)\s*:\s*i[g]nore\b", re.IGNORECASE),
        ("kics-ignore", _IN + r"\bkics-scan\s+(?:i[g]nore|disable)", re.IGNORECASE),
        ("hadolint-ignore", _IN + r"\bhadolint\s+i[g]nore\b", re.IGNORECASE),
        ("cfn-nag-suppress", r"\brules_to_s[u]ppress\b", 0),
        ("cfn-lint-ignore", r"\bignore_c[h]ecks\b", 0),
        ("zizmor-ignore", _IN + r"\bzizmor\s*:\s*i[g]nore\b", re.IGNORECASE),
        ("gitleaks-allow", _IN + r"\bgitleaks\s*:\s*a[l]low\b", re.IGNORECASE),
        ("trufflehog-ignore", _IN + r"\btrufflehog\s*:\s*i[g]nore\b", re.IGNORECASE),
        # detect-secrets' marker, which scan-secrets also honours. chock's own waivers are left to the
        # engine, which already ignores one an agent adds unless that line is committed in HEAD.
        ("pragma-allowlist-secret", _IN + r"\bpragma\s*:\s*a[l]lowlist\s+(?:nextline\s+)?s[e]cret\b", re.IGNORECASE),
        ("codeql-suppress", _C + r"\s*(?:lgtm|codeql)\s*\[", re.IGNORECASE),
        ("devskim-ignore", _IN + r"\bDevSkim\s*:\s*i[g]nore\b", re.IGNORECASE),
        ("deepcode-ignore", _IN + r"\bdeepcode\s+i[g]nore\b", re.IGNORECASE),
        ("bearer-disable", _IN + r"\bbearer\s*:\s*d[i]sable\b", re.IGNORECASE),
        ("psalm-suppress-taint", r"@psalm-s[u]ppress\s+Tainted", 0),
        ("rubocop-disable-security", _IN + r"\brubocop\s*:\s*(?:disable|todo)\b[^\n]*\bSecurity/", 0),
        ("rust-allow-unsafe-code", r"#!?\[\s*(?:allow|expect)\s*\([^)\]]*\bunsafe_c[o]de\b", 0),
        (
            "suppress-security-annotation",
            r"@Suppress(?:FBWarnings|Warnings)?\s*\([^)]*(?:" + _SEC_TOKENS + r")",
            re.IGNORECASE,
        ),
        (
            "suppress-message-security",
            r"\bSuppressMessage(?:Attribute)?\s*\(\s*\"(?:Microsoft\.)?S[e]curity\"|\bSuppressMessage[^\n]*\"CA(?:2100|23\d\d|3\d{3}|5\d{3})\b",
            0,
        ),
        (
            "pragma-warning-security",
            r"#\s*pragma\s+warning\s+disable\b[^\n]*\b(?:CA(?:2100|23\d\d|3\d{3}|5\d{3})|SCS\d{4})\b",
            0,
        ),
    )
)


def marker_rule(line: str) -> str | None:
    """The rule a line's suppression marker breaks, or None when it carries none."""
    return next((rule for rule, pattern in MARKERS if pattern.search(line)), None)
