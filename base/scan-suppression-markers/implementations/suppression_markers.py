"""Inline suppression markers: the comment or annotation a scanner reads as "do not report this line"."""

from __future__ import annotations

import re

# Every literal below is split by a character class ([o], [s], ...) or by `\s*`, so this file never
# holds the marker it looks for: the policy's own folder must not trip its own gate.
_C = r"(?:#|//|/\*|--|<!--|\*|;)"
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
        ("nosonar", r"\bN[O]SONAR\b", 0),
        ("nosemgrep", _C + r"\s*n[o]sem(?:grep)?\b", re.IGNORECASE),
        (
            "eslint-disable-security",
            r"eslint-disabl[e](?:-next-line|-line)?\b[^\n]*?(?:\bsecurity(?:-node)?/|\bno-unsanitized/|"
            r"\bno-secrets/|\bxss/|@microsoft/sdl/|\bno-eval\b|\bno-implied-eval\b|\bno-new-func\b|"
            r"\breact/no-danger)",
            0,
        ),
        ("checkov-skip", r"\b(?:checkov|bridgecrew)\s*:\s*s[k]ip\b", re.IGNORECASE),
        ("tfsec-trivy-ignore", r"\b(?:tfsec|trivy)\s*:\s*i[g]nore\b", re.IGNORECASE),
        ("kics-ignore", r"\bkics-scan\s+(?:i[g]nore|disable)", re.IGNORECASE),
        ("hadolint-ignore", r"\bhadolint\s+i[g]nore\b", re.IGNORECASE),
        ("cfn-nag-suppress", r"\brules_to_s[u]ppress\b", 0),
        ("cfn-lint-ignore", r"\bignore_c[h]ecks\b", 0),
        ("zizmor-ignore", r"\bzizmor\s*:\s*i[g]nore\b", re.IGNORECASE),
        ("gitleaks-allow", r"\bgitleaks\s*:\s*a[l]low\b", re.IGNORECASE),
        ("trufflehog-ignore", r"\btrufflehog\s*:\s*i[g]nore\b", re.IGNORECASE),
        ("pragma-allowlist", r"\bpragma\s*:\s*a[l]lowlist\b", re.IGNORECASE),
        ("chock-waiver", r"\bchock\s*:\s*a[l]low\b", re.IGNORECASE),
        ("codeql-suppress", _C + r"\s*(?:lgtm|codeql)\s*\[", re.IGNORECASE),
        ("devskim-ignore", r"\bDevSkim\s*:\s*i[g]nore\b", re.IGNORECASE),
        ("deepcode-ignore", r"\bdeepcode\s+i[g]nore\b", re.IGNORECASE),
        ("bearer-disable", r"\bbearer\s*:\s*d[i]sable\b", re.IGNORECASE),
        ("psalm-suppress-taint", r"@psalm-s[u]ppress\s+Tainted", 0),
        ("rubocop-disable-security", r"\brubocop\s*:\s*(?:disable|todo)\b[^\n]*\bSecurity/", 0),
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
