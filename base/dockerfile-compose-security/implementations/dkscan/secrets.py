"""Secret-named variables holding a literal, shared by Dockerfile ENV/ARG and compose environment rules.

A line scan-secrets (0.0.9, mandatory, every file) already refuses is left to it: no double report.
"""

from __future__ import annotations

import re
from itertools import pairwise

#: Word parts of a variable name (split on _ - . and camelCase) that name a credential.
SECRET_PARTS = frozenset(
    {"password", "passwd", "pass", "pwd", "secret", "token", "apikey", "credential", "credentials"}
)
#: Two-part names that name a credential only together.
SECRET_PAIRS = frozenset({("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"), ("auth", "key")})
#: A last part that makes the variable a pointer to or a property of a secret, not the secret.
NOT_SECRET_LAST = frozenset(
    {
        "file",
        "path",
        "dir",
        "url",
        "uri",
        "endpoint",
        "name",
        "user",
        "username",
        "header",
        "type",
        "length",
        "ttl",
        "expiry",
        "expires",
        "id",
        "min",
        "max",
        "policy",
        "required",
        "enabled",
        "env",
        "var",
        "ref",
        "hash",
        "algorithm",
        "location",
        "mode",
        "host",
        "port",
        "prefix",
        "suffix",
        "algo",
        "days",
        "age",
        "len",
        "encoder",
        "manager",
        "region",
        "rotation",
    }
)
#: A credential word glued to a prefix with no separator (PGPASSWORD, MYSQLPWD is too short to tell).
GLUED = ("password", "passwd", "secret")
SHELL_VARS = frozenset({"PWD", "OLDPWD"})
NOT_LITERAL = frozenset({"", "true", "false", "yes", "no", "on", "off", "none", "null", "0", "1"})
#: Reference forms: a variable, a template, an <angle placeholder>, a run-time secret path.
REFERENCE = re.compile(r"\$|\{\{|%\(|^<[^>]*>$|^/run/secrets/|^\*+$|^x{3,}$", re.IGNORECASE)
PARTS = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
#: scan-secrets 0.0.9's keyword and token alternatives (its private-key header excepted, which no
#: variable value carries); written with classes so this text is not itself a match.
SCAN_SECRETS = re.compile(
    r"(?i)((AKI[A]|ASI[A])[0-9A-Z]{16}|gh[oprsu]_[0-9A-Za-z]{36}|github_pa[t]_[0-9A-Za-z_]{22,}|xox[bpas]-[0-9A-Za-z-]{10,}"
    r"|(sk|rk)_liv[e]_[0-9A-Za-z]{16,}|sk-pro[j]-[0-9A-Za-z_-]{20,}|sk-an[t]-[0-9A-Za-z_-]{20,}|s[k]-[0-9A-Za-z]{20,}"
    r"|AIz[a][0-9A-Za-z_-]{35}|np[m]_[0-9A-Za-z]{36}|S[G]\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}"
    r"|ey[J][A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*|api[_-]?ke[y]\s*=\s*[\"'][A-Za-z0-9_\-]{20,}[\"']"
    r"|secret[_-]?ke[y]\s*=\s*[\"'][A-Za-z0-9_\-]{20,}[\"']|auth[_-]?toke[n]\s*=\s*[\"'][A-Za-z0-9_\-]{20,}[\"']"
    r"|passwor[d]\s*=\s*[\"'][^\"'\s]{12,}[\"']|(api|secret|auth)[_-]?(key|token)\s*[=:]\s*[A-Za-z0-9_\-]{20,}"
    r"|passwor[d]\s*[=:]\s*[^\s\"'${}]{12,})"
)


def is_secret_name(name: str) -> bool:
    if name.upper() in SHELL_VARS:
        return False
    parts = [p.lower() for p in PARTS.findall(name)]
    if not parts or parts[-1] in NOT_SECRET_LAST:
        return False
    if any(p in SECRET_PARTS or p.endswith(GLUED) for p in parts):
        return True
    return any(pair in SECRET_PAIRS for pair in pairwise(parts))


def is_literal(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    return stripped.lower() not in NOT_LITERAL and not REFERENCE.search(stripped)


def scan_secrets_reads(line: str) -> bool:
    """Whether scan-secrets refuses this physical line on its own."""
    return bool(SCAN_SECRETS.search(line))


Scanned = list[tuple[str, list[tuple[int, int]]]]


def scanned(lines: tuple[str, ...] | list[str]) -> Scanned:
    """Each raw physical line with the spans scan-secrets refuses in it; the scan is done once per instruction."""
    return [(line, [found.span() for found in SCAN_SECRETS.finditer(line)]) for line in lines]


def left_to_scan_secrets(literal: str, lines: Scanned) -> bool:
    """Whether scan-secrets refuses a span of one raw physical line that holds this literal; a value written elsewhere is not seen."""
    value = literal.strip().strip("\"'")
    if not value:
        return False
    for line, spans in lines:
        at = line.find(value) if spans else -1
        while at >= 0:
            if any(start < at + len(value) and end > at for start, end in spans):
                return True
            at = line.find(value, at + 1)
    return False
