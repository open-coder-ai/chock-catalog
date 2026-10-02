"""Scanner ignore lists, ignore keys in scanner config, and CI steps told to pass when a scan fails."""

from __future__ import annotations

import re
from collections.abc import Iterator

#: Files that hold nothing but ignore entries: every entry is one finding.
IGNORE_FILES = {
    ".gitleaksignore": "gitleaksignore-entry",
    ".trivyignore": "trivyignore-entry",
    ".trivyignore.yaml": "trivyignore-entry",
    ".trivyignore.yml": "trivyignore-entry",
    ".semgrepignore": "semgrepignore-entry",
}

#: YAML scanner configs and the keys in them that switch checks off.
CONFIG_KEYS = {
    ".checkov.yml": ("checkov-config-skip", {"skip-check", "skip_check", "soft-fail", "soft_fail"}),
    ".checkov.yaml": ("checkov-config-skip", {"skip-check", "skip_check", "soft-fail", "soft_fail"}),
    ".hadolint.yaml": ("hadolint-config-ignored", {"ignored"}),
    ".hadolint.yml": ("hadolint-config-ignored", {"ignored"}),
    ".ansible-lint": ("ansible-lint-skip-list", {"skip_list", "warn_list"}),
    ".ansible-lint.yml": ("ansible-lint-skip-list", {"skip_list", "warn_list"}),
    ".ansible-lint.yaml": ("ansible-lint-skip-list", {"skip_list", "warn_list"}),
    "ansible-lint.yml": ("ansible-lint-skip-list", {"skip_list", "warn_list"}),
    "ansible-lint.yaml": ("ansible-lint-skip-list", {"skip_list", "warn_list"}),
    ".bandit": ("bandit-config-skips", {"skips"}),
    "bandit.yaml": ("bandit-config-skips", {"skips"}),
    "bandit.yml": ("bandit-config-skips", {"skips"}),
    ".snyk": ("snyk-config-ignore", {"ignore"}),
    "zizmor.yml": ("zizmor-config-ignore", {"ignore", "disable"}),
    ".zizmor.yml": ("zizmor-config-ignore", {"ignore", "disable"}),
    "zizmor.yaml": ("zizmor-config-ignore", {"ignore", "disable"}),
    ".zizmor.yaml": ("zizmor-config-ignore", {"ignore", "disable"}),
}

GITLEAKS_TOML = {".gitleaks.toml", "gitleaks.toml"}

CI_FILE = re.compile(
    r"(^|/)(\.github/workflows/[^/]+|\.gitlab-ci[^/]*|\.gitlab/[^\n]+|azure-pipelines[^/]*|"
    r"bitbucket-pipelines[^/]*|\.circleci/[^/]+)\.ya?ml$"
)
#: A CI step or job that runs a security scanner, named by its action, its command or its title.
SCANNER = re.compile(
    r"codeql|semgrep|bandit|gitleaks|trufflehog|detect-secrets|trivy|grype|snyk|checkov|tfsec|kics|"
    r"zizmor|gosec|brakeman|npm audit|yarn audit|pnpm audit|pip-audit|safety check|osv-scanner|"
    r"dependency-review|scorecard|hadolint|sonar|govulncheck|cargo audit|cargo deny|bundler-audit|"
    r"secret.?scan|\bsast\b|\bdast\b|security|\bchock\b",
    re.IGNORECASE,
)
#: A step or job told to pass when it fails: a flag, or a shell `|| true` / `|| exit 0` / `|| :`.
SOFT_FAIL = re.compile(
    r"^\s*-?\s*(?:continue-on-error|allow_failure|continueOnError|soft[-_]fail)\s*:\s*['\"]?(?:true|yes|on)\b|"
    r"\|\|\s*(?:true|exit\s+0|:)\s*(?:$|[;)#&|])",
    re.IGNORECASE,
)
_KEY = re.compile(r"^\s*(?:-\s+)?['\"]?([\w.-]+)['\"]?\s*[:=](.*)$")
_COMMENT = re.compile(r"^\s*(#|$)")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def normalized(line: str) -> str:
    return " ".join(line.split())


def ignore_entries(text: str) -> Iterator[tuple[int, str]]:
    """Every non-blank, non-comment line of an ignore-only file."""
    for number, line in enumerate(text.splitlines(), 1):
        if not _COMMENT.match(line):
            yield number, normalized(line)


def keyed_entries(text: str, keys: set[str]) -> Iterator[tuple[int, str]]:
    """Lines that set, or sit in the block of, one of `keys` (YAML block or flow form)."""
    owner: tuple[int, str] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        if _COMMENT.match(line):
            continue
        indent, stripped = _indent(line), line.strip()
        if owner and (indent > owner[0] or (indent == owner[0] and stripped.startswith("- "))):
            yield number, f"{owner[1]}|{normalized(line)}"
            continue
        owner = None
        found = _KEY.match(line)
        if found and found.group(1) in keys:
            yield number, f"{found.group(1)}|{normalized(line)}"
            owner = (indent, found.group(1))


def gitleaks_allowlist(text: str) -> Iterator[tuple[int, str]]:
    """Value lines inside a gitleaks `[allowlist]`, `[[allowlists]]` or `[rules.allowlist]` table."""
    table = ""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("["):
            table = stripped
            if "allowlist" in table.lower():
                yield number, normalized(line)
        elif "allowlist" in table.lower() and not _COMMENT.match(line):
            yield number, f"{table}|{normalized(line)}"


def _block_head(lines: list[str], index: int) -> int:
    """The step or job a CI line belongs to: its nearest list-item ancestor, else its outermost key below the root."""
    limit, chain = _indent(lines[index]), []
    for back in range(index - 1, -1, -1):
        line = lines[back]
        if _COMMENT.match(line) or _indent(line) >= limit:
            continue
        if line.lstrip().startswith("- "):
            return back
        chain.append(back)
        limit = _indent(line)
    nested = [i for i in chain if _indent(lines[i]) > 0]
    return nested[-1] if nested else (chain[-1] if chain else index)


def _block(lines: list[str], head: int) -> str:
    """The text of the step or job that starts at `head`."""
    start = _indent(lines[head])
    body = [lines[head]]
    for line in lines[head + 1 :]:
        if not _COMMENT.match(line) and _indent(line) <= start:
            break
        body.append(line)
    return "\n".join(body)


def soft_failed_scans(text: str) -> Iterator[tuple[int, str]]:
    """A soft-fail line inside a CI step or job that runs a security scanner."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if _COMMENT.match(line) or not SOFT_FAIL.search(line):
            continue
        head = _block_head(lines, index)
        if SCANNER.search(_block(lines, head)):
            yield index + 1, f"{normalized(lines[head])}|{normalized(line)}"


def config_findings(path: str, text: str) -> Iterator[tuple[str, int, str]]:
    """(rule, line, key detail) for each ignore entry, ignore key or soft-failed scan in a config file."""
    name = path.rsplit("/", 1)[-1]
    if name in IGNORE_FILES:
        yield from ((IGNORE_FILES[name], n, d) for n, d in ignore_entries(text))
    elif name in CONFIG_KEYS:
        rule, keys = CONFIG_KEYS[name]
        yield from ((rule, n, d) for n, d in keyed_entries(text, keys))
    elif name in GITLEAKS_TOML:
        yield from (("gitleaks-config-allowlist", n, d) for n, d in gitleaks_allowlist(text))
    if CI_FILE.search(path):
        yield from (("ci-scan-soft-fail", n, d) for n, d in soft_failed_scans(text))
