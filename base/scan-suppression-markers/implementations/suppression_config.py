"""Scanner ignore lists, ignore keys in scanner config, and CI steps told to pass when a scan fails."""

from __future__ import annotations

import re
from collections.abc import Iterator

from suppression_markers import lines_of

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
    r"bitbucket-pipelines[^/]*|\.azure-pipelines/[^\n]+|\.circleci/[^/]+|action)\.ya?ml$"
)
#: A CI step or job that runs a security scanner, named by its action, its command or its title.
SCANNER = re.compile(
    r"codeql|semgrep|bandit|gitleaks|trufflehog|detect-secrets|trivy|grype|snyk|checkov|tfsec|kics|"
    r"zizmor|gosec|brakeman|npm audit|yarn audit|pnpm audit|pip-audit|safety check|osv-scanner|"
    r"dependency-review|scorecard|hadolint|sonar|govulncheck|cargo audit|cargo deny|bundler-audit|"
    r"secret.?scan|secret_detection|dependency_scanning|container_scanning|api_fuzzing|\bsast\b|\bdast\b|"
    r"security[-_ ]?(?:scan|audit|check|lint)|\bchock\s+check\b",
    re.IGNORECASE,
)
#: A step or job told to pass when it fails: a flag, a scanner's own no-fail option, or a shell
#: `|| true`-style fallback. `set +e` is a separate pattern (see `_RESTORED`).
SOFT_FAIL = re.compile(
    r"[\"']?\b(?:continue-on-error|allow_failure|continueOnError|soft[-_]fail)[\"']?\s*:\s*(?:!!bool\s+)?"
    r"(?:[\"']?(?:true|yes|on)\b|\{|[>|]-?\s*$|(?:#.*)?$)|"
    r"\bexit-code\s*:\s*[\"']?0\b|\bshell\s*:\s*bash\s+\+e\b|;\s*true\s*(?:#.*)?$|"
    r"\|\|\s*(?:\{\s*)?(?:(?:command|builtin)\s+)?(?:(?:/usr)?/bin/)?(?:true|:|exit\s+0)(?=$|[\s;)#&|'\"}])|"
    r"--soft-fail\b|--exit-code[ =][\"']?0\b|--exit-zero\b|--ignore-on-exit\b|(?:^|\s)--?no-fail\b|--no-exit-codes\b",
    re.IGNORECASE,
)
#: A fallback that prints instead of failing; inside `$( )` it only fills a variable.
_ECHO_FALLBACK = re.compile(r"\|\|\s*(?:echo|printf)\b")
_SET_PLUS_E = re.compile(r"\bset\s+\+e\b")
#: A block that turns errexit back on or passes the scan's own status on keeps the scan's verdict.
_RESTORED = re.compile(r"\bset\s+-e\b|\bexit\s+\"?\$")
#: GitLab's switches that turn a whole security template off.
GITLAB_DISABLED = re.compile(
    r"\b(?:SAST|SECRET_DETECTION|DEPENDENCY_SCANNING|CONTAINER_SCANNING|DAST|API_FUZZING|COVERAGE_FUZZING|"
    r"IAC_SCANNING)_DISABLED[\"']?\s*:\s*[\"']?(?:true|1|yes)\b",
    re.IGNORECASE,
)
#: Top-level keys that are settings, not a job a soft-fail could belong to.
_NOT_A_JOB = re.compile(
    r"^[\"']?(?:env|variables|on|permissions|defaults|concurrency|name|run-name|workflow|stages|include|default)"
    r"[\"']?\s*:"
)
_KEY = re.compile(r"^\s*(?:-\s+)?['\"]?([\w.-]+)['\"]?\s*[:=](.*)$")
_COMMENT = re.compile(r"^\s*(#|$)")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def normalized(line: str) -> str:
    return " ".join(line.split())


def ignore_entries(text: str) -> Iterator[tuple[int, str]]:
    """Every non-blank, non-comment line of an ignore-only file."""
    for number, line in enumerate(lines_of(text), 1):
        if not _COMMENT.match(line):
            yield number, normalized(line)


def keyed_entries(text: str, keys: set[str]) -> Iterator[tuple[int, str]]:
    """Lines that set, or sit in the block of, one of `keys` (YAML block or flow form)."""
    owner: tuple[int, str] | None = None
    for number, line in enumerate(lines_of(text), 1):
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
    for number, line in enumerate(lines_of(text), 1):
        stripped = line.strip()
        if stripped.startswith("["):
            table = stripped
            if "allowlist" in table.lower():
                yield number, normalized(line)
        elif "allowlist" in table.lower() and not _COMMENT.match(line):
            yield number, f"{table}|{normalized(line)}"


def _heads(lines: list[str]) -> list[int]:
    """For each line, the step or job it belongs to: the line itself if it is a list item, else its
    nearest list-item ancestor, else its outermost key below the root (the root key for a GitLab job).
    One pass with a stack of open ancestors, so a long `run:` block stays linear."""
    heads, stack = [], []  # stack: indices of open ancestors, strictly increasing indent
    for index, line in enumerate(lines):
        if _COMMENT.match(line):
            heads.append(index)
            continue
        while stack and _indent(lines[stack[-1]]) >= _indent(line):
            stack.pop()
        items = [i for i in stack if lines[i].lstrip().startswith("- ")]
        if line.lstrip().startswith("- "):
            heads.append(index)
        elif items:
            heads.append(items[-1])
        else:
            nested = [i for i in stack if _indent(lines[i]) > 0]
            heads.append(nested[0] if nested else (stack[0] if stack else index))
        stack.append(index)
    return heads


def _block(lines: list[str], head: int) -> str:
    """The text of the step or job that starts at `head`."""
    start = _indent(lines[head])
    body = [lines[head]]
    for line in lines[head + 1 :]:
        if not _COMMENT.match(line) and _indent(line) <= start:
            break
        body.append(line)
    return "\n".join(body)


def _soft_fails(line: str) -> bool:
    """Whether a CI line lets a failing command pass, before its step is known."""
    if SOFT_FAIL.search(line) or _SET_PLUS_E.search(line):
        return True
    echo = _ECHO_FALLBACK.search(line)
    return bool(echo) and line.count("$(", 0, echo.start()) <= line.count(")", 0, echo.start())


def soft_failed_scans(text: str) -> Iterator[tuple[int, str]]:
    """A soft-fail line inside a CI step or job that runs a security scanner, or a GitLab scan switched off."""
    lines = lines_of(text)
    heads = _heads(lines)
    scans: dict[int, str | None] = {}
    for index, line in enumerate(lines):
        if _COMMENT.match(line):
            continue
        if GITLAB_DISABLED.search(line):
            yield index + 1, f"disabled|{normalized(line)}"
            continue
        if not _soft_fails(line):
            continue
        head = heads[index]
        if head not in scans:
            block = _block(lines, head)
            scans[head] = None if _NOT_A_JOB.match(lines[head]) or not SCANNER.search(block) else block
        block = scans[head]
        restored = _SET_PLUS_E.search(line) and not SOFT_FAIL.search(line) and block and _RESTORED.search(block)
        if block and not restored:
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
