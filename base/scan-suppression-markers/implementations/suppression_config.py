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
SCANNER = re.compile(  # run on lowercased text: a case-sensitive search is far faster
    r"codeql|semgrep|bandit|gitleaks|trufflehog|detect-secrets|trivy|grype|snyk|checkov|tfsec|kics|"
    r"zizmor|gosec|brakeman|npm audit|yarn audit|pnpm audit|pip-audit|safety check|osv-scanner|"
    r"dependency-review|scorecard|hadolint|sonar|govulncheck|cargo audit|cargo deny|bundler-audit|"
    r"secret.?scan|secret_detection|dependency_scanning|container_scanning|api_fuzzing|\bsast\b|\bdast\b|"
    r"security[-_ ]?(?:scan|audit|check|lint)|\bchock\s+check\b",
)
#: A step or job told to pass when it fails: a flag, a scanner's own no-fail option, or a shell
#: `|| true`-style fallback. `set +e` is a separate pattern (see `_RESTORED`).
SOFT_FAIL = re.compile(
    r"[\"']?\b(?:continue-on-error|allow_failure|continueOnError|soft[-_]fail)[\"']?\s*:\s*(?:!!bool\s+)?"
    r"(?:[\"']?(?:true|yes|on)\b|\{|[>|]-?\s*$|(?:#.*)?$)|"
    r"\bexit-code\s*:\s*[\"']?0\b|\bshell\s*:\s*bash\s+\+e\b|;\s*true\s*(?:#.*)?$|"
    r"\|\|\s*(?:\{\s*)?(?:(?:command|builtin)\s+)?(?:(?:/usr)?/bin/)?(?:true|:|exit\s+0)(?=$|[\s;)#&|'\"}])|"
    r"(?<!\|)\|(?!\|)\s*(?:true|:)(?=$|[\s;)#&|'\"}])|"
    r"--soft-fail\b|--exit-code[ =][\"']?0\b|--exit-zero\b|--ignore-on-exit\b|(?:^|\s)--?no-fail(?![\w-])|--no-exit-codes\b",
    re.IGNORECASE,
)
#: A fallback that prints instead of failing; inside `$( )` it only fills a variable.
_ECHO_FALLBACK = re.compile(r"\|\|\s*(?:echo|printf)\b")
_SET_PLUS_E = re.compile(r"\bset\s+\+e\b")
#: A word every soft-fail shape above contains; a CI file without one has nothing to judge.
_CI_PREFILTER = re.compile(
    r"\|\||\|\s*(?:true|:)|continue|allow_failure|soft[-_]fail|set\s+\+e|bash\s+\+e|exit-code|exit-zero|ignore-on-exit|no-fail|"
    r"no-exit-codes|_disabled|;\s*true"
)
_SHELL_PLUS_E = re.compile(r"\bshell\s*:\s*bash\s+\+e\b")
#: A later code line that captures the scan's status ($?) or exits with it keeps the scan's verdict;
#: a bare set -e afterwards does not, as the failure was already swallowed.
_RESTORED = re.compile(r"\bexit\s+\"?\$|\$\?")
_DEFAULTS = re.compile(r"^[\"']?defaults[\"']?\s*:")
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
    table, inside = "", False
    for number, line in enumerate(lines_of(text), 1):
        stripped = line.strip()
        if stripped.startswith("["):
            table, inside = stripped, "allowlist" in stripped.lower()
            if inside:
                yield number, normalized(line)
        elif inside and not _COMMENT.match(line):
            yield number, f"{table}|{normalized(line)}"


def _layout(lines: list[str]) -> tuple[list[int], list[int], list[int]]:
    """Per line: the step or job it belongs to (itself if a list item, else its nearest list-item
    ancestor, else its outermost key below the root, else its root key), its root key, and the index
    just past the block it opens (the next code line indented no deeper). One pass with a stack of
    open ancestors whose indents strictly increase, so long and deeply nested files stay linear."""
    size = len(lines)
    indents = [_indent(line) for line in lines]
    item = [line.lstrip().startswith("- ") for line in lines]
    heads, roots, ends = list(range(size)), list(range(size)), [size] * size
    stack: list[int] = []
    items: list[int] = []  # positions in `stack` that are list items
    for index in range(size):
        if _COMMENT.match(lines[index]):
            continue
        while stack and indents[stack[-1]] >= indents[index]:
            ends[stack.pop()] = index
        while items and items[-1] >= len(stack):
            items.pop()
        if stack:
            roots[index] = stack[0]
            nested = stack[0] if indents[stack[0]] > 0 else (stack[1] if len(stack) > 1 else stack[0])
            heads[index] = index if item[index] else (stack[items[-1]] if items else nested)
        if item[index]:
            items.append(len(stack))
        stack.append(index)
    return heads, roots, ends


def _prefix(lines: list[str], pattern: re.Pattern[str], *, code_only: bool) -> list[int]:
    """Running count of the lines `pattern` finds, so any block's count is one subtraction."""
    counts = [0]
    for line in lines:
        hit = pattern.search(line) and not (code_only and _COMMENT.match(line))
        counts.append(counts[-1] + bool(hit))
    return counts


def _soft_fails(line: str) -> bool:
    """Whether a CI line lets a failing command pass, before its step is known."""
    if SOFT_FAIL.search(line) or _SET_PLUS_E.search(line):
        return True
    echo = _ECHO_FALLBACK.search(line)
    return bool(echo) and line.count("$(", 0, echo.start()) <= line.count(")", 0, echo.start())


def soft_failed_scans(text: str) -> Iterator[tuple[int, str]]:
    """A soft-fail line inside a CI step or job that runs a security scanner, or a GitLab scan switched off."""
    if not _CI_PREFILTER.search(text.lower()):
        return
    lines = lines_of(text)
    heads, roots, ends = _layout(lines)
    # Regexes run on the text after the indentation, never over a long run of leading spaces.
    code = [line.lstrip() for line in lines]
    scans = _prefix([line.lower() for line in code], SCANNER, code_only=False)
    restores = _prefix(code, _RESTORED, code_only=True)
    for index, (line, stripped) in enumerate(zip(lines, code, strict=True)):
        if _COMMENT.match(stripped):
            continue
        if GITLAB_DISABLED.search(stripped):
            yield index + 1, f"disabled|{normalized(line)}"
            continue
        if not _soft_fails(stripped):
            continue
        head = heads[index]
        end = ends[head]
        scanned = not _NOT_A_JOB.match(lines[head]) and scans[end] > scans[head]
        if not scanned and _SHELL_PLUS_E.search(stripped) and _DEFAULTS.match(lines[roots[index]]):
            # A root `defaults: run: shell: bash +e` reaches every step, the scans among them.
            scanned = scans[-1] > 0
        restored = (
            _SET_PLUS_E.search(stripped) and not SOFT_FAIL.search(stripped) and restores[end] > restores[index + 1]
        )
        if scanned and not restored:
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
