"""pin-github-actions: the per-line pattern, case by case, and silent on this repository's own workflows."""

from __future__ import annotations

import fnmatch
import re

import pytest
from policies import scriptkit
from trees import ROOT

GATE = scriptkit.manifest("pin-github-actions")["hook"]["gate"]
PATTERN = re.compile(GATE["params"]["content_pattern"])
SCOPE = scriptkit.manifest("pin-github-actions")["applies_to"]["paths"]
SHA = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"
DIGEST = "sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412"

REFUSED = [
    "      - uses: actions/checkout@v4",
    "uses: some-org/deploy@main",
    'uses: "some-org/action@main"',
    f"uses: some-org/action@{SHA}-release",
    f"uses: actions/checkout@{SHA[:7]}",
    f"uses: actions/checkout@{SHA.upper()}",
    f"uses: actions/checkout@{SHA}#v4",
    f"uses: actions/checkout@v4  # {SHA}",
    "uses: some-org/action@+release",
    "uses: some-org/action@",
    "    uses: some-org/shared/.github/workflows/build.yml@main",
    "uses: docker://alpine:3.19",
    "uses: docker://ghcr.io/some-org/tool",
    "uses: 'docker://alpine:3.19'",
    "uses: DOCKER://alpine:3.19",
    f"uses: docker://alpine@{DIGEST[:-1]}",
    f"uses: docker://alpine@{DIGEST}x",
    "  image: docker://alpine:3.19",
    '"uses": "actions/checkout@v4"',
    '{"steps": [{"uses":"actions/checkout@v4"}]}',
    "'uses': actions/checkout@v4",
    "      - {name: co, uses: actions/checkout@v4}",
    "      - uses : actions/checkout@v4",
    "      - uses: &co actions/checkout@v4",
    "      - uses: !!str actions/checkout@v4",
    "x-co: &co actions/checkout@v4",
    "x-img: &img 'docker://alpine:3.19'",
    'x-co: &co "actions\\/checkout@v4"',
    "          actions/checkout@v4",
    '          "some-org/action@main"',
    "          some-org/shared/.github/workflows/build.yml@main  # moved?",
    "          docker://alpine:3.19",
    "      : actions/checkout@v4",
    '      - uses: "actions/checkout\\x40v4"',
    '      - uses: "actions/checkout@v4\\',
    '      - uses: "actions/',
    "      - uses: 'actions/",
    '          "actions\\/checkout@v4"',
    '      - "u\\x73es": actions/checkout@v4',
    '      - {"u\\u0073es": a}',
    '      - "us\\',
    "      - run: echo \\u0040",
]

SILENT = [
    f"      - uses: actions/checkout@{SHA}",
    f"      - uses: actions/checkout@{SHA}  # v4.1.1",
    f'uses: "actions/checkout@{SHA}"',
    f"uses: 'actions/checkout@{SHA}'",
    f'"uses": "actions/checkout@{SHA}"',
    f"      - {{name: co, uses: actions/checkout@{SHA}}}",
    f"      - {{uses: actions/checkout@{SHA}, with: {{fetch-depth: 0}}}}",
    f"    uses: some-org/shared/.github/workflows/build.yml@{SHA}",
    f"          actions/checkout@{SHA}",
    f"x-co: &co actions/checkout@{SHA}",
    "      - uses: ./.github/actions/setup",
    "    uses: ./.github/workflows/build.yml",
    f"uses: docker://alpine@{DIGEST}",
    f'uses: "docker://alpine:3.19@{DIGEST}"',
    f"  image: docker://alpine@{DIGEST}",
    "  image: Dockerfile",
    "      image: node:20",
    "            golang.org/x/tools/gopls@latest",
    "            @some-scope/tool@1.2.3",
    "      - run: go install golang.org/x/tools/gopls@latest",
    "      - run: git config user.email someone@example.com",
    '      - run: echo "C:\\temp" && make 2>&1',
    '          "--define=X=\\$Y" \\',
    "      - uses:",
    "      - uses: >-",
    "    with:",
    f"      - uses: aquasecurity/trivy-action@{SHA}  # 0.28.0 (tag since moved)",
]


@pytest.mark.parametrize("line", REFUSED)
def test_refuses(line: str) -> None:
    assert PATTERN.search(line), line


@pytest.mark.parametrize("line", SILENT)
def test_stays_silent(line: str) -> None:
    assert not PATTERN.search(line), line


@pytest.mark.parametrize(
    ("path", "judged"),
    [
        (".github/workflows/ci.yml", True),
        (".github/actions/setup/action.yml", True),
        ("action.yml", True),
        ("action.yaml", True),
        ("tools/setup/action.yaml", True),
        ("README.md", False),
        ("docs/ci.yml", False),
        ("transaction.yml", False),
        ("tools/transaction.yml", False),
    ],
)
def test_scope(path: str, judged: bool) -> None:
    assert any(fnmatch.fnmatchcase(path, glob) for glob in SCOPE) is judged


def test_silent_on_this_repositorys_own_workflows() -> None:
    """Every line of the workflows CI runs here is a correct pin: none may fire."""
    files = [p for p in (ROOT / ".github").rglob("*") if p.is_file() and p.suffix in {".yml", ".yaml"}]
    assert files
    fired = [
        f"{p.relative_to(ROOT)}:{n}: {line}"
        for p in files
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if PATTERN.search(line) and not re.search(GATE["params"]["allowlist_pragma"], line)
    ]
    assert not fired, "\n".join(fired)
