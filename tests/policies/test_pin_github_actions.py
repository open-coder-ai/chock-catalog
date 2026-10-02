"""pin-github-actions: the per-line pattern, case by case, and silent on this repository's own workflows."""

from __future__ import annotations

import fnmatch
import re
import time

import pytest
from policies import scriptkit
from trees import ROOT

GATE = scriptkit.manifest("pin-github-actions")["hook"]["gate"]
PATTERN = re.compile(GATE["params"]["content_pattern"])
SCOPE = scriptkit.manifest("pin-github-actions")["applies_to"]["paths"]
SHA = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"
DIGEST = "sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412"

REFUSED = [
    "  - ? # c",
    "  - ? !!str",
    "  - ? &a",
    "  - ? |-",
    "    ? >-",
    "  ? *k",
    "  - *k : actions/checkout@v4",
    "  - {*k : a}",
    "    *d",
    '    "\\x64ocker://alpine"',
    '    "dock\\',
    '  x: &d "\\x64ocker://alpine"',
    f"      - uses: actions/checkout@{SHA}\u00a0x",
    "a" * 4096,
    "      - { ? uses",
    "    steps: [ ? uses",
    "      - {name: x, ? uses",
    "runs: {using: docker, ? image",
    "      ? uses",
    '    steps: [ "u\\x73es": actions/checkout@v4 ]',
    '      - { ? "u\\x73es": actions/checkout@v4 }',
    '      - !!str "u\\x73es": actions/checkout@v4',
    '      - &k "u\\x73es": actions/checkout@v4',
    '  &k "im\\x61ge": docker://alpine',
    '- { ? "use\\',
    "          docker://alpine:3",
    "          docker://alpine:3.19, args: [a]}",
    "  x: &d docker://alpine:3",
    '      - uses: a/b"c@v1',
    "      - uses: actions/checkout@v4",
    "uses: some-org/deploy@main",
    'uses: "some-org/action@main"',
    f"uses: a/b@{SHA}-release",
    f"uses: a/b@{SHA[:7]}",
    f"uses: a/b@{SHA.upper()}",
    f"uses: a/b@{SHA}#v4",
    f"uses: a/b@v4  # {SHA}",
    "uses: a/b@+release",
    "uses: a/b@",
    "    uses: o/shared/.github/workflows/build.yml@main",
    "uses: docker://alpine:3.19",
    "uses: docker://ghcr.io/o/tool",
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
    "      - uses: *co",
    "      - uses:",
    "      - uses: >-",
    "      - uses: |",
    "      - uses: &a",
    "      - uses: # later",
    "      - {uses:",
    '{"steps": [{"uses":',
    "  image: *img",
    '      - uses: "actions/checkout\\x40v4"',
    '      - uses: "actions/checkout@v4\\',
    '      - uses: "actions/',
    "      - uses: 'actions/",
    '      - "u\\x73es": actions/checkout@v4',
    '      - {"u\\u0073es": a}',
    "      - ? uses",
    f"      - uses: some-org/act@{SHA},x",
    f"      - uses: some-org/act@{SHA}}}x",
    f"      - uses: some-org/act@{SHA}]x",
    f"      - uses: some-org/act@{SHA}'x",
    f"      - uses: some-org/act@{SHA}}}",
    f"      - uses: some-org/act@{SHA},",
    "uses: evil/repo/a,b@main",
    "uses: evil/repo/a b@main",
    "uses: evil/repo/a}b@main",
    "uses: evil/repo/a'b@main",
    "uses: 'evil/repo/x''y@main'",
    'uses: "evil/repo/a b@main"',
    '  image: "docker:\\/\\/alpine:3.19"',
    '  image: "\\x64ocker://alpine:3.19"',
    "      - uses: actions/checkout",
    "      - uses: actions/checkout  # v4",
    f"      - uses: '{'a/b@' + SHA}''x'",
    f'      - uses: "a/b@{SHA}x"',
]

SILENT = [
    '        "C:\\Users\\me"',
    '      - run: echo "\\x41"',
    "          *.txt",
    "          path: |",
    "a" * 4095,
    "              ? 'pr'",
    "              : 'push'",
    "              ? context.issue.number",
    "inputs:",
    "  image:",
    "    description: The image",
    '      - name: "reuses: some-org/action@main"',
    "      image: >-",
    f"      - uses: actions/checkout@{SHA}",
    f"      - uses: actions/checkout@{SHA}  # v4.1.1",
    f'uses: "actions/checkout@{SHA}"',
    f"uses: 'actions/checkout@{SHA}'",
    f'"uses": "actions/checkout@{SHA}"',
    f'{{"uses":"actions/checkout@{SHA}"}}',
    f"      - {{name: co, uses: actions/checkout@{SHA}}}",
    f"      - {{uses: actions/checkout@{SHA}, with: {{fetch-depth: 0}}}}",
    f"      - [{{uses: actions/checkout@{SHA}}}]",
    f"    uses: o/shared/.github/workflows/build.yml@{SHA}",
    "      - uses: ./.github/actions/setup",
    "    uses: ./.github/workflows/build.yml",
    "      - {uses: ./x, with: {email: a@b.c}}",
    '      - uses: "./.github/actions/x"',
    f"uses: docker://alpine@{DIGEST}",
    f'uses: "docker://alpine:3.19@{DIGEST}"',
    f"  image: docker://alpine@{DIGEST}",
    f"uses: 'docker://alpine@{DIGEST}'",
    "  image: Dockerfile",
    "      image: node:20",
    "      image: ${{ matrix.image }}",
    '      image: "node:20"',
    "            golang.org/x/tools/gopls@latest",
    "            @some-scope/tool@1.2.3",
    "          actions/checkout@v4",
    "      - run: go install golang.org/x/tools/gopls@latest",
    "      - run: git config user.email someone@example.com",
    '      - run: echo "C:\\temp" && make 2>&1',
    '          "--define=X=\\$Y" \\',
    "    with:",
    f"      - uses: aquasecurity/trivy-action@{SHA}  # 0.28.0 (tag since moved)",
    '      - run: echo "uses: a/b@c"',
    "      - run: echo reuses: a/b@c",
    "      - run: printf '\\x40'",
    "      - run: sed -i 's/a\\/b/c/' f",
    "      - run: curl -u user:pass@host https://x/?a=1&b=2",
    "    env:",
    "      FOO: bar@baz",
    "    runs-on: ubuntu-latest",
    "      - name: Use uses: in name",
    "  using: composite",
    "  main: dist/index.js",
    "      matrix: {os: [a, b]}",
    "        with: {script: 'console.log(1)'}",
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


FAMILIES = [
    '"uses":a ',
    '{"uses":a,',
    "'uses':a ",
    "[&a",
    ",&a",
    ":&a",
    "[? &a",
    "[?\t!a",
    '"image":&a',
    "uses: !a ",
    "uses: &a ",
    " uses: a",
    "uses: a ",
    "uses: a:b ",
    "x uses: a ",
    '"uses": "\\',
    "uses: '''",
    "{",
    "- ",
    "[? ",
    ",? uses",
    '{"a\\":',
    "uses: a'",
    "? !a ",
    "*a: ",
    '{"image":docker://x,',
]


@pytest.mark.parametrize("line", [(f * 4096)[:4095] for f in FAMILIES] + [f * 13334 for f in FAMILIES[:6]])
def test_a_long_hostile_line_is_judged_in_linear_time(line: str) -> None:
    """A commit hook has no timeout: no line may make the pattern backtrack quadratically."""
    start = time.perf_counter()
    PATTERN.search(line)
    assert time.perf_counter() - start < 0.3
