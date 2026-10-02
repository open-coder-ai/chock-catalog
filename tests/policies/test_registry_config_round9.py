"""registry-config: the ninth review's reproducers: command strings that are correct, escapes past Unicode."""

from __future__ import annotations

import pytest
from policies.test_registry_config import B_TLS, B_UNREAD, mod, rules

W = ".github/workflows/x.yml"


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # Correct command strings: the proxy list ends where the command begins, and expansions stay whole.
        ("Makefile", 'build:\n\tsh -c "GOPROXY=https://proxy.golang.org,direct go build ./..."\n', []),
        (
            ".gitlab-ci.yml",
            'b:\n  script:\n    - bash -c "GOPROXY=https://proxy.golang.org,direct; go test ./..."\n',
            [],
        ),
        (W, '      - run: echo "GOFLAGS=${{ inputs.goflags }}" >> $GITHUB_ENV\n', []),
        (W, '      - run: bash -c "GOFLAGS=-mod=vendor go test ./..."\n', []),
        (".devcontainer/devcontainer.json", '{"postCreateCommand": "GOPRIVATE=github.com/acme go mod download"}', []),
        ("Taskfile.yml", 'tasks:\n  t:\n    cmds:\n      - "GOPRIVATE=github.com/acme go mod tidy"\n', []),
        ("a.sh", 'echo "GOPRIVATE=github.com/myorg/* set, building"\n', []),
        # An escape past the Unicode range is left as written, and the URL it makes is refused.
        (".devcontainer/devcontainer.json", '{"containerEnv": {"GOSUMDB": "\\UFFFFFFFF"}}', [B_UNREAD]),
        # A quoted value or command string longer than 4 KB is refused, never judged in part.
        (W, 'env:\n  GONOSUMDB: "' + "corp.example," * 400 + '*"\n', [B_UNREAD]),
        ("a.sh", 'echo "GONOSUMDB=' + "corp.example," * 400 + '*" >> f\n', [B_UNREAD]),
    ],
)
def test_round_nine_cases(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


def test_two_readings_that_agree_report_one_finding() -> None:
    found = mod.findings({"writes": {"a.sh": 'sh -c "GOSUMDB=off go build"\n'}})
    assert [f["rule"] for f in found] == [B_TLS]
