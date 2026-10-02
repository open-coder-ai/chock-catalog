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


@pytest.mark.parametrize(
    "text",
    [
        'sh -c "GOPRIVATE=github.com; go mod download"\n',
        'sh -c "GONOSUMDB=github.com/*; go mod download"\n',
        'bash -c "GONOSUMCHECK=gitlab.com& go build"\n',
        'sh -c "GOPRIVATE=github.com&&go build"\n',
    ],
)
def test_a_command_separator_ends_the_value_inside_a_string(text: str) -> None:
    assert rules("a.sh", text) == [B_TLS]


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ('sh -c "GOSUMDB=sum.golang.google.cn; go mod download"\n', []),
        ('sh -c "GOSUMDB=sum.golang.org&&go build"\n', []),
        ("GOSUMDB=sum.golang.org; go mod download\n", []),
        ("export GOSUMDB=sum.golang.google.cn; go build\n", []),
        ('sh -c "GOSUMDB=off; go build"\n', [B_TLS]),
        ("export GOPRIVATE=github.com&&go mod download\n", [B_TLS]),
        ("GONOSUMDB=github.com& go build\n", [B_TLS]),
        ("(export GOPRIVATE=github.com)\n", [B_TLS]),
        ("export GOPROXY=https://proxy.golang.org,direct&&go build\n", []),
    ],
)
def test_a_command_separator_ends_a_bare_or_sumdb_value(text: str, want: list[str]) -> None:
    assert rules("a.sh", text) == want


def test_a_sumdb_value_that_is_only_a_separator_is_empty() -> None:
    assert rules(".github/workflows/x.yml", "env:\n  GOSUMDB: ;x\n") == ["reg-overrides-redirect"]


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # A make variable assignment keeps ; & ( ) in its value; a recipe line is shell.
        ("Makefile", "GONOSUMDB = ;,*\n", [B_TLS]),
        ("rules.mk", "GOPRIVATE := (none),*\n", [B_TLS]),
        ("Makefile", "build:\n\tGOSUMDB=sum.golang.org; go build\n", []),
        ("Makefile", "build:\n\texport GOPRIVATE=github.com&&go build\n", [B_TLS]),
        # A quote or backslash before the separator: the shell may join across it, so both readings stand.
        ("a.sh", 'GOFLAGS=-ldflags=-s"; "-insecure\n', [B_TLS]),
        ("a.sh", "GOPROXY=https://proxy.golang.org'&',http://evil.example\n", ["reg-http-registry", B_UNREAD]),
    ],
)
def test_make_assignments_and_quoted_separators(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(want)


@pytest.mark.parametrize(
    ("text", "want"),
    [
        # Recipe lines continued with a backslash, and one-line rules, are shell too.
        ("t:\n\tset -e; \\\n    export GOPRIVATE=github.com/acme/*; go build\n", []),
        ("t:\n\tset -e; \\\n    export GOPRIVATE=github.com; go build\n", [B_TLS]),
        ("build: ; GOFLAGS=-mod=vendor; go build\n", []),
        ("build: ; GOSUMDB=off; go build\n", [B_TLS]),
        ("GOPRIVATE := (none),*\nt:\n\techo done\n", [B_TLS]),
    ],
)
def test_makefile_recipe_forms(text: str, want: list[str]) -> None:
    assert rules("Makefile", text) == want


def test_an_even_run_of_backslashes_does_not_continue_a_recipe() -> None:
    assert rules("Makefile", "t:\n\techo a\\\\\nGONOSUMDB := ;,*\n") == [B_TLS]
