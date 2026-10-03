"""registry-config: the fifth review's reproducers: unclosed expansions, glued terminators, one-letter variables."""

from __future__ import annotations

import time

import pytest
from policies.test_registry_config import A_REDIR, B_HOST, B_TLS, B_TOKEN, B_UNREAD, mod, rules

BUDGET = 5.0


@pytest.mark.parametrize(
    "text",
    [
        "GOSUMDB=" + "${" * 500_000,
        "GOSUMDB=" + "${{" * 300_000,
        "GOSUMDB=" + "$(" * 500_000,
        'GOSUMDB="' * 100_000,
        "GOSUMDB=#" * 100_000,
    ],
)
def test_unclosed_expansions_and_glued_words_are_judged_in_time(text: str) -> None:
    started = time.monotonic()
    assert mod.findings({"writes": {"b.sh": text}})
    assert time.monotonic() - started < BUDGET


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # A '#', ';', ']' or '}' glued to the value may be part of the word: both readings are judged.
        ("b.sh", "export GONOSUMDB=github.com/myorg#,*\n", [B_TLS]),
        ("b.sh", "export GOPROXY=https://proxy.golang.org#,https://evil.example\n", [B_HOST]),
        (".github/workflows/x.yml", "env:\n  GONOSUMDB: corp.example;,*\n  GOPRIVATE: corp.example],*\n", [B_TLS]),
        (".github/workflows/x.yml", "env: {GOPROXY: https://proxy.golang.org}\n", []),
        ("b.sh", "GOSUMDB=a#" + "x" * 5000 + ",*\n", [B_UNREAD]),
        # One-letter and positional variables split from what follows them.
        ("b.sh", "export GOSUMDB=$1off\n", [A_REDIR]),
        ("b.sh", "export GOSUMDB=$1\n", []),
        ("Makefile", "export GOSUMDB=$Eoff\n", [A_REDIR]),
        ("Makefile", "export GOSUMDB=$EOFF\n", [A_REDIR]),
        ("Makefile", "export GOSUMDB ?= $(GOSUMDB)\n", []),
        (".devcontainer/devcontainer.json", '{"remoteEnv": {"GOPROXY": "${localEnv:GOPROXY}"}}', []),
        ("build.ps1", '$env:GOPROXY = "$env:GOPROXY"\n', []),
        # An escape in a GO* value asks.
        ("b.sh", "GOFLAGS=\\-insecure\n", [A_REDIR]),
        # A YAML double-quoted escape is resolved as the loader resolves it.
        (".github/workflows/x.yml", 'env:\n  GOFLAGS: "\\x2dinsecure"\n', [B_TLS]),
        # Only an empty default makes a credential a reference.
        (".yarnrc.yml", 'npmAuthToken: "${NPM_TOKEN:-$lit3d9f}"\nnpmMinimalAgeGate: 3d\n', [B_TOKEN]),
        (".npmrc", "//r.example/:_authToken=${NPM_TOKEN:-}\nmin-release-age=1\n", []),
    ],
)
def test_round_five_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))
