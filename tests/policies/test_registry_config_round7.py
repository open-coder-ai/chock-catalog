"""registry-config: the seventh review's reproducers, against the rewritten GO* value reader (reg_goenv)."""

from __future__ import annotations

import time

import pytest
from policies.test_registry_config import A_REDIR, B_HOST, B_TLS, B_UNREAD, mod, rules

W = ".github/workflows/x.yml"
D = ".devcontainer/devcontainer.json"


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # A value starting with a terminator after the separator's space is still the value.
        (W, "env:\n  GONOSUMDB: ;,*\n", [B_TLS]),
        ("Dockerfile", "ENV GONOSUMDB ;,*\n", [B_TLS]),
        ("Makefile", "export GONOSUMDB = ],*\n", [B_TLS]),
        (".env", "GONOSUMDB= ;,*\n", [B_TLS]),
        (".env", "GOSUMDB= # default\n", []),
        # A quote closed on a later line: what this line holds is judged, and nothing certain asks.
        ("b.sh", 'export GOFLAGS="-insecure\n"\n', [B_TLS]),
        ("b.sh", 'export GONOSUMDB="*,\ncorp.example"\n', [B_TLS]),
        (W, 'env:\n  GOFLAGS: "-mod=vendor\n    -trimpath"\n', [A_REDIR]),
        ("b.sh", "echo 'GOFLAGS=-mod=vendor\n", [A_REDIR]),
        # devcontainer.json: JSON keys, runArgs and commands are all read; .devcontainer.json at the root too.
        (D, '{"runArgs": ["-e", "GOSUMDB=off"]}', [B_TLS]),
        (D, '{"runArgs": ["--env=GOFLAGS=-insecure"]}', [B_TLS]),
        (D, '{"postCreateCommand": "go env -w GOSUMDB=off"}', [B_TLS]),
        (D, '{"postCreateCommand": "echo GOINSECURE=* >> ~/.bashrc"}', [B_TLS]),
        (".devcontainer.json", '{"runArgs": ["-e", "GOSUMDB=off"]}', [B_TLS]),
        (D, '{"containerEnv": {"GOSUMDB": "sum.golang.org", "X": "y"}}', []),
        # The documented quoted $GITHUB_ENV form: the value ends at the outer string's quote.
        (W, '      - run: echo "GOSUMDB=off" >> "$GITHUB_ENV"\n', [B_TLS]),
        (W, '      - run: echo "GONOSUMDB=*" | tee -a "$GITHUB_ENV"\n', [B_TLS]),
        (W, '      - run: echo "GOPRIVATE=github.com/myorg/*" >> "$GITHUB_ENV"\n', []),
        (W, '      - run: echo "GOPROXY=https://proxy.golang.org,direct" >> "$GITHUB_ENV"\n', []),
        (W, "      - run: printf 'GOPRIVATE=%s\\n' github.com/myorg >> \"$GITHUB_ENV\"\n", [A_REDIR]),
        (W, 'env:\n  GOSUMDB: "off\n', [B_TLS]),
        # Shell concatenation after a closing quote, and a JSON or YAML flow separator that is not one.
        ("b.sh", 'GOPROXY="https://proxy.golang.org",https://evil.example\n', [B_HOST]),
        ("compose.yaml", 'services:\n  b:\n    environment: {GOPROXY: "https://proxy.golang.org", X: y}\n', []),
        ("compose.yaml", 'services:\n  b:\n    environment: {"GOSUMDB":"off","GONOSUMDB":"*"}\n', [B_TLS]),
        ("b.sh", "GONOSUMDB=corp.example#comment\n", [A_REDIR]),
    ],
)
def test_round_seven_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    "text",
    [
        ("GOFLAGS=-x#" * 363 + " ") * 250,
        ("GOPRIVATE=a} " * 80000),
        ('GOSUMDB="' + "x" * 1_000_000),
        "GOFLAGS=" + "x" * 5000 + "\n",
    ],
)
def test_many_settings_and_long_words_are_judged_in_time(text: str) -> None:
    started = time.monotonic()
    assert mod.findings({"writes": {"b.sh": text}})
    assert time.monotonic() - started < 5.0


def test_a_file_of_too_many_settings_is_refused() -> None:
    assert B_UNREAD in rules("b.sh", "GOPROXY=direct\n" * 1001)
