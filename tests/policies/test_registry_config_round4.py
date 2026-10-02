"""registry-config: the fourth review's reproducers: partial expansions and defaulted credentials."""

from __future__ import annotations

import pytest
from policies.test_registry_config import A_CONF, A_REDIR, B_HTTP, B_TLS, B_TOKEN, rules


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # A GO* value that is part expansion, part literal asks: what Go reads is not knowable from the file.
        ("Dockerfile", "ENV GOSUMDB=${X}off\n", [A_REDIR]),
        ("b.sh", 'export GOSUMDB=$EMPTY"off"\n', [A_REDIR]),
        ("b.sh", "export GOSUMDB=${EMPTY:-}off\n", [A_REDIR]),
        ("compose.yaml", "services:\n  b:\n    environment:\n      GOSUMDB: ${A}${B}\n", [A_REDIR]),
        (".github/workflows/x.yml", "env:\n  GOSUMDB: ${{ vars.E }}off\n", [A_REDIR]),
        ("b.sh", "export GOFLAGS=${EMPTY}-insecure\nexport GOPROXY=${E}direct\n", [A_REDIR]),
        ("compose.yaml", "services:\n  b:\n    environment:\n      GOFLAGS: ${X} -insecure\n", [A_REDIR]),
        # Pass-throughs stay quiet; quotes in a plain word are the shell's.
        ("Makefile", "export GOSUMDB ?= $(GOSUMDB)\n", []),
        ("b.sh", 'export GOSUMDB="$GOSUMDB"\n', []),
        ("b.sh", "export GOSUMDB=of'f'\n", [B_TLS]),
        ("b.sh", 'GOSUMDB="of"f\n', [B_TLS]),
        (".github/workflows/x.yml", "env: {GOSUMDB: 'off', GOFLAGS: -insecure}\n", [B_TLS]),
        ("Dockerfile", 'ENV GOPROXY="https://proxy.golang.org,direct"\n', []),
        # A defaulted reference is a reference only when the default is empty or itself a reference.
        (".npmrc", "//r.example/:_authToken=${NPM_TOKEN:-lit3.d9f}\nmin-release-age=3\n", [B_TOKEN]),
        (".yarnrc.yml", 'npmAuthToken: "${NPM_TOKEN-lit3.d9f}"\nnpmMinimalAgeGate: 3d\n', [B_TOKEN]),
        (".npmrc", "//r.example/:_authToken=${NPM_TOKEN:-}\nmin-release-age=3\n", []),
        (".npmrc", "//r.example/:_authToken=${NPM_TOKEN:-$CI_TOKEN}\nmin-release-age=3\n", [B_TOKEN]),
        # A nested packageSources does not make a nested <clear/> direct.
        (
            "nuget.config",
            "<configuration><packageSources><foo><packageSources/><clear/></foo>"
            '<add key="nuget.org" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>',
            [A_CONF],
        ),
        ("Gemfile", 'source(("http://evil.example"))\n', [B_HTTP]),
        ("requirements.txt", "# " + "x" * 70_000 + "\n" + " " * 70_000 + "\n", []),
    ],
)
def test_round_four_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))
