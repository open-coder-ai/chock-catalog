"""registry-config: the third review's reproducers: shell defaults, list spacing, XML tricks and slow lines."""

from __future__ import annotations

import time

import pytest
from policies.test_registry_config import (
    A_REDIR,
    B_HOST,
    B_HTTP,
    B_TLS,
    B_TOKEN,
    B_UNREAD,
    mod,
    rules,
)

BUDGET = 5.0


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # An unquoted shell default is judged like a quoted one.
        ("b.sh", "export GOSUMDB=${GOSUMDB:-off}\n", [B_TLS]),
        ("compose.yaml", "services:\n  b:\n    environment:\n      GOSUMDB: ${GOSUMDB:-off}\n", [B_TLS]),
        (
            "Dockerfile",
            "ENV GOPROXY=${GOPROXY:-http://evil.example}\nENV GOFLAGS=${GOFLAGS:--insecure}\n",
            [B_HTTP, B_TLS],
        ),
        # Go trims each list element.
        ("Dockerfile", 'ENV GOPROXY="https://proxy.golang.org| https://evil.example"\n', [B_HOST]),
        ("b.sh", 'export GOPROXY="https://proxy.golang.org, http://evil.example"\n', [B_HTTP]),
        # GOSUMDB built from an expression asks; a plain pass-through does not.
        (".github/workflows/x.yml", "env:\n  GOSUMDB: ${{ 'off' }}\n", [A_REDIR]),
        ("Dockerfile", "ENV GOSUMDB=off$EMPTY\n", [A_REDIR]),
        ("Dockerfile", "ENV GOSUMDB=${GOSUMDB}\n", []),
        # NuGet: case-variant attributes are refused; a processing instruction ends at its own '?>'.
        (
            "nuget.config",
            '<configuration><packageSources><clear/><add key="n" value="http://evil.example/" '
            'Value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>',
            [B_UNREAD],
        ),
        (
            "nuget.config",
            '<configuration><?x \'?><packageSources><clear/><add key="a" value="http://evil.example/"/>'
            "</packageSources><!-- ' --></configuration>",
            [B_HTTP],
        ),
        (
            "settings.xml",
            "<settings><?x '?><mirrors><mirror><url>http://evil.example/</url></mirror></mirrors></settings>",
            [B_HTTP],
        ),
        ("nuget.config", "<configuration><?x unclosed", [B_UNREAD]),
        # Only a <clear/> directly in packageSources clears inherited sources.
        (
            "nuget.config",
            '<configuration><packageSources><add key="a" value="https://api.nuget.org/v3/index.json"><clear/></add>'
            "</packageSources></configuration>",
            ["reg-confusion"],
        ),
        # npm 9's ${VAR?} is an environment reference; pnpm's workspace: protocol is a local package.
        (".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN?}\nmin-release-age=1\n", []),
        ("pnpm-workspace.yaml", "overrides:\n  baz: 'workspace:*'\nminimumReleaseAge: 1\n", []),
        # JSON5 line comments end at CR, LS and PS too.
        ("renovate.json5", "{ // c\r a: 1 }", []),
        ("renovate.json5", "{ // c\u2028 automerge: true }", ["reg-vcs-weaken"]),
        ("renovate.json5", "{ a: 1 // end", [B_UNREAD]),
        (".npmrc", "  strict-ssl = false \nmin-release-age=1\n", [B_TLS]),
        (".yarnrc", "registry   http://e.example/   \n", [B_HTTP]),
        ("Gemfile", 'source ( "http://e.example" )\n', [B_HTTP]),
        (".pypirc", "[pypi]\npassword = ${{ secrets.X }}x\n", [B_TOKEN]),
    ],
)
def test_round_three_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("Gemfile", "source" + " " * 20000 + "x"),
        ("Podfile", "source" + " " * 20000 + "x"),
        (".npmrc", "a=x" + " " * 1_000_000 + "y"),
        (".yarnrc", "a b" + " " * 1_000_000 + "c"),
        ("requirements.txt", "--index-url " + "x" * 1_000_000),
        ("requirements.txt", "--index-url '" + "x" * 1_000_000),
        ("environment.yml", "dependencies:\n  - pip:\n    - '" + "x" * 900_000 + "'\n"),
        ("nuget.config", "<configuration><add " + "a" * 500_000 + "/></configuration>"),
    ],
)
def test_pathological_lines_are_judged_in_time(path: str, text: str) -> None:
    started = time.monotonic()
    mod.findings({"writes": {path: text}})
    assert time.monotonic() - started < BUDGET


def test_an_overlong_requirement_line_is_refused() -> None:
    assert rules("requirements.txt", "--index-url " + "x" * 70_000 + "\n") == [B_UNREAD]
