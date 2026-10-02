"""registry-config: the second review's reproducers: timing on hostile input, and bypasses the first fixes left."""

from __future__ import annotations

import time

import pytest
from policies.test_registry_config import (
    A_COOL,
    A_REDIR,
    B_HOST,
    B_HTTP,
    B_TLS,
    B_TOKEN,
    B_UNREAD,
    LIT,
    MODULES,
    mod,
    rules,
)

AGE = "min-release-age=3\n"
BUDGET = 10.0  # seconds; the runner allows a script gate 30 s for both of its runs


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("nuget.config", "<configuration>" + "<add " * 20000),
        ("nuget.config", "<configuration><packageSources>" + '<add key="x" value="http://h.example/"/>' * 20000),
        ("settings.xml", "<settings>" + "<url " * 20000),
        ("settings.xml", "<settings><url>http://" + "x" * 100000 + "</url></settings>"),
        ("Directory.Build.props", "<Project>" + "<RestoreSources " * 20000),
        ("pip.conf", "[global]\nindex-url=" + "http://a.example/ " * 50000),
        ("deny.toml", "[sources]\nallow-registry = [" + "'http://a.example'," * 50000 + "]\n"),
        ("composer.json", '{"repositories": [' + '{"url": "http://a.example"},' * 30000 + '{"url": "x"}]}'),
        ("renovate.json5", "{" + "a: 'b'," * 100000 + "}"),
    ],
)
def test_hostile_input_is_judged_in_time(path: str, text: str) -> None:
    started = time.monotonic()
    found = mod.findings({"writes": {path: text}})
    assert time.monotonic() - started < BUDGET
    assert found


def test_a_flood_of_findings_in_one_file_is_one_new_finding() -> None:
    found = mod.findings({"writes": {"pip.conf": "[global]\nindex-url=" + "http://a.example/ " * 5000}})
    assert [(f["key"], f.get("new")) for f in found] == [("too-many", True)]


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # Yarn classic reads key:value with no space, and quoted keys.
        (
            ".yarnrc",
            'registry:"http://evil.example/"\nstrict-ssl:false\n"registry":"http://e2.example/"\n',
            [B_HTTP, B_TLS],
        ),
        # npm strips single quotes, then JSON-decodes what is inside; keys too.
        (".npmrc", "registry='\"http://evil.example/\"'\n" + AGE, [B_HTTP]),
        (".npmrc", "'\"strict-ssl\"'=false\n" + AGE, [B_TLS]),
        (".npmrc", "strict-ssl='\"false\"'\n" + AGE, [B_TLS]),
        (".npmrc", "strict-ssl='false'\nregistry='{\"a\": 1}'\nsave='1'\n" + AGE, [B_TLS]),
        # pip splits option text the shell way, so quotes inside a value join and drop.
        ("requirements.txt", '--index-url h"ttp://evil.example/simple"\n', [B_HTTP]),
        ("requirements.txt", '--trusted-host e"vil.example"\n', [B_TLS]),
        # pip refuses a line with an unbalanced quote, so nothing installs from it.
        ("requirements.txt", "--index-url 'unbalanced http://evil.example/\n", []),
        ("requirements.txt", "--index-url\n", []),
        # GOSUMDB: its own key, its own URL, clear text, read from the environment, a default expansion.
        ("Dockerfile", 'ENV GOSUMDB="sum.golang.org+deadbeef+AQID https://evil.example"\n', [A_REDIR, B_HOST]),
        ("Dockerfile", 'ENV GOSUMDB="sum.golang.org http://evil.example"\n', [B_HTTP]),
        ("Dockerfile", "ARG GOSUMDB\nENV GOSUMDB=$GOSUMDB\n", []),
        ("docker-compose.yml", "services:\n  b:\n    environment:\n      GOSUMDB: ${GOSUMDB}\n", []),
        (".github/workflows/b.yml", "env:\n  GOSUMDB: ${{ vars.GOSUMDB }}\n", []),
        ("Dockerfile", "ENV GOSUMDB=\n", []),
        ("scripts/b.sh", 'export GOPROXY="${GOPROXY:-http://evil.example}"\n', [B_HTTP]),
        ("scripts/b.sh", 'export GOFLAGS="${GOFLAGS:--insecure}"\n', [B_TLS]),
        (".env", "GOFLAGS=--mod=mod\n", [A_REDIR]),
        ("Dockerfile", "ENV GOPRIVATE=g\\ithub.com\n", [B_TLS]),
        # Prose in scripts and task files is not a setting.
        ("scripts/b.sh", 'echo "Set GOINSECURE to bypass"\nprintf "GOSUMDB off is bad\\n"\n', []),
        ("Taskfile.yml", "tasks:\n  b:\n    desc: GOSUMDB off for local builds\n", []),
        # Renovate JSON5 is parsed, not scanned line by line.
        ("renovate.json5", f"{{ hostRules: [{{ password: '{LIT}' /* not encrypted */ }}] }}\n", [B_TOKEN]),
        ("renovate.json5", f"{{\n  hostRules: [{{token:\n  '{LIT}'}}],\n}}\n", [B_TOKEN]),
        ("renovate.json5", f"{{ hostRules: [{{ \\u0074oken: '{LIT}' }}] }}\n", [B_TOKEN]),
        ("renovate.json5", f"{{ npmToken: '{LIT}', s: 'a\\\nb', q: 'it\\'s \"x\"' }}\n", [B_TOKEN]),
        ("renovate.json5", "{ a: 'open\n}\n", [B_UNREAD]),
        ("renovate.json5", "{ a: 'open", [B_UNREAD]),
        (".yarnrc", "registry \"http://bad\\x.example/\"\nyarn-path './y.js'\n", [B_UNREAD, A_REDIR]),
        ("renovate.json5", "{ a: 0x10 }\n", [B_UNREAD]),
        ("renovate.json5", "{ /* c */ a: 1, // d\n b: [true, null] }", []),
        ("renovate.json5", "{ a: 1 } /* unclosed", [B_UNREAD]),
        ("renovate.json", '{"hostRules": [{"token": "{{ secrets.NPM_TOKEN }}"}]}', []),
        # CDATA in a project file is character data, not a refusal.
        ("App.csproj", '<Project><Target Name="x"><Exec Command="echo"><![CDATA[a]]></Exec></Target></Project>', []),
        ("App.csproj", "<Project><RestoreSources><![CDATA[http://n.example/]]></RestoreSources></Project>", [B_HTTP]),
        (
            "nuget.config",
            '<configuration><packageSources/><packageSources><clear/><add key="a" value="http://e.example/"/></packageSources></configuration>',
            [B_HTTP],
        ),
        ("nuget.config", "<?xml version='1.0'?><configuration></configuration>", []),
        ("nuget.config", "<configuration><add key='x' value=\"unclosed/></configuration>", [B_UNREAD]),
        (
            "settings.xml",
            "<settings><servers><server><password>{COQLCE6DU6GtcS5P=}</password></server></servers></settings>",
            [],
        ),
        # Cooldown values that are no cooldown; only scripts under .yarn/releases or plugins are digested.
        (".npmrc", "min-release-age=0.0\n", [A_COOL]),
        (".npmrc", "min-release-age=-1\n", [A_COOL]),
        (".yarn/releases/README.md", "# notes\n", []),
    ],
)
def test_round_two_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


def test_line_numbers_follow_the_document_and_fall_back_to_the_last_match() -> None:
    reg_core = MODULES["reg_core"]
    ctx = reg_core.Ctx("x", "a\nb\nc\n")
    assert [reg_core.line_of(ctx, n) for n in ("b", "c", "zz", "a", "")] == [2, 3, 3, 1, 1]


def test_registry_host_from_go_proxy_uses_the_table() -> None:
    assert rules("Dockerfile", "ENV GOPROXY=https://proxy.golang.org,direct\n") == []
    assert rules("Dockerfile", "ENV GOPROXY=direct\n") == [A_REDIR]
    assert rules("Dockerfile", "ENV GOPROXY=https://evil.example\n") == [B_HOST]
