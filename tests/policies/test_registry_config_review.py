"""registry-config: the adversarial review's reproducers, each a bypass, crash or false positive now closed."""

from __future__ import annotations

import pytest
from policies.test_registry_config import (
    A_COOL,
    A_REDIR,
    B_HOST,
    B_HTTP,
    B_SCRIPTS,
    B_TLS,
    B_TOKEN,
    B_UNREAD,
    LIT,
    mod,
    rules,
)

BOM = "\ufeff"
AGE = "min-release-age=3\n"


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # A byte order mark hides nothing: npm, Yarn and pip drop it.
        (".npmrc", BOM + "registry=http://evil.example/\n" + AGE, [B_HTTP]),
        (".npmrc", BOM + "strict-ssl=false\n" + AGE, [B_TLS]),
        (".yarnrc", BOM + 'registry "http://bom.example/"\n', [B_HTTP]),
        ("requirements.txt", BOM + "--index-url http://evil.example/simple\n", [B_HTTP]),
        # npm JSON-decodes a double-quoted value, escapes included.
        (".npmrc", 'registry="http\\u003a//evil.example/"\nstrict-ssl="f\\u0061lse"\n' + AGE, [B_HTTP, B_TLS]),
        (".npmrc", 'registry="not json\\x"\n' + AGE, []),
        # Yarn classic reads `key: value` too.
        (".yarnrc", 'registry: "http://evil.example/"\nstrict-ssl: false\n', [B_HTTP, B_TLS]),
        (".yarnrc", '@a:registry "http://evil.example/"\n', [B_HTTP]),
        # pip reads any unambiguous prefix of a long option.
        ("requirements.txt", "--index http://evil.example/simple\n", [B_HTTP]),
        ("requirements.txt", "--extra-index https://evil.example/simple\n", ["reg-confusion", B_HOST]),
        ("requirements.txt", "--trusted evil.example\n", [B_TLS]),
        ("requirements.txt", "--editable .\n--no-index\n", []),
        # Go matches GOPRIVATE/GONOSUMDB elements as globs against module path prefixes.
        (".github/workflows/b.yml", "env:\n  GONOSUMDB: github.com/*\n", [B_TLS]),
        ("Dockerfile", "ENV GONOSUMDB=*/*\n", [B_TLS]),
        (".env", "GOPRIVATE='?ithub.com'\n", [B_TLS]),
        (".env", "GOPRIVATE=[g]ithub.com\n", [B_TLS]),
        (".env", "GOPRIVATE=*.corp.example,github.com/acme/*\n", []),
        (".github/workflows/b.yml", "env: {GOSUMDB: 'off', GOFLAGS: -insecure}\n", [B_TLS]),
        ("Dockerfile", "ENV GOPROXY=https://evil.example\n", [B_HOST]),
        ("Dockerfile", "ENV GOSUMDB=sum.evil.example+abc\n", [B_HOST, A_REDIR]),
        ("Dockerfile", "ENV GOSUMDB=sum.golang.org\n", []),
        # A second source after ';' on one Gemfile line, and a gem's git source in clear text.
        ("Gemfile", 'source "https://rubygems.org"; source "http://evil.example"\n', [B_HTTP, "reg-confusion"]),
        ("Gemfile", "source 'https://rubygems.org'\ngem 'x', git: 'http://g.example/x.git'\n", [B_HTTP]),
        # XML: '>' inside a quoted attribute, attributes and spaces on Maven elements.
        (
            "nuget.config",
            '<configuration><packageSources><clear/><add key="a>b" value="http://evil.example/"/></packageSources></configuration>',
            [B_HTTP],
        ),
        (
            "settings.xml",
            "<settings><mirrors><mirror><url >http://evil.example/m2</url></mirror></mirrors></settings>",
            [B_HTTP],
        ),
        (
            "settings.xml",
            f'<settings><servers><server><password type="x">{LIT}</password></server></servers></settings>',
            [B_TOKEN],
        ),
        (
            "App.csproj",
            "<Project><PropertyGroup><RestoreSources>http://n.example/</RestoreSources></PropertyGroup></Project>",
            [B_HTTP],
        ),
        # Renovate JSON5 read line by line still sees a written-out credential.
        ("renovate.json5", f"{{\n  hostRules: [{{matchHost: 'x', token: '{LIT}'}}],\n}}\n", [B_TOKEN]),
        ("renovate.json5", "{\n  hostRules: [{encrypted: {token: 'wcFMA'}}],\n}\n", []),
        # Zero is no cooldown; pnpm overrides to a GitHub shorthand or an scp-style git URL redirect.
        (".npmrc", "min-release-age=0\n", [A_COOL]),
        (
            "pnpm-workspace.yaml",
            "overrides:\n  foo: evil/foo\n  bar: git@github.com:evil/bar.git\nminimumReleaseAge: 1\n",
            [A_REDIR],
        ),
        # go.mod: the replacement version is part of the key.
        ("go.mod", "replace a => github.com/fork/b v1.9.9\n", [A_REDIR]),
        # More files that set GO*.
        ("docker-compose.yml", "services:\n  b:\n    environment:\n      GOINSECURE: x.example\n", [B_TLS]),
        ("scripts/build.sh", "export GOFLAGS=-insecure\n", [B_TLS]),
        ("ci/build.gitlab-ci.yml", "variables:\n  GOSUMDB: 'off'\n", [B_TLS]),
    ],
)
def test_review_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # cargo-deny's default allow-registry names the crates.io git index on github.com.
        # A TOML key spelled with an escape still names the setting (the finding falls back to line 1).
        ("pyproject.toml", '[tool.uv]\n"\\u0069ndex-url" = "http://x.example/simple"\n', [B_HTTP]),
        ("deny.toml", '[sources]\nallow-registry = ["https://github.com/rust-lang/crates.io-index"]\n', []),
        ("renovate.json", '{"hostRules": [{"matchHost": "npm.pkg.github.com", "encrypted": {"token": "wcFMA"}}]}', []),
        (
            "pyproject.toml",
            '[tool.uv]\npublish-url = "https://test.pypi.org/legacy/"\ncheck-url = "https://test.pypi.org/simple"\n',
            [],
        ),
        (
            "pyproject.toml",
            '[tool.uv.sources]\nfoo = { url = "https://github.com/acme/foo/releases/download/v1/foo.whl" }\n',
            [],
        ),
        ("pyproject.toml", '[tool.uv.sources]\nfoo = { git = "http://g.example/foo" }\n', [B_HTTP]),
        (
            ".github/dependabot.yml",
            "registries:\n  gh:\n    type: git\n    url: https://github.com\n    password: ${{secrets.T}}\n"
            "updates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown: {default-days: 3}\n",
            [],
        ),
        ("requirements.txt", "--extra-index-url https://download.pytorch.org/whl/cu121\n", ["reg-confusion"]),
    ],
)
def test_review_false_positives_are_gone(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


def test_deep_toml_is_refused_not_a_crash() -> None:
    assert rules(".cargo/config.toml", "x = " + "[" * 3000 + "]" * 3000 + "\n") == [B_UNREAD]


@pytest.mark.parametrize(
    "text",
    [
        '{"repositories": {"1": {"url": "https://evil.example"}}}',
        '{"repositories": [[{"url": "https://e.example"}], 3]}',
    ],
)
def test_composer_repository_shapes_never_crash(text: str) -> None:
    found = rules("composer.json", text)
    assert found in ([B_HOST], [])


def test_yarn_releases_are_digested_whatever_their_size() -> None:
    text = "x" * (mod.MAX_TEXT + 5)
    assert rules(".yarn/releases/yarn-4.5.0.cjs", text) == [A_REDIR]
    assert rules(".yarn/plugins/@yarnpkg/plugin-x.cjs", "module.exports = {}\n") == [A_REDIR]


def test_scripts_rule_constant_is_used() -> None:
    assert rules(".npmrc", "ignore-scripts=false\n" + AGE) == [B_SCRIPTS]
