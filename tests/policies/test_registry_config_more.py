"""registry-config: Cargo, NuGet, Maven, Ruby, PHP, Elixir, Apple and update-bot readers."""

from __future__ import annotations

import pytest
from policies.test_registry_config import (
    A_CONF,
    A_COOL,
    A_IND,
    A_REDIR,
    A_VCS,
    B_HOST,
    B_HTTP,
    B_SCRIPTS,
    B_TLS,
    B_TOKEN,
    B_UNREAD,
    LIT,
    rules,
)

NUGET_HEAD = '<configuration>\n<packageSources>\n<clear/>\n<add key="n" value="https://api.nuget.org/v3/index.json"/>\n'
NUGET_TAIL = "</packageSources>\n</configuration>\n"


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        (".cargo/config.toml", '[registries.x]\nindex = "sparse+https://evil.example/"\n', [B_HOST]),
        (".cargo/config", f'[registry]\ntoken = "{LIT}"\n', [B_TOKEN]),
        (".cargo/config.toml", '[source.x]\ngit = "git://g.example/r"\n', [B_HTTP]),
        (".cargo/config.toml", "[http]\ncheck-revoke = false\n", [B_TLS]),
        (".cargo/config.toml", "[http]\ncheck-revoke = true\nproxy = 'x'\n", []),
        (".cargo/config.toml", '[build]\nrustc-wrapper = "sccache"\njobs = 4\n', [A_REDIR]),
        (".cargo/config.toml", '[target.x86_64-unknown-linux-gnu]\nlinker = "clang"\nrustflags = ["-C"]\n', [A_REDIR]),
        (".cargo/config.toml", '[target.x]\nrunner = ["qemu", "-L"]\n', [A_REDIR]),
        (".cargo/config.toml", '[alias]\nxtask = "run -p xtask --"\n[env]\nA = "1"\n', [A_REDIR]),
        (".cargo/config.toml", "[net\n", [B_UNREAD]),
        (".cargo/config.toml", '[source.vendored]\ndirectory = "vendor"\n', []),
        (".cargo/config.toml", '[patch.crates-io]\nserde = { git = "http://g.example/serde" }\n', [A_REDIR, B_HTTP]),
        ("deny.toml", '[sources]\nunknown-registry = "allow"\nunknown-git = "deny"\n', [A_CONF]),
        (
            "deny.toml",
            '[sources]\nallow-registry = ["https://evil.example/index"]\nallow-git = ["http://g.example/r"]\n',
            [B_HTTP],
        ),
        ("deny.toml", "[advisories]\nyanked = 'deny'\n", []),
        ("deny.toml", "x = \n", [B_UNREAD]),
    ],
)
def test_cargo(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        ("nuget.config", NUGET_HEAD + NUGET_TAIL, []),
        (
            "NuGet.Config",
            NUGET_HEAD
            + '<add key="m" value="http://n.example/v3/index.json" allowInsecureConnections="true"/>\n'
            + NUGET_TAIL,
            [A_CONF, B_HTTP, B_TLS],
        ),
        ("nuget.config", NUGET_HEAD + "<!-- <add key='x' value='http://n.example/'/> -->\n" + NUGET_TAIL, []),
        ("nuget.config", NUGET_HEAD + '<add key="m" value="https://n&#46;example/"/>\n' + NUGET_TAIL, [A_CONF, B_HOST]),
        ("nuget.config", "<configuration><packageSources/></configuration>\n", []),
        ("nuget.config", NUGET_HEAD + NUGET_TAIL + "<!-- open\n", [B_UNREAD]),
        ("nuget.config", "<!DOCTYPE x [<!ENTITY e 'http://h'>]>\n" + NUGET_HEAD + NUGET_TAIL, [B_UNREAD]),
        ("nuget.config", NUGET_HEAD + NUGET_TAIL + "<![CDATA[x]]>\n", [B_UNREAD]),
        (
            "nuget.config",
            f'<config><add key="http_proxy.password" value="{LIT}"/><add key="Username" value="u"/></config>\n',
            [B_TOKEN],
        ),
        ("nuget.config", "<config><add key='signatureValidationMode' value='accept'/></config>\n", [B_TLS]),
        ("nuget.config", "<config><add key='signatureValidationMode' value='require'/><add value='x'/></config>\n", []),
        (
            "Directory.Build.props",
            "<Project><PropertyGroup><RestoreSources>https://api.nuget.org/v3/index.json;http://n.example/</RestoreSources></PropertyGroup></Project>\n",
            [B_HTTP],
        ),
        ("directory.build.targets", "<Project><!-- unclosed\n", [B_UNREAD]),
        (
            "settings.xml",
            f"<settings><servers><server><password>{LIT}</password></server></servers>\n<mirrors><mirror><url>https://repo1.maven.org/maven2</url></mirror></mirrors></settings>\n",
            [B_TOKEN],
        ),
        (
            "settings.xml",
            "<settings><servers><server><password>${env.MVN_PW}</password></server></servers></settings>\n",
            [],
        ),
        ("settings.xml", "<application><url>http://x.example</url></application>\n", []),
    ],
)
def test_xml(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        ("Gemfile", "source 'https://rubygems.org'\nsource 'https://gems.example' do\n  gem 'x'\nend\n", [B_HOST]),
        ("Gemfile", "source 'https://rubygems.org'\nsource('https://rubygems.org')\n", [A_CONF]),
        ("gems.rb", "# source 'http://x'\ngem 'a', source: 'https://rubygems.org'\n", []),
        # Ruby interpolation inside a URL is read as written (it ends at the quote or '#'): refused, never guessed.
        ("Gemfile", "source \"https://#{ENV['T']}@gems.example\"\n", [B_UNREAD]),
        ("Gemfile", f"source 'https://u:{LIT}@rubygems.org'\n", [B_TOKEN]),
        (
            "composer.json",
            '{"repositories": [{"type": "composer", "url": "https://evil.example"}, {"type": "vcs", "url": "http://g.example/r"}]}',
            [B_HOST, B_HTTP],
        ),
        ("composer.json", '{"repositories": {"a": {"url": "https://repo.packagist.org"}, "packagist.org": false}}', []),
        ("composer.json", '{"config": {"disable-tls": true, "secure-http": true}}', [B_TLS]),
        (
            "composer.json",
            f'{{"config": {{"http-basic": {{"h": {{"username": "u", "password": "{LIT}"}}}}}}}}',
            [B_TOKEN],
        ),
        ("composer.json", '{"config": {"allow-plugins": true}}', [A_CONF]),
        ("composer.json", '{"config": {"allow-plugins": {"*": true, "a/b": false}}}', [A_CONF]),
        ("composer.json", '{"config": {"allow-plugins": {"a/b": true}, "sort-packages": true}}', []),
        ("composer.json", '{"name": "x", "config": 1}', []),
        ("composer.json", "[1]", []),
        ("composer.json", '{"a": 1, "a": 2}', [A_IND]),
        ("composer.json", "{", [B_UNREAD]),
        ("mix.exs", "  hex: [unsafe_https: true]\n", [B_TLS]),
        (
            "mix.exs",
            '  repo: "http://hex.example/repo"\n  homepage_url: "http://docs.example"\n# repo: "http://x"\n',
            [B_HTTP],
        ),
        ("mix.exs", '  repo: "https://hex.example/repo"\n', []),
        ("Podfile", "source 'http://specs.example/Specs.git'\nsource 'https://github.com/acme/Specs.git'\n", [B_HTTP]),
        (
            "Package.swift",
            '    .package(url: "http://g.example/a.git", from: "1.0.0"),\n// .package(url: "http://x")\n',
            [B_HTTP],
        ),
        (
            "Package.swift",
            '    .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),\nlet x = "http://y"\n',
            [],
        ),
    ],
)
def test_misc(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


DEPENDABOT = (
    "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown:\n      default-days: 3\n"
)


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        (".github/dependabot.yml", DEPENDABOT, []),
        (".github/dependabot.yaml", "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n", [A_COOL]),
        (
            ".github/dependabot.yml",
            DEPENDABOT + "    ignore:\n      - dependency-name: '*'\n      - dependency-name: 'a'\n",
            [A_VCS],
        ),
        (".github/dependabot.yml", DEPENDABOT + "    insecure-external-code-execution: deny\n", []),
        (
            ".github/dependabot.yml",
            "registries:\n  r:\n    type: npm-registry\n    url: http://r.example\n    token: ${{secrets.T}}\n"
            + DEPENDABOT,
            [B_HTTP],
        ),
        (
            ".github/dependabot.yml",
            f"registries:\n  r:\n    url: https://registry.npmjs.org\n    password: {LIT}\n" + DEPENDABOT,
            [B_TOKEN],
        ),
        (".github/dependabot.yml", "updates: [\n", [B_UNREAD]),
        ("renovate.json", '{"postUpgradeTasks": {"commands": ["make gen"]}, "automerge": false}', [B_SCRIPTS]),
        (
            ".renovaterc",
            '{"packageRules": [{"automerge": true}], "registryUrls": ["https://evil.example"]}',
            [A_VCS, B_HOST],
        ),
        (".renovaterc.json", f'{{"hostRules": [{{"matchHost": "h", "token": "{LIT}", "username": "u"}}]}}', [B_TOKEN]),
        ("renovate.json5", '{"automerge": true}', [A_VCS]),
        (
            "renovate.json5",
            "{\n  // c\n  automerge: true,\n  postUpgradeTasks: {commands: ['x']},\n  registryUrls: [\n    'http://r.example',\n  ],\n  x: 'http://y',\n}\n",
            [A_VCS, B_HTTP, B_SCRIPTS],
        ),
        (".renovaterc.json5", "{extends: ['config:recommended']}\n", []),
        ("renovate.json", "{", [B_UNREAD]),
    ],
)
def test_bots(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))
