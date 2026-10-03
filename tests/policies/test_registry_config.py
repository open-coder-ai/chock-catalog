"""registry-config: each reader's findings, one row per setting shape, refused and allowed."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest
from policies import scriptkit

NAME = "registry-config-gate.py"
SCAN = "chock_scan"


def load_gate() -> tuple[ModuleType, dict[str, ModuleType]]:
    """The gate and its reg_* modules, imported against the chock_scan copy it ships. tests/chock_scan is
    also a package named chock_scan, so any already imported is set aside and put back afterwards, and the
    folder the gate puts on sys.path is taken off again."""
    saved = {name: sys.modules.pop(name) for name in list(sys.modules) if name.split(".")[0] == SCAN}
    for name in [n for n in sys.modules if n.startswith("reg_")]:
        # A second load (xdist may import this file under two names) must not reuse readers bound to the first copy.
        del sys.modules[name]
    path = list(sys.path)
    try:
        gate = scriptkit.load("registry-config", NAME)
    finally:
        sys.path[:] = path
        for name in [n for n in sys.modules if n.split(".")[0] == SCAN]:
            del sys.modules[name]
        sys.modules.update(saved)
    return gate, {name: sys.modules[name] for name in ("reg_core", "reg_hosts")}


mod, MODULES = load_gate()

# Credentials in fixtures are short and dotted so no secret scanner reads them as real ones.
LIT = "lit3.d9f"
NPM_OK = "min-release-age=3\n"


def rules(path: str, text: str) -> list[str]:
    found = mod.findings({"event": "commit", "repo_root": "/nonexistent", "writes": {path: text}})
    return sorted({f["rule"] for f in found})


B_TOKEN, B_HTTP, B_TLS, B_SCRIPTS, B_HOST, B_UNREAD = (
    "reg-npmrc-token",
    "reg-http-registry",
    "reg-tls-off",
    "reg-script-allow-weaken",
    "reg-registry-host",
    "reg-unreadable",
)
A_CONF, A_REDIR, A_COOL, A_VCS, A_IND = (
    "reg-confusion",
    "reg-overrides-redirect",
    "reg-cooldown-absent",
    "reg-vcs-weaken",
    "reg-indirect",
)


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # npm
        (".npmrc", f"_authToken={LIT}\n" + NPM_OK, [B_TOKEN]),
        (".npmrc", "//r.example/:_password=${PW}\n" + NPM_OK, []),
        (".npmrc", "registry=https://registry.npmjs.org/ ; comment\n" + NPM_OK, []),
        (".npmrc", "@a:registry='http://10.0.0.5/'\n" + NPM_OK, [B_HTTP]),
        (".npmrc", "registry=http://127.0.0.1:4873/\n" + NPM_OK, []),
        (".npmrc", "registry=http://[::1]:4873/\n" + NPM_OK, []),
        (".npmrc", "registry=https://verdaccio.localhost/\n" + NPM_OK, []),
        (".npmrc", "registry=https:\\\\evil.example\n" + NPM_OK, [B_UNREAD]),
        (".npmrc", "registry=./local-dir\n" + NPM_OK, []),
        (".npmrc", "registry=file://tmp/r\n" + NPM_OK, []),
        (".npmrc", "registry=https://user@registry.npmjs.org/\n" + NPM_OK, []),
        (".npmrc", "registry=https://u:${PW}@registry.npmjs.org/\n" + NPM_OK, []),
        (".npmrc", "strict-ssl\n" + NPM_OK, []),
        (".npmrc", "strict-ssl=true\n" + NPM_OK, []),
        (".npmrc", "ignore-scripts=false\n" + NPM_OK, [B_SCRIPTS]),
        (".npmrc", "ignore-scripts=true\n" + NPM_OK, []),
        (".npmrc", "script-shell=/bin/sh\n" + NPM_OK, [B_SCRIPTS]),
        (".npmrc", "unsafe-perm=true\n" + NPM_OK, [B_SCRIPTS]),
        (".npmrc", "dangerously-allow-all-builds=true\n" + NPM_OK, [B_SCRIPTS]),
        (".npmrc", "strict-dep-builds=false\nblock-exotic-subdeps=false\n" + NPM_OK, [B_SCRIPTS]),
        (".npmrc", "trust-policy=off\n" + NPM_OK, [B_SCRIPTS]),
        (".npmrc", "only-built-dependencies[]=*\n" + NPM_OK, [B_SCRIPTS]),
        (".npmrc", "only-built-dependencies[]=esbuild\n" + NPM_OK, []),
        (".npmrc", "pnpmfile=hooks.cjs\n" + NPM_OK, [A_REDIR]),
        (".npmrc", "# strict-ssl=false\n; x\n[section]\n=novalue\n" + NPM_OK, []),
        (".npmrc", "save-exact=true\n", [A_COOL]),
        ("npmrc", "minimum-release-age=1440\n", []),
        # Yarn classic
        (".yarnrc", 'registry "http://r.example/"\n', [B_HTTP]),
        (".yarnrc", '"@a:registry" "https://registry.yarnpkg.com"\n', []),
        (".yarnrc", "strict-ssl false\n", [B_TLS]),
        (".yarnrc", "strict-ssl true\n", []),
        (".yarnrc", "yarn-path ./x.js\n", [A_REDIR]),
        (".yarnrc", f"_authToken {LIT}\n", [B_TOKEN]),
        (".yarnrc", "--ignore-scripts false\n# registry http://x\nlonely\n", [B_SCRIPTS]),
        # Yarn berry
        (".yarnrc.yml", "npmRegistryServer: http://r.example\nnpmMinimalAgeGate: 3d\n", [B_HTTP]),
        (".yarnrc.yml", f"npmScopes:\n  a:\n    npmAuthToken: {LIT}\nnpmMinimalAgeGate: 3d\n", [B_TOKEN]),
        (".yarnrc.yml", "npmAuthIdent: ${YARN_IDENT}\nnpmMinimalAgeGate: 3d\n", []),
        (".yarnrc.yml", "enableStrictSsl: false\nnpmMinimalAgeGate: 3d\n", [B_TLS]),
        (".yarnrc.yml", "enableStrictSsl: true\nenableScripts: false\nnpmMinimalAgeGate: 3d\n", []),
        (".yarnrc.yml", "unsafeHttpWhitelist:\n  - r.example\nnpmMinimalAgeGate: 3d\n", [B_TLS]),
        (".yarnrc.yml", "plugins:\n  - path: .yarn/plugins/p.cjs\nnpmMinimalAgeGate: 3d\n", [A_REDIR]),
        (".yarnrc.yml", "nodeLinker: pnp\n", [A_COOL]),
        (".yarnrc.yml", "a: [unclosed\n", [B_UNREAD]),
        (".yarnrc.yml", "base: &b 1\nother: *b\nnpmMinimalAgeGate: 3d\n", [A_IND]),
        # pnpm workspace
        ("pnpm-workspace.yaml", "registry: http://r.example\nminimumReleaseAge: 1440\n", [B_HTTP]),
        ("pnpm-workspace.yaml", "registries:\n  '@a': https://r.example\nminimumReleaseAge: 1\n", [B_HOST]),
        ("pnpm-workspace.yaml", "strictSsl: false\nminimumReleaseAge: 1\n", [B_TLS]),
        ("pnpm-workspace.yaml", "strictSsl: true\npnpmfile: ''\nminimumReleaseAge: 1\n", []),
        ("pnpm-workspace.yaml", "pnpmfile: hooks.cjs\nminimumReleaseAge: 1\n", [A_REDIR]),
        ("pnpm-workspace.yaml", "overrides:\n  lodash: npm:evil@1\n  a: 1.2.3\nminimumReleaseAge: 1\n", [A_REDIR]),
        ("pnpm-workspace.yaml", "onlyBuiltDependencies:\n  - '*'\nminimumReleaseAge: 1\n", [B_SCRIPTS]),
        ("pnpm-workspace.yaml", "catalogs:\n  x:\n    deep:\n      key: v\nminimumReleaseAge: 1\n", []),
        ("pnpm-workspace.yaml", "a: [x\n", [B_UNREAD]),
        (".pnpmfile.cjs", "module.exports = {hooks: {}}\n", [A_REDIR]),
        # Bun
        ("bunfig.toml", '[install]\nregistry = "http://r.example"\nminimumReleaseAge = 1\n', [B_HTTP]),
        (
            "bunfig.toml",
            '[install.registry]\nurl = "https://registry.npmjs.org"\ntoken = "$T"\n[install]\nminimumReleaseAge = 1\n',
            [],
        ),
        ("bunfig.toml", '[install.scopes]\na = "https://r.example"\n', [A_COOL, B_HOST]),
        ("bunfig.toml", '[install]\ncache = ["a"]\nminimumReleaseAge = 1\n', []),
        ("bunfig.toml", "[test]\nroot = '.'\n", []),
        (".bunfig.toml", f'[install.scopes.a]\npassword = "{LIT}"\n[install]\nminimumReleaseAge = 1\n', [B_TOKEN]),
    ],
)
def test_npm_family(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        ("requirements.txt", "-i http://p.example/simple\nx==1\n", [B_HTTP]),
        ("requirements-dev.txt", "--index-url=https://pypi.org/simple\n", []),
        ("dev-requirements.in", "-ihttps://evil.example/simple\n", [B_HOST]),
        ("requirements/base.txt", "--extra-index-url https://pypi.org/simple # c\n", [A_CONF]),
        ("constraints.txt", "--trusted-host p.example\n", [B_TLS]),
        ("requirements.txt", "-f ./wheels\n--find-links http://w.example/\n", [B_HTTP]),
        ("requirements.txt", "x==1 \\\n  --index-url http://p.example \\\n", [B_HTTP]),
        ("requirements.txt", "# --index-url http://p.example\n", []),
        (
            "pip.conf",
            "[global]\nextra-index-url =\n  https://pypi.org/simple\n  https://evil.example/s\n",
            [A_CONF, B_HOST],
        ),
        ("pip.conf", "[install]\nfind_links = https://evil.example/w\ntimeout = 3\n", []),
        ("pip.conf", "not an ini\n", [B_UNREAD]),
        (".pypirc", f"[pypi]\npassword = {LIT}\nrepository = http://up.example/\n", [B_HTTP, B_TOKEN]),
        (".pypirc", "[pypi]\npassword = ${TWINE_PASSWORD}\nusername = __token__\n", []),
        (".pypirc", "[x\n", [B_UNREAD]),
        ("uv.toml", 'index-strategy = "unsafe-best-match"\n', [A_CONF]),
        ("uv.toml", 'index-strategy = "first-index"\n[[index]]\nurl = "https://pypi.org/simple"\n', []),
        ("uv.toml", '[pip]\nextra-index-url = ["https://pypi.org/simple"]\n', [A_CONF]),
        ("uv.toml", "x = [\n", [B_UNREAD]),
        ("pyproject.toml", '[[tool.poetry.source]]\nname = "x"\nurl = "http://p.example/simple"\n', [B_HTTP]),
        ("pyproject.toml", '[tool.poetry]\nname = "x"\n', []),
        ("pyproject.toml", '[[tool.pdm.source]]\nurl = "https://pypi.org/simple"\nverify_ssl = false\n', [B_TLS]),
        ("pyproject.toml", f'[tool.uv]\npassword = "{LIT}"\n', [B_TOKEN]),
        ("pyproject.toml", '[project]\nname = "x"\n', []),
        ("pyproject.toml", "[tool]\nother = 1\n", []),
        ("pyproject.toml", "bad = \n", [B_UNREAD]),
        ("Pipfile", '[[source]]\nurl = "https://pypi.org/simple"\nverify_ssl = true\n', []),
        (
            "Pipfile",
            '[[source]]\nurl = "https://pypi.org/simple"\n[[source]]\nurl = "https://pypi.org/simple"\n',
            [A_CONF],
        ),
        ("Pipfile", "[packages]\nx = '*'\n", []),
        (".condarc", "channels:\n  - http://c.example/x\nchannel_alias: https://conda.anaconda.org\n", [B_HTTP]),
        (".condarc", "ssl_verify: true\ncustom_channels:\n  x: https://evil.example\n", [B_HOST]),
        (
            "environment.yml",
            "channels:\n  - conda-forge\ndependencies:\n  - pip:\n    - --extra-index-url https://pypi.org/simple\n",
            [A_CONF],
        ),
        ("environment.yml", "name: x\n", []),
        ("environment.yml", "a: [\n", [B_UNREAD]),
    ],
)
def test_python_family(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        ("go.mod", "module m\nreplace a/b => ./local\n", [A_REDIR]),
        ("go.mod", "module m\nreplace a/b v1.0.0 => a/b v1.0.1\n", []),
        ("go.work", "replace (\n  a/b => ../b // fork\n  c/d v1 => e/f v2\n\n)\nrequire x v1\n", [A_REDIR]),
        ("Dockerfile.build", "ARG GOINSECURE\nENV GOPROXY direct\n", [A_REDIR]),
        ("build.dockerfile", "ENV GOPROXY=http://proxy.example,https://proxy.golang.org\n", [B_HTTP]),
        ("Makefile", "GOFLAGS := -mod=mod\n# GOSUMDB=off\n", [A_REDIR]),
        ("ci.mk", "export GOPRIVATE=*.com\n", [B_TLS]),
        (".env.local", "GONOSUMCHECK=github.com\n", [B_TLS]),
        ("app.env", "GOPRIVATE=*.corp.example,github.com/acme\nGOSUMDB=sum.golang.org\n", []),
        (".envrc", "echo ${GOINSECURE}\nGOINSECURE=\n", []),
        ("go.env", "GOFLAGS=-mod=readonly\nGOPROXY=https://proxy.golang.org,direct\n", []),
        (".gitlab-ci.yml", "variables:\n  GONOSUMDB: '*'\n", [B_TLS]),
        (".circleci/config.yml", "environment:\n  GOPROXY: off\n", []),
        ("Jenkinsfile", "  // GOINSECURE=x\n", []),
    ],
)
def test_go(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))
