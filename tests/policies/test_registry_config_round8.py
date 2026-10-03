"""registry-config: the eighth review's reproducers: settings inside command strings, glued after them, scheme-less proxies."""

from __future__ import annotations

import time

import pytest
from policies.test_registry_config import A_REDIR, B_HOST, B_HTTP, B_TLS, mod, rules

W = ".github/workflows/x.yml"
D = ".devcontainer/devcontainer.json"


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # Inside a command string the value is the first word; the rest may be the command it prefixes.
        ("a.sh", 'sh -c "GOPRIVATE=github.com go build"\n', [B_TLS]),
        ("a.sh", 'sh -c "GOPROXY=direct go build"\n', [A_REDIR]),
        (D, '{"postCreateCommand": "GOPRIVATE=github.com go mod download"}', [B_TLS]),
        (W, '      - run: echo "GOFLAGS=-a -insecure" >> $GITHUB_ENV\n', [B_TLS]),
        (W, '      - run: echo "GOFLAGS=-mod=vendor -trimpath" >> "$GITHUB_ENV"\n', []),
        (W, '      - run: echo "GOSUMDB=sum.golang.org" >> "$GITHUB_ENV"\n', []),
        ("a.sh", 'echo "GOSUMDB=off\n', [B_TLS]),
        # Text glued after the closing quote, or passed as the next word after a trailing ',', joins the value.
        (W, '      - run: echo "GONOSUMDB=corp.example,"\'*\' >> "$GITHUB_ENV"\n', [B_TLS]),
        (W, '      - run: echo "GOPROXY=https://proxy.golang.org,"http://evil.example >> "$GITHUB_ENV"\n', [B_HTTP]),
        (W, '      - run: echo "GONOSUMDB=corp.example," "*" >> "$GITHUB_ENV"\n', [B_TLS]),
        # Go adds https:// to a proxy element with '.', ':' or '/' and no ':/'.
        ("a.sh", "export GOPROXY=evil.example\n", [B_HOST]),
        ("Dockerfile", "ENV GOPROXY=evil.example,direct\n", [B_HOST]),
        (D, '{"GOPROXY": "evil.example"}', [B_HOST]),
        (
            "Dockerfile",
            "ENV GOPROXY=https://proxy.golang.org,direct\nENV GOPROXY=off\nENV GOPROXY=file:///srv/mods\n",
            [],
        ),
        # A double-quoted YAML or JSON string's escapes are resolved as the loader resolves them.
        (W, 'env:\n  GONOSUMDB: "\\x2a"\n  GOPRIVATE: "\\u002a"\n', [B_TLS]),
        (D, '{"GOSUMDB": "\\u006fff"}', [B_TLS]),
        ("a.sh", 'GONOSUMDB="\\x2a"\n', [A_REDIR]),
    ],
)
def test_round_eight_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("a.sh", "x" + " -GONOSUMDB=a,b" * 70000),
        ("a.sh", " -GOFLAGS=-x" * 90000),
        ("compose.yaml", " -GOFLAGS=-x" * 90000),
    ],
)
def test_long_lines_of_settings_stay_linear(path: str, text: str) -> None:
    started = time.monotonic()
    assert mod.findings({"writes": {path: text}})
    assert time.monotonic() - started < 5.0
