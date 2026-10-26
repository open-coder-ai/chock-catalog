"""registry-config: added coverage for long URL values, remote file: sources and scheme-less UNC values."""

from __future__ import annotations

import pytest
from policies.test_registry_config import B_HOST, B_UNREAD, NPM_OK, rules

LONG_PAD = "a" * 183


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # A second '@' after an allowed host, past the 200th character, is still read.
        ("requirements.txt", f"--index-url https://{LONG_PAD}@pypi.org@other.example/simple\n", [B_UNREAD]),
        (".npmrc", f"registry=https://{'a' * 173}@registry.npmjs.org@other.example/\n" + NPM_OK, [B_UNREAD]),
        (".npmrc", f"registry=https://registry.npmjs.org/{'a' * 300}\n" + NPM_OK, []),
        (".npmrc", f"registry=https://{'a' * 300}.example/\n" + NPM_OK, [B_UNREAD]),
        # file: is local only with an empty host or localhost.
        (".npmrc", "registry=file://tmp/r\n" + NPM_OK, [B_HOST]),
        (".npmrc", "registry=file://pkgs.remote.example/feed\n" + NPM_OK, [B_HOST]),
        (".npmrc", "registry=file:///srv/r\n" + NPM_OK, []),
        (".npmrc", "registry=file://localhost/srv/r\n" + NPM_OK, []),
        ("requirements.txt", "--index-url file://pkgs.remote.example/simple\n", [B_HOST]),
        ("requirements.txt", "--index-url file:///srv/simple\n", []),
        (
            "nuget.config",
            '<configuration><packageSources><clear />\n<add key="c" value="file://pkgs.remote.example/feed"/>\n</packageSources></configuration>\n',
            [B_HOST],
        ),
        # Scheme-less UNC values name a remote host too.
        ("requirements.txt", "--index-url '\\\\pkgs.remote.example\\feed'\n", [B_HOST]),
        (".npmrc", "registry=//pkgs.remote.example/feed\n" + NPM_OK, [B_HOST]),
        (".npmrc", "registry=\\\\registry.npmjs.org\\feed\n" + NPM_OK, []),
        (".npmrc", "registry=./local-dir\n" + NPM_OK, []),
        # Go proxy list
        ("a.sh", "export GOPROXY=file://pkgs.remote.example/p,direct\n", [B_HOST]),
        ("a.sh", "export GOPROXY=file:///srv/goproxy\n", []),
    ],
)
def test_sr2d2_cases(path: str, text: str, want: list[str]) -> None:
    got = rules(path, text)
    assert [r for r in got if r in (B_HOST, B_UNREAD)] == sorted(set(want))
