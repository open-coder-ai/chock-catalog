"""registry-config: the sixth review's reproducers: outer quotes, empty values, quoted glued tails, JSON keys."""

from __future__ import annotations

import pytest
from policies.test_registry_config import A_REDIR, B_HOST, B_TLS, B_UNREAD, rules

W = ".github/workflows/x.yml"
D = ".devcontainer/devcontainer.json"


@pytest.mark.parametrize(
    ("path", "text", "want"),
    [
        # A quote the value opens and never closes belongs to an outer string.
        (W, 'jobs:\n  b:\n    steps:\n      - run: echo "GOSUMDB=off" >> $GITHUB_ENV\n', [B_TLS]),
        (W, "      - run: echo 'GOINSECURE=*' >> $GITHUB_ENV\n", [B_TLS]),
        (W, '      - run: echo "GOPROXY=https://proxy.golang.org,direct" >> $GITHUB_ENV\n', []),
        (W, '      - run: echo "GOFLAGS=-mod=vendor" >> $GITHUB_ENV\n', []),
        ("Dockerfile", 'ENV ["GOSUMDB=off"]\n', [B_TLS]),
        # An empty value followed by a comment is empty.
        ("b.sh", "export GOSUMDB= # use default\n", []),
        (".env", "GOSUMDB= # default\n", []),
        (W, "env:\n  GOSUMDB: # default\n", []),
        # A quoted piece glued to the value stays part of the shell word.
        ("b.sh", 'export GONOSUMDB=corp.example#" x",*\n', [B_TLS]),
        ("b.sh", 'export GOPROXY=https://proxy.golang.org#" x",https://evil.example\n', [B_HOST]),
        ("b.sh", "GOSUMDB=a#" + "y" * 5000 + "\n", [B_UNREAD]),
        ("b.sh", "export GONOSUMDB=#,*\n", [B_TLS]),
        # Values are judged whole, however long.
        ("b.sh", "export GONOSUMDB=" + ",".join(f"corp{i}.example" for i in range(20)) + ",*\n", [B_TLS]),
        ("b.sh", "GOFLAGS='" + "-trimpath " * 25 + "-insecure'\n", [B_TLS]),
        ("b.sh", "GOSUMDB=" + "x" * 300 + "$X\n", [A_REDIR]),
        # JSON files: each key's value is exactly its JSON string, minified or not.
        (D, '{"containerEnv":{"GOSUMDB":"off","GONOSUMDB":"*"}}', [B_TLS]),
        (D, '{"remoteEnv":{"GOSUMDB":"sum.golang.org","X":"y"}}', []),
        (D, '{\n  "remoteEnv": {\n    "GOPRIVATE": "${localEnv:GOPRIVATE}",\n    "X": "y"\n  }\n}\n', []),
        ("compose.yaml", 'services:\n  b:\n    environment: {"GOSUMDB":"off"}\n', [B_TLS]),
    ],
)
def test_round_six_bypasses_are_closed(path: str, text: str, want: list[str]) -> None:
    assert rules(path, text) == sorted(set(want))
