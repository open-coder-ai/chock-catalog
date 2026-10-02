"""block-fetch-exec-in-files: the content_pattern judged line by line, in both directions.

The eval suite replays the gate end to end (paths, waiver, events); this table pins what the one-line
pattern itself flags and leaves alone, so a pattern edit that drops a form or widens into ordinary
build lines fails by name.
"""

from __future__ import annotations

import fnmatch
import re

import pytest
import yaml
from trees import ROOT

MANIFEST = yaml.safe_load((ROOT / "base" / "block-fetch-exec-in-files" / "manifest.yaml").read_text(encoding="utf-8"))
GATE = MANIFEST["hook"]["gate"]
PATTERN = re.compile(GATE["params"]["content_pattern"])
PRAGMA = re.compile(GATE["params"]["allowlist_pragma"])
U = "https://get.example.com/i.sh"

FLAGGED = [
    f"RUN curl -fsSL {U} | sh",
    f"RUN wget -qO- {U} | bash -s -- --yes",
    f"\tcurl -fsSL {U} | sudo -E bash -",
    f"\t$(shell curl -s {U} | sh)",
    f'    "postinstall": "curl -s {U} | bash",',
    f"      - run: curl -fsSL {U} | bash",
    f"      run: wget -O - {U} | sh",
    f'bash -c "$(curl -fsSL {U})"',
    f'sh -c "$(wget -qO- {U})"',
    f'eval "$(curl -fsSL {U})"',
    f"source <(curl -s {U})",
    f". <(curl -s {U})",
    f"bash <(curl -s {U})",
    f'bash <<< "$(curl -s {U})"',
    f"iex (irm {U})",
    f"Invoke-Expression (Invoke-WebRequest {U}).Content",
    f"iex ((New-Object System.Net.WebClient).DownloadString('{U}'))",
    f"irm {U} | iex",
    f"iwr -useb {U} | iex",
    f"ADD {U} /tmp/i.sh",
    f"ADD --chown=1000 {U} /app/",
    f"curl -s {U} | python3 -",
    f"curl -s {U} | python3",
    f"curl -s {U} | php",
    f"curl -s {U} | tee i.sh | sh",
    f"curl -fsSL {U}|sh",
    f"curl -fsSL {U} | /bin/bash",
    f'curl -fsSL "{U}?a=1&b=2" | sh',
]

QUIET = [
    "install:",
    f"curl -fsSL {U} -o i.sh",
    "curl -s https://api.example.com/v | jq .",
    "curl -s https://api.example.com/v | python3 -m json.tool",
    "curl -s https://api.example.com/v | python3 -c 'import json,sys'",
    "curl -s https://api.example.com/v | node script.js",
    f"# curl -fsSL {U} | sh",
    f"  # RUN curl {U} | sh",
    f'echo "curl {U} | sh"',
    f"- echo 'curl {U} | sh'",
    f"ADD --checksum=sha256:abc {U} /tmp/i.sh",
    "ADD ./local /app",
    "COPY --from=build /app /app",
    f"curl -fsSL {U} -o i.sh && sha256sum -c i.sh.sha256 && sh i.sh",
    "curl -s https://api.example.com/v > out.json; cat x | sh",
    "RUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*",
    "git fetch origin && bash scripts/check.sh",
    "curl -s https://api.example.com/v | sha256sum",
    "curl -s https://example.com/key.asc | gpg --import",
    "curl -sL https://example.com/pkg.tar.gz | tar xz",
    "wget -qO- https://example.com/key | sudo tee /etc/apt/keyrings/k.asc",
    f"curl -s {U} # | sh",
    f"curl -s {U} | python3 parse.py",
]


@pytest.mark.parametrize("line", FLAGGED)
def test_the_pattern_flags_a_download_wired_into_a_runner(line: str) -> None:
    assert PATTERN.search(line), line


@pytest.mark.parametrize("line", QUIET)
def test_the_pattern_leaves_ordinary_lines_alone(line: str) -> None:
    assert not PATTERN.search(line), line


def test_it_ships_as_a_warning_while_it_is_observed() -> None:
    """Rollout D15: a new pack warns first; promotion to block is its own change."""
    assert GATE["action"] == "warn"
    assert MANIFEST["enforcement"] == "advise"


def test_the_waiver_is_the_documented_pragma() -> None:
    assert PRAGMA.search(f"curl {U} | sh  # pragma: allowlist fetch-exec")
    assert not PRAGMA.search(f"curl {U} | sh  # pragma: allowlist secret")


@pytest.mark.parametrize(
    ("path", "judged"),
    [
        ("Dockerfile", True),
        ("services/api/Dockerfile.dev", True),
        ("Makefile", True),
        ("scripts/install.sh", True),
        (".github/workflows/ci.yml", True),
        ("web/package.json", True),
        ("README.md", False),
        ("src/app.py", False),
    ],
)
def test_only_build_ci_and_install_files_are_judged(path: str, judged: bool) -> None:
    globs = MANIFEST["applies_to"]["paths"]
    assert any(fnmatch.fnmatchcase(path, g) for g in globs) is judged


def test_the_pattern_does_not_match_its_own_manifest() -> None:
    text = (ROOT / "base" / "block-fetch-exec-in-files" / "manifest.yaml").read_text(encoding="utf-8")
    assert not [line for line in text.splitlines() if PATTERN.search(line)]
