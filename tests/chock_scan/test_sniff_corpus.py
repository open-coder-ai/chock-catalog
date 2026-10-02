"""chock_scan.sniff over real files (corpus/), renamed and re-encoded copies, seeded random input, and hostile sizes.

corpus/upstream/ is vendored at pinned commits (corpus/SOURCES.txt says from where, under which
licence); corpus/own/ is copied from this repository. Hypothesis is not a dev dependency here,
so the property cases draw from a seeded generator and a failure reproduces from its seed.
"""

from __future__ import annotations

import codecs
import random
import time
from pathlib import Path
from types import ModuleType

import pytest

CORPUS = Path(__file__).parent / "corpus"
EXPECTED = {
    "own/gha-stale.yml": {"github-actions": "high"},
    "own/shell-block-curl-pipe-sh.sh": {"script": "high", "shell": "high"},
    "own/unknown-claude-settings.json": {},
    "own/unknown-pyproject.toml": {},
    "upstream/ansible-drupal-playbook.yml": {"ansible": "high"},
    "upstream/ansible-first-playbook.yml": {"ansible": "high"},
    "upstream/cfn-compliant-bucket.json": {"cloudformation": "medium"},
    "upstream/cfn-compliant-bucket.yaml": {"cloudformation": "medium"},
    "upstream/compose-nginx-flask-mysql.yaml": {"compose": "medium"},
    "upstream/dockerfile-flask-backend": {"dockerfile": "high"},
    "upstream/dockerfile-python-3.13-slim-bookworm": {"dockerfile": "high"},
    "upstream/k8s-frontend-deployment.yaml": {"kubernetes": "high"},
    "upstream/k8s-guestbook-all-in-one.yaml": {"kubernetes": "high"},
    "upstream/openapi-petstore.yaml": {"openapi": "high"},
    "upstream/sam-api-endpointconfiguration.yaml": {"cloudformation": "high"},
}
FILES = sorted(EXPECTED)
DECOY_NAMES = ["build.txt", "notes.conf", "data", "README", "x.md", ".hidden", "settings.ini"]
SEEDS = range(40)
LIMIT = 1 << 20


def _kinds(result: object) -> dict[str, str]:
    return {c.kind: c.confidence for c in result.candidates}  # type: ignore[attr-defined]


def test_every_corpus_file_has_an_expectation() -> None:
    on_disk = {p.relative_to(CORPUS).as_posix() for p in CORPUS.rglob("*") if p.is_file()}
    assert on_disk - {"SOURCES.txt"} == set(EXPECTED)


@pytest.mark.parametrize("name", FILES)
def test_corpus_file(sn: ModuleType, name: str) -> None:
    result = sn.sniff((CORPUS / name).read_bytes())
    assert result.content == "text"
    assert _kinds(result) == EXPECTED[name]


@pytest.mark.parametrize("name", FILES)
def test_a_renamed_copy_is_the_same_file(sn: ModuleType, name: str, tmp_path: Path) -> None:
    original = sn.sniff((CORPUS / name).read_bytes())
    for decoy in DECOY_NAMES:
        (tmp_path / decoy).write_bytes((CORPUS / name).read_bytes())
        assert sn.sniff((tmp_path / decoy).read_bytes()) == original


def _variants(data: bytes, name: str) -> dict[str, bytes]:
    text = data.decode("utf-8")
    out = {
        "crlf": text.replace("\n", "\r\n").encode("utf-8"),
        "utf-8-bom": codecs.BOM_UTF8 + data,
        "utf-16-bom": text.encode("utf-16"),
        "utf-32-le": text.encode("utf-32-le"),
        "trailing-nul": data + b"\0",
        "trailing-latin-1": data + b"\n# caf\xe9\n",
    }
    if not text.startswith(("#!", "{")):
        out["padded"] = ("# padding\n" * 300).encode("utf-8") + data
    if name.endswith((".yml", ".yaml")):
        out["document-after"] = b"a: 1\n---\n" + data
    return out


@pytest.mark.parametrize("name", FILES)
def test_rewritten_copies_keep_their_kinds(sn: ModuleType, name: str) -> None:
    data = (CORPUS / name).read_bytes()
    expected = {k for k, v in EXPECTED[name].items() if v != "low"}
    for label, variant in _variants(data, name).items():
        found = sn.sniff(variant).kinds("medium")
        assert expected <= found, (label, found)


def _rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret


def _check_invariants(sn: ModuleType, result: object, size: int) -> None:
    assert result.content in ("text", "undecodable", "binary")  # type: ignore[attr-defined]
    ranks = [sn.RANK[c.confidence] for c in result.candidates]  # type: ignore[attr-defined]
    assert ranks == sorted(ranks, reverse=True)
    assert len({c.kind for c in result.candidates}) == len(result.candidates)  # type: ignore[attr-defined]
    assert {c.kind for c in result.candidates} <= set(sn.KINDS)  # type: ignore[attr-defined]
    assert size <= LIMIT


@pytest.mark.parametrize("seed", SEEDS)
def test_random_bytes_never_raise(sn: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    data = rng.randbytes(rng.randrange(0, 4000))
    _check_invariants(sn, sn.sniff(data), len(data))


TOKENS = ["apiVersion", "kind", "on", "jobs", "hosts", "tasks", "services", "openapi", "mcpServers", "FROM a", "RUN b"]
TOKENS += [
    "#!/usr/bin/env -S",
    "bash",
    ": ",
    ":",
    "- ",
    "? ",
    "&a ",
    "*a ",
    "!!str ",
    '"',
    "'",
    "\\",
    "#",
    "\n",
    "\r\n",
]
TOKENS += ["\r", "\t", "  ", "---\n", "...\n", "{", "}", "[", "]", ",", "%YAML", "\x85", chr(0xFEFF), "\0", "\\u006b"]


@pytest.mark.parametrize("seed", SEEDS)
def test_random_config_shaped_text_never_raises(sn: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    text = "".join(rng.choice(TOKENS) for _ in range(rng.randrange(0, 400)))
    for codec in ("utf-8", "utf-16", "utf-32-be"):
        data = text.encode(codec)
        _check_invariants(sn, sn.sniff(data), len(data))


@pytest.mark.parametrize("seed", SEEDS)
def test_a_manifest_stays_kubernetes_through_noise(sn: ModuleType, seed: int) -> None:
    """Comments, blank lines, quoting, line ends, BOMs and indentation that YAML allows never hide the pair."""
    rng = _rng(seed)
    end = rng.choice(["\n", "\r\n", "\r"])
    keys = [rng.choice(["apiVersion", '"apiVersion"', "'apiVersion'", "!!str apiVersion", "&x apiVersion"])]
    keys.append(rng.choice(["kind", '"kind"', "'kind'", '"\\x6bind"', "&y kind"]))
    noise = ["# a comment: with colon", "", "metadata:", "  name: x", "spec: {}", "labels: {a: b}"]
    lines = [rng.choice(noise) for _ in range(rng.randrange(0, 60))]
    for key in keys:
        lines.insert(rng.randrange(0, len(lines) + 1), f"{key}{rng.choice([':', ' :'])} v{rng.choice(['', ' # c'])}")
    indent = " " * rng.choice([0, 0, 2])
    text = end.join(indent + line if line and not line.startswith(" ") else line for line in lines)
    data = rng.choice([b"", codecs.BOM_UTF8]) + text.encode("utf-8")
    assert sn.sniff(data).kinds("high") >= {"kubernetes"}, text


@pytest.mark.parametrize("name", FILES)
def test_every_truncation_of_a_corpus_file_is_handled(sn: ModuleType, name: str) -> None:
    data = (CORPUS / name).read_bytes()
    for cut in range(0, len(data), max(1, len(data) // 97)):
        _check_invariants(sn, sn.sniff(data[:cut]), cut)


HOSTILE = {
    "open-double-quote": lambda n: ' "a' * (n // 3),
    "open-single-quote": lambda n: " '" + "''" * (n // 2 - 1),
    "escapes": lambda n: '"' + "\\" * (n - 1),
    "colons": lambda n: "a:" * (n // 2),
    "space-colons": lambda n: "a" + " :" * (n // 2 - 1),
    "comment-marks": lambda n: "a" + " #" * (n // 2 - 1),
    "anchors": lambda n: "&a " * (n // 3),
    "ampersands": lambda n: "&" * n,
    "env-flag-run": lambda n: "#!/usr/bin/env -" + "v" * (n - 20),
    "env-split-chain": lambda n: "#!/usr/bin/env " + "-S" * (n // 2 - 10),
    "env-split-string-chain": lambda n: "#!/usr/bin/env " + "--split-string=" * (n // 15 - 1),
    "directive-spaces": lambda n: "#a=" + " " * (n - 6) + "x y",
    "dash-blank-lines": lambda n: "- \n" * (n // 3),
    "slashed-words": lambda n: "a/" * (n // 2),
    "comment-ended-words": lambda n: "*/a" * (n // 3),
    "tagged-anchors": lambda n: " !&a" * (n // 4),
    "anchors-then-tags": lambda n: "&a !t" * (n // 5),
    "ampersand-names": lambda n: "&a" * (n // 2),
    "anchored-tags": lambda n: "&a " + "!t " * (n // 3 - 1),
    "type-colons": lambda n: "Resources: 1\nType:" * (n // 18),
    "split-keys": lambda n: '"a"\n' * (n // 4),
    "docker-continuations": lambda n: "FROM a\nRUN " + "x\\\n" * (n // 3 - 4),
    "aliases": lambda n: "*a :\n" * (n // 5),
    "tags": lambda n: "!t " * (n // 3),
    "dashes": lambda n: "- " * (n // 2),
    "dash-lines": lambda n: "-\n " * (n // 3),
    "documents": lambda n: "---\n" * (n // 4),
    "newlines": lambda n: "\n" * n,
    "one-long-key": lambda n: "k" * (n - 3) + ": v",
    "deep-json": lambda n: "[" * n,
    "deep-json-object": lambda n: '{"a":' * (n // 5),
    "env-options": lambda n: "#!/usr/bin/env " + "-S " * (n // 3 - 6),
    "arg-lines": lambda n: "ARG a\\\n" * (n // 7),
    "directives": lambda n: "#a=b\n" * (n // 5),
    "commas": lambda n: "{" + "," * (n - 1),
}


@pytest.mark.parametrize("make", HOSTILE.values(), ids=HOSTILE.keys())
def test_a_hostile_file_at_the_limit_is_read_in_bounded_time(sn: ModuleType, make: object) -> None:
    """Quadrupling the input must not take ~16x as long; a slow machine passes, a quadratic does not."""
    small, big = (make(size).encode("utf-8")[:size] for size in (LIMIT // 4, LIMIT))  # type: ignore[operator]
    took = []
    for data in (small, big):
        started = time.perf_counter()
        result = sn.sniff(data)
        took.append(time.perf_counter() - started)
        _check_invariants(sn, result, len(data))
    assert took[1] < 1 or took[1] < 10 * took[0], took
    assert took[1] < 60, took
