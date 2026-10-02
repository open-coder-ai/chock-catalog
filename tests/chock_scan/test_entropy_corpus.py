"""The entropy tier end to end over real files: lockfile digests, UUIDs, inline images and minified code stay quiet.

corpus/entropy/SOURCES.txt names each file's origin and licence. A positive control proves the
pipeline is not vacuously quiet: keyword-adjacent random values in the same shapes are reported.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import ModuleType

import pytest
from chock_scan import tokens
from chock_scan.libmods import LIB, load, rng
from trees import ROOT

CORPUS = Path(__file__).parent / "corpus" / "entropy"
FILES = [
    *sorted(p for p in CORPUS.iterdir() if p.name != "SOURCES.txt"),
    ROOT / "requirements" / "test.txt",
    ROOT / "chock.lock",
]
TOKEN = re.compile(r"[A-Za-z0-9+/=_.:-]{16,150}")


@pytest.fixture(scope="module")
def mods() -> dict[str, ModuleType]:
    return {name: load(LIB, name) for name in ("safe_read", "entropy", "keyword_values", "checksums")}


@pytest.mark.parametrize("path", FILES, ids=[p.name for p in FILES])
def test_real_files_parse_and_yield_nothing_suspicious(mods: dict[str, ModuleType], path: Path) -> None:
    text = mods["safe_read"].read_text(path)
    flagged = [
        (c.line, c.key, mods["entropy"].assess(c.value))
        for c in mods["keyword_values"].candidates(text)
        if mods["entropy"].assess(c.value).suspicious
    ]
    assert flagged == []


@pytest.mark.parametrize("path", FILES, ids=[p.name for p in FILES])
def test_no_token_in_real_files_is_a_confirmed_credential(mods: dict[str, ModuleType], path: Path) -> None:
    text = mods["safe_read"].read_text(path)
    cs = mods["checksums"]
    verdicts = {cs.check(t).verdict for t in TOKEN.findall(text)}
    assert cs.Verdict.CONFIRMED not in verdicts


def test_the_corpus_reaches_the_allow_reasons(mods: dict[str, ModuleType]) -> None:
    reasons = set()
    for path in FILES:
        for c in mods["keyword_values"].candidates(mods["safe_read"].read_text(path)):
            reasons.add(mods["entropy"].assess(c.value).reason)
    assert "uuid" in reasons
    raw = " ".join(TOKEN.findall((CORPUS / "package-lock.json").read_text(encoding="utf-8")))
    assert {mods["entropy"].assess(t).reason for t in raw.split() if t.startswith("sha512-")} == {"digest"}


@pytest.mark.parametrize("seed", range(40))
def test_positive_control_random_values_next_to_secret_keys_are_reported(
    mods: dict[str, ModuleType], seed: int
) -> None:
    r = rng(seed)
    alphabet = r.choice([tokens.BASE62, tokens.BASE62 + "+/", tokens.BASE62 + "-_", "0123456789abcdef"])
    value = tokens.draw(r, alphabet, r.randrange(24, 80))
    key = r.choice(["client_secret", "apiKey", "DB_PASSWORD", "access-token", "signingKey"])
    form = r.choice(['"{k}": "{v}",', "{k}: {v}", "{k}={v}", "  {k} = '{v}'"])
    text = "name: demo\n" + form.format(k=key, v=value) + "\nport: 8080\n"
    found = [(c, mods["entropy"].assess(c.value)) for c in mods["keyword_values"].candidates(text)]
    assert [(c.line, c.value, a.suspicious) for c, a in found] == [(2, value, True)]


SHAPED = re.compile(
    r"(?:sha(?:1|256|384|512)[-:=]|h1:)[A-Za-z0-9+/=_-]+"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|data:image/png;base64,[A-Za-z0-9+/=]+"
)


@pytest.mark.parametrize("path", FILES, ids=[p.name for p in FILES])
def test_corpus_digests_uuids_and_images_stay_allowed_even_under_a_secret_key(
    mods: dict[str, ModuleType], path: Path
) -> None:
    # The adversarial placement: the same real values written next to a secret-like key, where the
    # keyword filter no longer helps; only the value's own shape keeps it from being reported.
    values = SHAPED.findall(mods["safe_read"].read_text(path))
    text = "\n".join(f"client_secret: {v}" for v in values)
    judged = [mods["entropy"].assess(c.value) for c in mods["keyword_values"].candidates(text)]
    assert [a for a in judged if a.suspicious] == []
    assert len(judged) == sum(16 <= len(v) <= 150 for v in values)
