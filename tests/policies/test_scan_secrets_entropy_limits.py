"""scan-secrets-entropy names the misses it was probed for, and the gate still misses each of them.

Once a fix starts catching a probe, its test fails so the description drops that miss; while the
probe passes unreported, the manifest description must name it.
"""

from __future__ import annotations

import re

import pytest
from policies import entropykit as kit
from policies import scriptkit

gate = kit.load()
V = kit.secret(31)
PROBES = {
    "split across lines": ("conf.yaml", f"client_secret: |\n  {V}\n"),
    "over 150 characters": (".env", f"CLIENT_SECRET={kit.secret(32, 151)}\n"),
    "under other key names": ("conf.json", f'{{"x": "{V}"}}\n'),
    "written like code": ("conf.yaml", "client_secret: CorrectHorseBatteryStaple\n"),
}


@pytest.mark.parametrize("miss", sorted(PROBES))
def test_a_stated_miss_is_still_missed_and_still_stated(miss: str) -> None:
    path, text = PROBES[miss]
    assert gate.judge(path, text, waivable=False) == []
    description = re.sub(r"\s+", " ", scriptkit.manifest(kit.POLICY)["description"])
    assert miss in description


def test_the_description_says_it_only_warns_and_is_not_a_boundary() -> None:
    description = re.sub(r"\s+", " ", scriptkit.manifest(kit.POLICY)["description"])
    assert description.startswith("Friction, not a security boundary")
    assert "Warns only (observe)" in description
