"""Shared constants for the HCL tests."""

from __future__ import annotations

import random

from trees import ROOT

CORPUS = ROOT / "tests" / "chock_scan" / "corpus" / "hcl"


def rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret
