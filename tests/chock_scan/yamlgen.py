"""Seeded YAML for the differential tests: random data dumped by PyYAML in random styles, and mutations of it.

hypothesis is not a dev dependency here, so cases come from random.Random(seed): a failure names its
seed and reproduces from it alone.
"""

from __future__ import annotations

import random

import yaml

#: Characters that change how YAML reads: indicators, quotes, blanks, breaks, and non-ASCII text.
ALPHABET = "ab: #-'\"\n\t{}[],&*!|>%@`?\\x\u00e9\u4e2d\U0001f600 0.~"
SCALARS = (1, 2.5, None, True, "", "on", "null", "- x", "a: b", "#c")


def rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret


def text(r: random.Random, longest: int = 12) -> str:
    return "".join(r.choice(ALPHABET) for _ in range(r.randrange(longest)))


def data(r: random.Random, depth: int = 0) -> object:
    """A random tree; keys are one line and non-empty, so PyYAML never needs an explicit `?` key."""
    pick = r.random()
    if depth > 4 or pick < 0.4:
        return text(r) if r.random() < 0.8 else r.choice(SCALARS)
    if pick < 0.7:
        return [data(r, depth + 1) for _ in range(r.randrange(4))]
    return {(text(r).replace("\n", " ") or "k"): data(r, depth + 1) for _ in range(r.randrange(4))}


def document(r: random.Random) -> str:
    """One or two documents of random data in a random mix of block, flow, quoting and block-scalar styles."""
    options = {
        "default_flow_style": r.choice([False, True, None]),
        "default_style": r.choice([None, None, '"', "'", "|", ">"]),
        "width": r.choice([20, 80, 1000]),
        "indent": r.choice([2, 3, 4, 6]),
        "allow_unicode": r.random() < 0.5,
        "explicit_start": r.random() < 0.3,
        "explicit_end": r.random() < 0.2,
    }
    if r.random() < 0.3:
        return yaml.dump_all([data(r), data(r)], **options)
    return yaml.dump(data(r), **options)


def mutate(r: random.Random, source: str) -> str:
    """One to three edits: insert a significant character, delete one, or duplicate a line elsewhere."""
    for _ in range(r.randrange(1, 4)):
        at, edit = r.randrange(len(source) + 1), r.random()
        if edit < 0.4:
            source = source[:at] + r.choice(ALPHABET + "\n  ") + source[at:]
        elif edit < 0.7:
            source = source[:at] + source[at + 1 :]
        else:
            lines = source.split("\n")
            lines.insert(r.randrange(len(lines)), r.choice(lines))
            source = "\n".join(lines)
    return source
