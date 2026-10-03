"""Load scan-secrets-entropy's gate in-process, and draw the secret-shaped values its tests feed it.

The gate imports `chock_scan` from its own folder, while tests/ has a `chock_scan` test package of
the same name; load() imports the gate with tests' modules set aside and puts them back, so each
side keeps its own. Values are drawn per run from a seed, so no credential-shaped literal sits in
this file (scan-secrets refuses an agent-written waiver pragma).
"""

from __future__ import annotations

import importlib.util
import string
import sys
from types import ModuleType

from trees import ROOT

POLICY = "scan-secrets-entropy"
NAME = f"{POLICY}-gate.py"
IMPL = ROOT / "base" / POLICY / "implementations"
BASE62 = string.digits + string.ascii_letters
_SHARED = ("chock_scan", "entropyscan")


def _helper(name: str) -> ModuleType:
    """tests/chock_scan/<name>.py by path: guardkit drops `chock_scan` from sys.modules, so a plain import can find a gate's copy."""
    spec = importlib.util.spec_from_file_location(f"entropy_test_{name}", ROOT / "tests" / "chock_scan" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tokens = _helper("tokens")
rng = _helper("libmods").rng


def _shared(name: str) -> bool:
    return any(name == top or name.startswith(f"{top}.") for top in _SHARED)


def load() -> ModuleType:
    """The gate module, its entropyscan and chock_scan imports resolved inside its own folder."""
    saved = {name: module for name, module in sys.modules.items() if _shared(name)}
    for name in saved:
        del sys.modules[name]
    path = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location("scan_secrets_entropy_gate", IMPL / NAME)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name in [n for n in sys.modules if _shared(n)]:
            del sys.modules[name]
        sys.modules.update(saved)
        sys.path[:] = path
    return module


def draw(seed: int, alphabet: str = BASE62, size: int = 32) -> str:
    """size characters drawn from alphabet with a seeded generator."""
    return tokens.draw(rng(seed), alphabet, size)


def secret(seed: int, size: int = 32) -> str:
    """A base62 value that entropy calls suspicious and no shape explains: what a real credential looks like."""
    return draw(seed, BASE62, size)


def crc_token(seed: int, prefix: str = "ghp") -> str:
    """A GitHub- or npm-style token whose CRC32 tail verifies."""
    return tokens.crc_token(rng(seed), prefix)


def luhn_number(seed: int, prefix: str = "4", size: int = 16) -> str:
    """A size-digit number starting with prefix whose Luhn check digit holds."""
    draws = rng(seed)
    body = prefix + "".join(draws.choice(string.digits) for _ in range(size - len(prefix) - 1))
    total = 0
    for index, char in enumerate(reversed(body)):
        digit = int(char) * (2 if index % 2 == 0 else 1)
        total += digit - 9 if digit > 9 else digit
    return body + str((10 - total % 10) % 10)


def grouped(number: str, sep: str = " ") -> str:
    """A 16-digit number written 4-4-4-4."""
    return sep.join(number[i : i + 4] for i in range(0, len(number), 4))
