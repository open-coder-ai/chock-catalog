"""The crypto pack: Cryptography and TLS."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="crypto",
    title="Cryptography and TLS",
    covers=(
        "JCA ciphers, digests, random numbers, keys and IVs; TLS contexts, trust managers and hostname verifiers; credentials written into the source."
    ),
)

RULES: tuple[Rule, ...] = (
)
