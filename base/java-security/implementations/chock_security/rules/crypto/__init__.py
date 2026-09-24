"""The crypto pack: Cryptography and TLS."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.crypto.crypto_hardcoded_credential import RULE as HARDCODED_CREDENTIAL
from chock_security.rules.crypto.crypto_insecure_random import RULE as INSECURE_RANDOM
from chock_security.rules.crypto.crypto_legacy_tls import RULE as LEGACY_TLS
from chock_security.rules.crypto.crypto_short_key import RULE as SHORT_KEY
from chock_security.rules.crypto.crypto_static_iv_or_salt import RULE as STATIC_IV_OR_SALT
from chock_security.rules.crypto.crypto_tls_trust_all import RULE as TLS_TRUST_ALL
from chock_security.rules.crypto.crypto_weak_cipher import RULE as WEAK_CIPHER
from chock_security.rules.crypto.crypto_weak_password_hash import RULE as WEAK_PASSWORD_HASH

PACK = Pack(
    id="crypto",
    title="Cryptography and TLS",
    covers=(
        "JCA ciphers, digests, random numbers, keys and IVs; TLS contexts, trust managers and hostname verifiers; credentials written into the source."
    ),
)

RULES: tuple[Rule, ...] = (
    WEAK_CIPHER,
    WEAK_PASSWORD_HASH,
    INSECURE_RANDOM,
    TLS_TRUST_ALL,
    LEGACY_TLS,
    STATIC_IV_OR_SALT,
    SHORT_KEY,
    HARDCODED_CREDENTIAL,
)
