"""Seeding SecureRandom with a constant: its own contract says seed material must be unpredictable.

What a constant does depends on the provider. A SHA1PRNG seeded before its first use replaces its
entropy with the seed and yields the same sequence on every run; NativePRNG and DRBG mix the seed
in, so it adds nothing. Either way the call is a mistake, and on the provider an adopter cannot see
from the source it is a key or token anyone can reproduce -- which is why Sonar reports every
constant seed (java:S4347) rather than trying to guess the provider."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "crypto-securerandom-fixed-seed"

_FACTS = facts("crypto")["random_seed"]

_DECLARATIONS = "|".join(re.escape(d) for d in _FACTS["declarations"])
_DECL = re.compile(r"(\w+)\s*=\s*new\s+(?:" + _DECLARATIONS + r")\s*\)")
#: Greedy to the last `)` on the line, so a nested call (`"seed".getBytes()`) is captured whole
#: rather than truncated at its own closing paren.
_SET_SEED = re.compile(r"(\w+)\.setSeed\(\s*(.*?)\s*\)\s*;")
#: A literal that fixes the seed at compile time: a quoted string (optionally turned into bytes),
#: a numeric literal, or an ALL_CAPS constant name -- never a call or a lower-case variable, which
#: might carry fresh entropy this rule cannot see the origin of.
_FIXED_ARG = re.compile(
    r'^(?:"[^"]*"(?:\.getBytes\([^)]*\))?|-?\d[\d_]*[lL]?|0[xX][0-9a-fA-F_]+[lL]?|[A-Z][A-Z0-9_]*)$'
)

_MESSAGE = (
    "{var}.setSeed({arg}) seeds SecureRandom with a constant. On SHA1PRNG seeded before first use "
    "that fixes every value it produces to one reproducible sequence; on other providers it adds no "
    "entropy -- and the source does not say which provider runs. Drop the call (SecureRandom seeds "
    "itself), or seed from SecureRandom.getInstanceStrong().generateSeed(...). A fixture that only "
    f"exists for a reproducible test vector needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every setSeed() call whose argument is a literal, on a variable this file built as SecureRandom."""
    declared: set[str] = set()
    for line_no, line in enumerate(text.lines, 1):
        decl = _DECL.search(line)
        if decl:
            declared.add(decl.group(1))
        seeded = _SET_SEED.search(line)
        if not seeded or seeded.group(1) not in declared:
            continue
        argument = seeded.group(2).strip()
        if _FIXED_ARG.match(argument):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(var=seeded.group(1), arg=argument))


RULE = Rule(
    id=RULE_ID,
    pack="crypto",
    title="SecureRandom seeded with a fixed value",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(call): secureRandom.setSeed(...) with a literal string, number, or ALL_CAPS "
        "constant -- drop the call, or seed from SecureRandom.getInstanceStrong().generateSeed()"
    ),
    refuses=(
        "setSeed() on a `new SecureRandom()` variable, called with a quoted string (with or "
        "without .getBytes()), a numeric literal, or an ALL_CAPS constant name"
    ),
    silent_on=(
        "a SecureRandom never reseeded; setSeed() called with a variable or a call expression "
        "(e.g. a value read from generateSeed()); setSeed() on a variable this file never built as SecureRandom"
    ),
    cwe=("CWE-337",),
    references=(
        "https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/SecureRandom.html",
        "https://rules.sonarsource.com/java/RSPEC-4347/",
    ),
)
