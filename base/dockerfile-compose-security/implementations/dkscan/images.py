"""Image references: variable substitution, tag and digest, and the forms another policy already reads on one line."""

from __future__ import annotations

import json
import re
from pathlib import Path

NESTED = re.compile(r"\$\{[^}]*\$")
VAR = re.compile(r"\$(?:\{([A-Za-z_]\w*)(?:(:?[-+?])([^}]*))?\}|([A-Za-z_]\w*))")
DIGEST = re.compile(r"@[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[0-9a-fA-F]{32,}$")
#: block-unpinned-agent-components (HP06 0.1.0) reads these FROM and image: lines one at a time; where that
#: gate is installed, a line one of these matches is its to report, so this bundle stays silent on it.
#: The single-character classes keep the pattern from matching its own source text.
HP06_FROM = re.compile(
    r"FROM\s+\S+:late[s]t\b|^\s*[Ff][Rr][Oo][Mm]\s+(?:--platform[=\s]\S+\s+)?(?!-)(?:\S+:late[s]t(?![\w.-])"
    r"|(?:[^\s/'\"]+/)+[^\s/:@'\"$]+(?:\s+[Aa][Ss]\s+\S+)?\s*(?:#.*)?$)"
)
HP06_IMAGE = re.compile(r"image:\s*['\"]?\S{1,256}:late[s]t\b")
TABLE = Path(__file__).resolve().parent / "data" / "floating-tags.json"
#: Tag words that name a moving target, and release codenames (data/floating-tags.json); a missing or broken table
#: raises and the runner refuses.
_FACTS = json.loads(TABLE.read_text(encoding="utf-8"))
FLOATING_TAGS = frozenset(_FACTS["floating_tags"])
RELEASE_CODENAMES = frozenset(_FACTS["release_codenames"])
TAG_PARTS = re.compile(r"[-._]")


def substitute(text: str, env: dict[str, str | None]) -> str | None:
    """`text` with $VAR, ${VAR}, ${VAR:-word}, ${VAR-word} and ${VAR:+word} expanded; None when one cannot be."""
    if NESTED.search(text):
        return None
    unknown = False

    def one(found: re.Match[str]) -> str:
        nonlocal unknown
        name = found.group(1) or found.group(4)
        op, word = found.group(2), found.group(3) or ""
        value = env.get(name)
        if op in (":-", "-"):
            return value if value else word
        if op in (":+", "+"):
            if value is None and name in env:
                unknown = True
            return word if value else ""
        if value is None:
            unknown = True
            return ""
        return value

    out = VAR.sub(one, text)
    return None if unknown or "$" in out else out


def split_ref(ref: str) -> tuple[str, str, str]:
    """(name, tag, digest) of an image reference; tag and digest are "" when absent."""
    digest = ""
    if found := DIGEST.search(ref):
        digest, ref = found.group(), ref[: found.start()]
    name, tag = ref, ""
    colon = ref.rfind(":")
    if colon > ref.rfind("/"):
        name, tag = ref[:colon], ref[colon + 1 :]
    return name, tag, digest


def judge(ref: str) -> str:
    """'floating', 'pinned' (a digest, or a tag that names a release) or 'scratch'.

    Without a digest a tag floats when it is absent, when any `-._` component is a floating word (`lts-alpine`), or
    when it holds no digit and does not start with a release codename (`slim`, `alpine`; `bookworm-slim` names one).
    """
    if ref.lower() == "scratch":
        return "scratch"
    _, tag, digest = split_ref(ref)
    if digest:
        return "pinned"
    parts = TAG_PARTS.split(tag.lower())
    if not tag or FLOATING_TAGS.intersection(parts):
        return "floating"
    return "pinned" if any(c.isdigit() for c in tag) or parts[0] in RELEASE_CODENAMES else "floating"


def runs_as_non_root(ref: str) -> bool:
    """A base image whose tag says it runs unprivileged: `nonroot` (distroless), or ending -nonroot or -rootless."""
    tag = split_ref(ref)[1].lower()
    return tag == "nonroot" or tag.endswith(("-nonroot", "-rootless"))
