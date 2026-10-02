"""Image references: variable substitution, tag and digest, and the forms another policy already reads on one line."""

from __future__ import annotations

import re

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
FLOATING_TAG = "latest"


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
    """'floating' (no tag, or latest, and no digest), 'no-digest', 'pinned' or 'scratch'."""
    if ref.lower() == "scratch":
        return "scratch"
    _, tag, digest = split_ref(ref)
    if digest:
        return "pinned"
    if not tag or tag == FLOATING_TAG:
        return "floating"
    return "no-digest"


def runs_as_non_root(ref: str) -> bool:
    """A base image whose tag says it runs unprivileged: `nonroot` (distroless), or ending -nonroot or -rootless."""
    tag = split_ref(ref)[1].lower()
    return tag == "nonroot" or tag.endswith(("-nonroot", "-rootless"))
