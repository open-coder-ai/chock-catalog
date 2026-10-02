"""Package.swift: `.package(url:|id:)` declarations by regex; Swift is code, so only the literal form is read."""

from __future__ import annotations

import re

_PACKAGE = re.compile(r'\.package\s*\(\s*(?:name\s*:\s*"[^"]*"\s*,\s*)?(url|id)\s*:\s*"([^"]+)"')
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_USER = re.compile(r"^[^@/]+@")


def _location(url: str) -> str:
    """`host/org/repo` for a git URL in https or scp form, without scheme, user, `.git` or trailing slash."""
    ssh = not _SCHEME.match(url)
    bare = _USER.sub("", _SCHEME.sub("", url.strip()))
    bare = bare.replace(":", "/", 1) if ssh else bare
    return bare.removesuffix("/").removesuffix(".git").removesuffix("/")


def package_swift_names(text: str) -> list[str]:
    """Remote package locations (and registry ids) a manifest depends on; `path:` packages are local."""
    code = "\n".join(line for line in text.removeprefix("\ufeff").splitlines() if not line.lstrip().startswith("//"))
    return [_location(value) if kind == "url" else value for kind, value in _PACKAGE.findall(code)]
