"""Files a hook runs: a script an npm lifecycle entry names, or the file Cargo's `package.build` names.

Editing such a file changes what runs at install or build while the manifest stays as it was, so
the file itself is judged, keyed by a digest of its text: any edit is new, an untouched file is old.
"""

from __future__ import annotations

import json
import posixpath
import re
import tomllib

from lifecycle import ASK, BLOCK, Hit, digest
from lifecycle.signals import danger
from lifecycle.textrules import build_rs
from lifecycle.tree import ancestors, join, text_of

LIFECYCLE_NAMES = [
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "postpack",
    "dependencies",
    "pnpm:devPreinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
]
#: A path argument a hook names: anything with a folder in it, or a bare name with a file extension.
RUNS_FILE = re.compile(
    r"(?<![\w.@/-])((?:\.{0,2}/)?[\w@.-]+(?:/[\w@.-]+)+|[\w@-][\w@.-]*\.[A-Za-z]\w{0,5})(?![\w.@/-])"
)


def _scripts(folder: str, writes: dict[str, str], root: str) -> dict:
    manifest = posixpath.join(folder, "package.json") if folder else "package.json"
    text = text_of(manifest, writes, root)
    try:
        data = json.loads(text.removeprefix("﻿")) if text else {}
    except ValueError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    return scripts if isinstance(scripts, dict) else {}


def npm_script(path: str, text: str, writes: dict[str, str], root: str, *, scan: bool = True) -> list[Hit]:
    """A script file run by a lifecycle entry of a package.json above it (in the change or on disk).

    `scan=False` (a file too large to scan) skips the signal search: the hit is then asked about.
    """
    for folder in ancestors(path):
        scripts = _scripts(folder, writes, root)
        for name in LIFECYCLE_NAMES:
            body = scripts.get(name)
            if isinstance(body, str) and any(join(folder, m) == path for m in RUNS_FILE.findall(body)):
                why = danger(text) if scan else None
                where = posixpath.join(folder, "package.json") if folder else "package.json"
                return [Hit(1, "npm-lifecycle-target", f"{where} scripts.{name}", digest(text),
                            BLOCK if why else ASK, f"runs at install through scripts.{name}" + (f" and {why}" if why else ""))]  # fmt: skip
    return []


def cargo_build(path: str, text: str, writes: dict[str, str], root: str) -> list[Hit]:
    """A .rs file a Cargo.toml above it names as `package.build`: judged as build.rs is."""
    for folder in ancestors(path):
        manifest = text_of(posixpath.join(folder, "Cargo.toml") if folder else "Cargo.toml", writes, root)
        try:
            build = tomllib.loads(manifest).get("package", {}).get("build") if manifest else None
        except (tomllib.TOMLDecodeError, AttributeError):
            build = None
        if isinstance(build, str) and join(folder, build) == path:
            return build_rs(text)
    return []
