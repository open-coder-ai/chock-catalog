"""Files a hook runs: a script an npm lifecycle entry names, or the file Cargo's `package.build` names.

Editing such a file changes what runs at install or build while the manifest stays as it was, so
the file itself is judged, keyed by a digest of its text: any edit is new, an untouched file is old.
"""

from __future__ import annotations

import json
import posixpath
import re
import tomllib

from lifecycle import ASK, Hit, digest
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
#: Programs that run the file named after them (their flags aside): `node x.js`, `sh setup`, `python x.py`.
INTERPRETERS = frozenset(
    [
        "node",
        "nodejs",
        "bun",
        "deno",
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "python",
        "python3",
        "py",
        "ruby",
        "perl",
        "php",
        "pwsh",
        "powershell",
        "tsx",
        "ts-node",
        "lua",
    ]
)
#: Words that run the rest of the command line as given: `env X=1 node x.js`, `npx tsx x.ts`.
WRAPPERS = frozenset(["env", "sudo", "exec", "nohup", "time", "command", "cross-env", "npx", "pnpx", "bunx", "run"])
INLINE = frozenset(["-e", "--eval", "-p", "--print", "-pe", "-c", "-E"])
SEPARATORS = re.compile(r"&&|\|\||[;|&\n]")


def executed(body: str) -> list[str]:
    """The files a hook body executes: each command's program when it is a path, or the first operand of an
    interpreter. Data arguments (`tsc -p tsconfig.json`, `cp a b`) are not files it executes.
    """
    found = []
    for command in SEPARATORS.split(body):
        words = [w.strip("'\"") for w in command.split()]
        while words and (re.match(r"^[A-Za-z_]\w*=", words[0]) or words[0] in WRAPPERS):
            words.pop(0)
        if not words:
            continue
        program = posixpath.basename(words[0].replace("\\", "/")).lower().removesuffix(".exe")
        if program in INTERPRETERS:
            for word in words[1:]:
                if word in INLINE:  # `node -e <code>`: the operand is code, no file is run
                    break
                if not word.startswith("-") and word != "run":
                    found.append(word)
                    break
        elif "/" in words[0] or "." in posixpath.basename(words[0]):
            found.append(words[0])
    return found


def _scripts(folder: str, writes: dict[str, str], root: str) -> dict:
    manifest = posixpath.join(folder, "package.json") if folder else "package.json"
    text = text_of(manifest, writes, root)
    try:
        data = json.loads(text.removeprefix("\ufeff")) if text else {}
    except ValueError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    return scripts if isinstance(scripts, dict) else {}


def npm_script(path: str, text: str, writes: dict[str, str], root: str) -> list[Hit]:
    """A file a lifecycle entry of a package.json above it (in the change or on disk) executes."""
    for folder in ancestors(path):
        scripts = _scripts(folder, writes, root)
        for name in LIFECYCLE_NAMES:
            body = scripts.get(name)
            where = posixpath.join(folder, "package.json") if folder else "package.json"
            if isinstance(body, str) and path != where and any(join(folder, m) == path for m in executed(body)):
                # Asked about, never blocked: a URL or child_process in a program's own source is ordinary,
                # so its text is no signal; the edit itself is what a person reviews.
                return [Hit(1, "npm-lifecycle-target", f"{where} scripts.{name}", digest(text), ASK,
                            f"runs at install through scripts.{name}")]  # fmt: skip
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
