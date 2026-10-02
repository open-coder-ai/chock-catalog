"""Whether a change moves a lockfile and the manifest that explains it together, and lockfiles ignored or deleted.

All verdicts here are asks: `npm update`, `cargo update` and `go mod tidy` legitimately move a lock alone.
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from pathlib import Path, PurePosixPath

from lockscan.model import DELETED, IGNORED, LOCK_ONLY, MANIFEST_ONLY, Finding, digest

#: lock file name (lowercase) -> ecosystem; manifest name pattern (lowercase) -> ecosystem.
LOCKS = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "poetry.lock": "python",
    "uv.lock": "python",
    "pipfile.lock": "pipenv",
    "cargo.lock": "cargo",
    "go.sum": "go",
    "gemfile.lock": "ruby",
    "gems.locked": "ruby",
    "composer.lock": "php",
    "packages.lock.json": "nuget",
}
MANIFESTS = {
    "package.json": "npm",
    "pnpm-workspace.yaml": "npm",
    "pyproject.toml": "python",
    "pipfile": "pipenv",
    "cargo.toml": "cargo",
    "go.mod": "go",
    "gemfile": "ruby",
    "gems.rb": "ruby",
    "*.gemspec": "ruby",
    "composer.json": "php",
    "*.csproj": "nuget",
    "*.fsproj": "nuget",
    "*.vbproj": "nuget",
    "directory.packages.props": "nuget",
}
JSON_KEYS = {
    "package.json": (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundleDependencies",
        "bundledDependencies",
        "overrides",
        "resolutions",
        "workspaces",
        "pnpm",
    ),
    "composer.json": ("require", "require-dev", "repositories", "minimum-stability", "prefer-stable", "replace"),
}
TOML_KEYS = {
    "pyproject.toml": ("project.dependencies", "project.optional-dependencies", "project.requires-python",
                       "dependency-groups", "tool.poetry.dependencies", "tool.poetry.group",
                       "tool.poetry.dev-dependencies", "tool.poetry.source", "tool.uv"),
    "cargo.toml": ("package.name", "package.version", "dependencies", "dev-dependencies", "build-dependencies",
                   "target", "workspace", "patch", "replace"),
    "pipfile": ("packages", "dev-packages", "source", "requires"),
}  # fmt: skip
GO_DIRECTIVE = re.compile(r"^(require|replace|exclude)\b")
NUGET_ITEM = re.compile(
    r"<(?:Global)?Package(?:Reference|Version)\b[^>]*?(?:/>|>.*?</(?:Global)?Package(?:Reference|Version)>)", re.S
)
GEMSPEC_DEP = re.compile(r"^\s*\w+\.add_(?:runtime_|development_)?dependency\b.*$", re.M)


def lock_eco(path: str) -> str | None:
    return LOCKS.get(PurePosixPath(path).name.lower())


def manifest_eco(path: str) -> str | None:
    name = PurePosixPath(path).name.lower()
    return next((eco for pattern, eco in MANIFESTS.items() if fnmatch.fnmatchcase(name, pattern)), None)


def related(a: str, b: str) -> bool:
    """Whether two files sit in one folder or one sits in a folder below the other's (a workspace)."""
    da, db = PurePosixPath(a).parent.parts, PurePosixPath(b).parent.parts
    return da[: len(db)] == db or db[: len(da)] == da


def _dig(document: object, dotted: str) -> object:
    for part in dotted.split("."):
        document = document.get(part) if isinstance(document, dict) else None
    return document


def dependency_digest(path: str, text: str) -> str:
    """A fingerprint of what in a manifest decides its lock; any change to it should move the lock too."""
    name = PurePosixPath(path).name.lower()
    picked: object
    try:
        if name in JSON_KEYS:
            loaded = json.loads(text)
            picked = [_dig(loaded, key) for key in JSON_KEYS[name]]
        elif name in TOML_KEYS:
            loaded = tomllib.loads(text)
            picked = [_dig(loaded, key) for key in TOML_KEYS[name]]
        elif name == "go.mod":
            picked = _go_directives(text)
        elif name.endswith(".gemspec"):
            picked = GEMSPEC_DEP.findall(text)
        elif manifest_eco(path) == "nuget":
            picked = [" ".join(item.split()) for item in NUGET_ITEM.findall(text)]
        else:
            picked = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    except (ValueError, tomllib.TOMLDecodeError):
        picked = text  # unreadable: every edit counts as a dependency change
    return digest(json.dumps(picked, sort_keys=True, default=str))


def _go_directives(text: str) -> list[str]:
    kept, block = [], False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if block:
            block = line != ")"
            kept.append(line)
        elif GO_DIRECTIVE.match(line):
            block = line.endswith("(")
            kept.append(line)
    return kept


def lock_on_disk(root: Path, manifest: str, eco: str) -> bool:
    """Whether a lock of `eco` sits in the manifest's folder or a folder above it, up to the repository root."""
    folder = PurePosixPath(manifest).parent
    for parent in (folder, *folder.parents):
        here = root / parent
        if here.is_dir() and any(lock_eco(p.name) == eco for p in here.iterdir()):
            return True
    return False


def sync_findings(writes: dict[str, str], root: Path) -> list[Finding]:
    """Locks the change moves without a related manifest, and manifests moved without the lock they have."""
    found = []
    for path, text in writes.items():
        if (eco := lock_eco(path)) and not any(manifest_eco(m) == eco and related(path, m) for m in writes):
            message = "lockfile changed without its manifest: ask a person to confirm the lock update was intended"
            found.append(Finding(LOCK_ONLY, f"{LOCK_ONLY}|{digest(text)}", path, 1, message))
        eco = manifest_eco(path)
        if (
            eco
            and not any(lock_eco(lock) == eco and related(path, lock) for lock in writes)
            and lock_on_disk(root, path, eco)
        ):
            message = "manifest dependencies changed without the lockfile beside it: regenerate the lock in this change"
            found.append(Finding(MANIFEST_ONLY, f"{MANIFEST_ONLY}|{dependency_digest(path, text)}", path, 1, message))
    return found


def ignore_findings(writes: dict[str, str]) -> list[Finding]:
    """`.gitignore` patterns that would drop a lockfile from the repository."""
    found = []
    for path, text in writes.items():
        if PurePosixPath(path).name != ".gitignore":
            continue
        for number, raw in enumerate(text.splitlines(), 1):
            pattern = raw.strip()
            if not pattern or pattern.startswith(("#", "!")):
                continue
            last = pattern.rstrip("/").rsplit("/", 1)[-1].lower()
            if any(fnmatch.fnmatchcase(lock, last) for lock in LOCKS):
                message = f"ignores a lockfile ({pattern}): keep lockfiles committed so installs stay pinned"
                found.append(Finding(IGNORED, f"{IGNORED}|{pattern}", path, number, message))
    return found


def deleted_findings(deleted: list[str], root: Path) -> list[Finding]:
    """Lockfiles the commit deletes while a manifest of theirs stays in the same folder."""
    found = []
    for path in deleted:
        eco = lock_eco(path)
        folder = root / PurePosixPath(path).parent
        if eco and folder.is_dir() and any(manifest_eco(p.name) == eco for p in folder.iterdir() if p.is_file()):
            message = "lockfile deleted while its manifest stays: restore it, or ask a person"
            found.append(Finding(DELETED, f"{DELETED}|{path}", path, 1, message))
    return found
