"""package.json and composer.json: install-time scripts, gypfile, bin shadowing, unpinned git/URL dependencies."""

from __future__ import annotations

import json
import posixpath
import re

from lifecycle import ASK, BLOCK, Hit, line_of, norm
from lifecycle.gyp import native_sources
from lifecycle.signals import danger
from lifecycle.targets import LIFECYCLE_NAMES, RUNS_FILE

#: Scripts npm, yarn, pnpm or bun run on install, on a git-dependency prepare, or on pack/publish.
#: `dependencies` runs after node_modules changes (npm 8+); `pnpm:devPreinstall` before a pnpm install;
#: the uninstall trio when a package manager replaces or removes an installed package.
LIFECYCLE = tuple(LIFECYCLE_NAMES)
#: The `prepare` values husky documents, allowed verbatim (roadmap FP control).
HUSKY = {"husky", "husky install", "husky install .husky"}
DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
SHADOWED = frozenset(
    [
        "node",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "bun",
        "corepack",
        "git",
        "sh",
        "bash",
        "zsh",
        "dash",
        "fish",
        "env",
        "sudo",
        "su",
        "doas",
        "ls",
        "cp",
        "mv",
        "rm",
        "cat",
        "curl",
        "wget",
        "ssh",
        "scp",
        "python",
        "python3",
        "pip",
        "pip3",
        "make",
        "gcc",
        "cc",
        "ld",
        "tar",
        "gzip",
        "chmod",
        "chown",
        "kill",
        "ps",
        "docker",
        "kubectl",
        "gh",
        "which",
        "find",
        "grep",
        "sed",
        "awk",
        "cd",
        "echo",
        "test",
        "true",
        "false",
    ]
)
GIT_SPEC = re.compile(r"(?i)^(?:git\+[\w+.-]*:|git:|git@|github:|gitlab:|bitbucket:|gist:)")
SHORTHAND = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+(?:#.*)?$")
PINNED = re.compile(r"#[0-9a-fA-F]{40}$")
KEY = re.compile(r'"((?:[^"\\\n]|\\.)*)"\s*:')
URL_SPEC = re.compile(r"(?i)^https?://")
PATH_SPEC = re.compile(r"^(?:file:|link:|\.{1,2}/|/|~|[A-Za-z]:[\\/])")
#: Composer runs these for the root package only; roadmap NP04 judges the ones with fetch tools.
COMPOSER_EVENTS = {
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "pre-autoload-dump",
    "post-autoload-dump",
    "post-root-package-install",
    "post-create-project-cmd",
    "pre-package-install",
    "post-package-install",
    "pre-package-update",
    "post-package-update",
}


def load(path: str, text: str) -> tuple[dict | None, list[Hit]]:
    """The manifest object, or None with a BLOCK hit when it does not parse (an install would fail too)."""
    try:
        data = json.loads(text.removeprefix("\ufeff"))
    except ValueError as exc:
        return None, [Hit(1, "manifest-unparseable", path.rsplit("/", 1)[-1], "", BLOCK, f"does not parse ({exc})")]
    return (data if isinstance(data, dict) else {}), []


def _escapes(base: str, target: str) -> bool:
    """A path that is absolute, or climbs out of the repository from the manifest's folder."""
    if re.match(r"^(?:/|~|[A-Za-z]:[\\/]|\\\\)", target):
        return True
    joined = posixpath.normpath(posixpath.join(base or ".", target.replace("\\", "/")))
    return joined == ".." or joined.startswith("../")


def package_json(path: str, text: str, writes: dict[str, str], root: str) -> list[Hit]:
    data, hits = load(path, text)
    if data is None:
        return hits
    base = posixpath.dirname(path)
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        hits += _scripts(path, text, scripts, writes, base)
    if data.get("gypfile") is True and not native_sources(base, writes, root):
        hits.append(
            Hit(
                line_of(text, '"gypfile"'),
                "gyp-no-native",
                "gypfile",
                "true",
                BLOCK,
                "gypfile is true but no binding.gyp with C/C++ sources exists beside it",
            )
        )
    hits += _bins(text, data.get("bin"), str(data.get("name", "")))
    for section in DEP_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict):
            hits += _deps(text, section, deps, base)
    return hits


def _scripts(path: str, text: str, scripts: dict, writes: dict[str, str], base: str) -> list[Hit]:
    hits = []
    changed = {p for p in writes if p != path}
    for name in LIFECYCLE:
        body = scripts.get(name)
        if not isinstance(body, str):
            continue
        value = norm(body)
        if name == "prepare" and value in HUSKY:
            continue
        why = danger(body)
        ran = [m for m in RUNS_FILE.findall(body) if posixpath.normpath(posixpath.join(base, m)) in changed]
        if not why and ran:
            why = f"runs {ran[0]}, a file this same change writes"
        level = BLOCK if why else ASK
        hits.append(
            Hit(
                line_of(text, f'"{name}"'),
                "npm-lifecycle",
                f"scripts.{name}",
                value,
                level,
                why or "new or changed install-time script",
            )
        )
    return hits


def _bins(text: str, bins: object, package: str) -> list[Hit]:
    entries = {package.rsplit("/", 1)[-1]: bins} if isinstance(bins, str) else bins
    if not isinstance(entries, dict):
        return []
    hits = []
    for name, target in entries.items():
        if not isinstance(target, str):
            continue
        shadows = name.lower() in SHADOWED or "/" in name or "\\" in name
        if shadows or _escapes("", target):
            why = f"bin '{name}' shadows a system command" if shadows else f"bin '{name}' points outside the package"
            hits.append(Hit(line_of(text, '"bin"'), "npm-bin", f"bin.{name}", norm(target), ASK, why))
    return hits


def _deps(text: str, section: str, deps: dict, base: str) -> list[Hit]:
    hits = []
    start = text.find(f'"{section}"')
    # The first line of each quoted key after the section, counted in one pass so a 40k-entry list stays linear.
    lines: dict[str, int] = {}
    offset, line = 0, 1
    for key in KEY.finditer(text, max(start, 0)):
        line += text.count("\n", offset, key.start())
        offset = key.start()
        lines.setdefault(key.group(1), line)
    for name, spec in deps.items():
        if not isinstance(spec, str):
            continue
        spec_n = spec.strip()
        line = lines.get(name, 1)  # an escaped key is reported at line 1
        if (GIT_SPEC.match(spec_n) or (SHORTHAND.match(spec_n) and not spec_n.startswith("@"))) and not PINNED.search(
            spec_n
        ):
            hits.append(
                Hit(
                    line,
                    "npm-git-url-dep",
                    f"{section}.{name}",
                    spec_n,
                    BLOCK,
                    "git dependency without a 40-hex commit pin",
                )
            )
        elif URL_SPEC.match(spec_n):
            hits.append(
                Hit(
                    line,
                    "npm-git-url-dep",
                    f"{section}.{name}",
                    spec_n,
                    BLOCK,
                    "URL tarball dependency: nothing pins its content",
                )
            )
        elif PATH_SPEC.match(spec_n) and _escapes(base, re.sub(r"^(?:file:|link:)", "", spec_n)):
            hits.append(
                Hit(line, "npm-path-dep", f"{section}.{name}", spec_n, ASK, "path dependency outside the repository")
            )
    return hits


def composer_json(path: str, text: str) -> list[Hit]:
    data, hits = load(path, text)
    scripts = (data or {}).get("scripts")
    if not isinstance(scripts, dict):
        return hits
    for event in sorted(COMPOSER_EVENTS & set(scripts)):
        commands = scripts[event] if isinstance(scripts[event], list) else [scripts[event]]
        for command in commands:
            if isinstance(command, str) and (why := danger(command)):
                hits.append(
                    Hit(
                        line_of(text, f'"{event}"'),
                        "composer-script-fetch",
                        f"scripts.{event}",
                        norm(command),
                        BLOCK,
                        why,
                    )
                )
    return hits
