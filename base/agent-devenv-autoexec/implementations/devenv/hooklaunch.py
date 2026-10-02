"""Git hook launchers committed to the repository: husky, .githooks, lefthook, pre-commit, package.json prepare."""

from __future__ import annotations

import re

from devenv.agents import object_of
from devenv.commands import run
from devenv.core import ASK, BLOCK, Collector, dotted, key_of, norm, walk
from devenv.parse import toml_value, yaml_leaves

RULE = "dev-hook-launchers"
#: Hooks git runs on clone, checkout, pull and rebase, with no commit by the person.
UNPROMPTED = frozenset(
    {"post-checkout", "post-merge", "post-rewrite", "post-applypatch", "post-update", "reference-transaction"}
)
#: Hook folders this gate judges itself, so pointing core.hooksPath at one hides nothing.
JUDGED_HOOK_DIRS = frozenset({".husky", ".husky/_", ".githooks"})


def hook_script(c: Collector) -> None:
    """A .husky/ or .githooks/ script: each command line asks; one that fetches and runs code blocks."""
    for number, line in enumerate(c.lines, 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            run(c, RULE, f"line@{norm(stripped)}", stripped, "hook script line", severity=ASK, line=number)


_HOOKS_PATH = re.compile(r"(?i)core\.hookspath[\"']?(?:\s*=\s*|\s+)[\"']?([^\s\"';&|]*)")


def package_json(c: Collector) -> None:
    """A script pointing core.hooksPath somewhere this gate does not judge; simple-git-hooks commands."""
    config = object_of(c.text)
    hooks = config.get("simple-git-hooks")
    for hook, body in hooks.items() if isinstance(hooks, dict) else []:
        if isinstance(body, str):
            severity = BLOCK if hook in UNPROMPTED else ASK
            run(c, RULE, f"simple-git-hooks.{hook}", body, f"simple-git-hooks {hook} command", severity=severity)
    scripts = config.get("scripts")
    for name, body in scripts.items() if isinstance(scripts, dict) else []:
        if not isinstance(body, str):
            continue
        for found in _HOOKS_PATH.finditer(body):
            target = re.sub(r"^(?:\./)+", "", found.group(1).replace("\\", "/")).rstrip("/")
            if target not in JUDGED_HOOK_DIRS:
                c.add(
                    RULE,
                    f"scripts.{name}.hooksPath={norm(found.group(1))}",
                    f"scripts.{name} sets core.hooksPath",
                    line=c.line_of(f'"{name}"'),
                )


def lefthook(c: Collector) -> None:
    _lefthook(c, yaml_leaves(c.text))


def lefthook_json(c: Collector) -> None:
    _lefthook(c, _as_leaves(c, object_of(c.text)))


def lefthook_toml(c: Collector) -> None:
    _lefthook(c, _as_leaves(c, toml_value(c.text)))


def _as_leaves(c: Collector, value: object) -> list[tuple[tuple, str, int]]:
    return [(path, str(leaf), c.line_of(key_of(path))) for path, leaf in walk(value) if path]


def _lefthook(c: Collector, leaves: list[tuple[tuple, str, int]]) -> None:
    for path, value, line in leaves:
        key = str(path[-1])
        spot = dotted(path)
        if path[0] in ("remotes", "remote", "extends") or key == "git_url":
            c.add(RULE, f"{spot}={norm(value)}", "lefthook loads hooks from another repository or file", line=line)
        elif key in ("run", "runner"):
            hook = str(path[0])
            severity = BLOCK if hook in UNPROMPTED else ASK
            run(c, RULE, spot, value, f"lefthook {hook} command", severity=severity, line=line)


_SHA = re.compile(r"^[0-9a-f]{40}$")
#: Key-path shapes: repos[i].<field> and repos[i].hooks[j].<field>.
REPO_FIELD, HOOK_FIELD = ("repos", 0, "field"), ("repos", 0, "hooks", 0, "field")


def pre_commit(c: Collector) -> None:
    """Remote hook repos pinned by tag ask, http repos block; local hooks that shell out ask; any entry that
    fetches and runs code blocks."""
    leaves = yaml_leaves(c.text)
    repos: dict[object, dict[str, tuple[str, int]]] = {}
    for path, value, line in leaves:
        if len(path) == len(REPO_FIELD) and path[0] == "repos":
            repos.setdefault(path[1], {})[str(path[2])] = (value, line)
    for path, value, line in leaves:
        if len(path) == len(HOOK_FIELD) and path[0] == "repos" and path[2] == "hooks" and path[4] == "entry":
            repo = repos.get(path[1], {}).get("repo", ("", 0))[0]
            language = next((v for p, v, _ in leaves if p[:4] == path[:4] and p[4:] == ("language",)), "")
            shells_out = repo == "local" and language in ("system", "script", "unsupported", "unsupported_script")
            label = f"local pre-commit hook ({language})" if shells_out else "pre-commit hook entry"
            run(c, RULE, dotted(path), value, label, severity=ASK if shells_out else None, line=line)
    for index, fields in repos.items():
        repo, line = fields.get("repo", ("", 1))
        rev = fields.get("rev", ("", line))[0]
        if repo.startswith(("http://", "git://")):
            c.add(RULE, f"repos.{norm(repo)}", f"pre-commit hook repo over an unencrypted URL: {repo}", line=line)
        elif repo not in ("local", "meta", "") and not _SHA.match(rev):
            c.add(
                RULE,
                f"repos.{norm(repo)}@{norm(rev)}",
                f"pre-commit repo {index} pinned by a movable rev",
                severity=ASK,
                line=line,
            )
