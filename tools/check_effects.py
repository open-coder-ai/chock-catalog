#!/usr/bin/env python3
"""Fail if a policy declaring `read_only` ships a guard script that writes.

    python tools/check_effects.py                      # every policy: what CI runs on main
    python tools/check_effects.py --base origin/main   # what a PR touches (tools/select_tests.py scope)
    python tools/check_effects.py --policies a,b       # exactly these policy ids
    python tools/check_effects.py --jobs 1             # serial, e.g. to compare timings

Guards are run concurrently; the report is in policy order, then guard order, whatever order they finish.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import NamedTuple

import yaml
from mechanism import SCRIPT_SUFFIXES, is_event_script
from select_tests import changed_files, policy_ids, select

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "base"

NON_WRITING = {"read_only", "none", "reads_private", "network"}
WRITING = {"writes_workspace", "writes_external", "irreversible"}

CANARIES = {
    "README.md": "# canary\n",
    "src/app.py": "print('canary')\n",
    ".git/config": "[core]\n\trepositoryformatversion = 0\n",
    "notes.txt": "untouched\n",
}


def snapshot(root: Path) -> dict[str, str]:
    """Map every file under `root` to a digest of its contents."""
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() or path.is_symlink():
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                digest = f"unreadable:{exc.errno}"
            out[path.relative_to(root).as_posix()] = digest
    return out


def differences(before: dict[str, str], after: dict[str, str]) -> list[str]:
    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    return (
        [f"created {p}" for p in created] + [f"deleted {p}" for p in deleted] + [f"modified {p}" for p in modified]
    )


def eval_commands(policy_dir: Path) -> list[str]:
    """The argv strings the eval suite invokes this policy's guard with."""
    suite_path = policy_dir / "evals" / "suite.yaml"
    if not suite_path.exists():
        return []
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8")) or {}
    cases = (suite.get("suite") or {}).get("cases") or suite.get("cases") or []
    return [c["execute"]["command"] for c in cases if isinstance(c, dict) and (c.get("execute") or {}).get("command")]


def guard_scripts(policy_dir: Path) -> list[Path]:
    """Every guard this policy ships, shell or Python. A .py one was invisible here before."""
    impl = policy_dir / "implementations"
    return sorted(p for s in SCRIPT_SUFFIXES for p in impl.glob(f"*{s}")) if impl.is_dir() else []


def init_repo(workspace: Path) -> None:
    """A git-event guard reads the staged change, so it needs a repo with a commit to read.

    Background maintenance is off before the commit: git's detached `maintenance run --auto` would
    otherwise hold and delete `.git/objects/maintenance.lock` mid-run and look like a guard's write.
    """
    for args in (
        ["init", "--quiet", "."],
        ["config", "maintenance.auto", "false"],
        ["config", "gc.auto", "0"],
        ["config", "user.email", "effects@chock.invalid"],
        ["config", "user.name", "effects"],
        ["add", "-A"],
        ["commit", "--quiet", "-m", "canary"],
    ):
        subprocess.run(["git", *args], cwd=workspace, capture_output=True, check=False)


def plant(workspace: Path) -> None:
    for rel, content in CANARIES.items():
        dest = workspace / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def interpreter(bash: str, guard: Path) -> str:
    """What runs this guard: this Python for a .py one, bash otherwise -- the runtime's own rule."""
    return sys.executable if guard.suffix == ".py" else bash


def split_command(command: str) -> list[str]:
    """argv as the engine builds it: shlex, or a whitespace split when the quoting does not balance."""
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def run_guard(
    bash: str, guard: Path, command: str | None, workspace: Path, home: Path, scratch: Path, stdin: str | None = None
) -> None:
    """Invoke the guard as its runtime does, inside the throwaway workspace.

    `command` is None for a git-event script: the hook passes it no argv and it reads the
    staged change from git itself. `stdin` is the runner's payload for a script gate, which
    is handed the writes and never reads git.
    """
    env = dict(os.environ, HOME=str(home), TMPDIR=str(scratch), GIT_CONFIG_GLOBAL=str(home / ".gitconfig"))
    argv = [] if command is None else split_command(command)
    try:
        subprocess.run(
            [interpreter(bash, guard), str(guard), *argv],
            cwd=workspace,
            env=env,
            # Never the checker's own stdin: a pre-push script reads refs from it and would wait
            # on a terminal or open pipe until the timeout. Empty stdin is a push of nothing.
            input="" if stdin is None else stdin,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise RuntimeError(f"could not run guard: {exc}") from exc


class Exercise(NamedTuple):
    """How a policy's guards are run: what each is handed, and what it declared it would not do."""

    effects: set[str]
    script_gate: bool
    git_repo: bool
    commands: list[str | None]


def check_guard(bash: str, policy_name: str, guard: Path, how: Exercise) -> list[str]:
    """Run one guard in its own throwaway workspace and report what it wrote."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        workspace, home, scratch = base / "workspace", base / "home", base / "scratch"
        for d in (workspace, home, scratch):
            d.mkdir()
        plant(workspace)
        plant(home)
        if how.git_repo:
            init_repo(workspace)

        payload = None
        if how.script_gate:
            payload = json.dumps({"event": "commit", "repo_root": str(workspace), "writes": {}})
        before = {"workspace": snapshot(workspace), "home": snapshot(home)}
        for command in how.commands:
            try:
                run_guard(bash, guard, command, workspace, home, scratch, stdin=payload)
            except RuntimeError as exc:
                failures.append(f"{policy_name}/{guard.name}: {exc}")
                break
        after = {"workspace": snapshot(workspace), "home": snapshot(home)}

        for where in ("workspace", "home"):
            for diff in differences(before[where], after[where]):
                failures.append(
                    f"{policy_name}/{guard.name} declares {sorted(how.effects & NON_WRITING)} "
                    f"but wrote to the {where}: {diff}"
                )
    return failures


def policy_tasks(policy_dir: Path, bash: str) -> list[Callable[[], list[str]]]:
    """One task per guard the policy ships, in guard order; each returns its own failures.

    A guard is the unit of work, not a policy: one policy ships 16 guards and over half of all the
    runs, so a task per policy leaves most of the machine idle behind it.
    """
    manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    effects = set(manifest.get("effects") or [])
    guards = guard_scripts(policy_dir)

    if not guards or effects & WRITING or not effects & NON_WRITING:
        return []

    policy_id = manifest.get("id") or policy_dir.name
    # A script gate is handed the writes on stdin by the runner; the payload with no writes
    # is what a commit that stages nothing looks like to it.
    script_gate = ((manifest.get("hook") or {}).get("gate") or {}).get("kind") == "script"
    # A git-event script takes no argv, so an eval case's command is not its exercise: running
    # it with none, in a repo with nothing staged, is exactly what the hook does.
    if script_gate or all(is_event_script(g, policy_id) for g in guards):
        commands: list[str | None] = [None]
    else:
        commands = list(eval_commands(policy_dir))
        if not commands:
            message = f"{policy_dir.name}: declares {sorted(effects)} and ships a guard, but no eval case exercises it"
            return [lambda: [message]]

    how = Exercise(effects, script_gate, any(is_event_script(g, policy_id) for g in guards), commands)
    return [partial(check_guard, bash, policy_dir.name, guard, how) for guard in guards]


def scoped_ids(args: argparse.Namespace) -> set[str] | None:
    """The policy ids to check, or None for all. A scope this tool cannot resolve is all, never none."""
    if args.policies is not None:
        wanted = {i for i in args.policies.split(",") if i}
        if not wanted:
            raise SystemExit("--policies needs at least one policy id")
        if unknown := sorted(wanted - set(policy_ids(ROOT))):
            raise SystemExit(f"unknown policy id(s): {', '.join(unknown)}")
        return wanted
    if args.base is None:
        return None
    try:
        full, covered, _ = select(ROOT, changed_files(args.base, ROOT))
    except (SystemExit, SyntaxError, OSError) as exc:
        print(f"{exc}; checking every policy.", file=sys.stderr)
        return None
    return None if full else covered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--policies", help="comma-separated policy ids to check instead of all")
    scope.add_argument("--base", help="check only the policies the diff against this ref touches, or all if shared")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="guards checked at once")
    args = parser.parse_args(argv)

    bash = shutil.which("bash")
    if not bash:
        print("No bash on PATH; cannot observe guard behaviour.", file=sys.stderr)
        return 2

    wanted = scoped_ids(args)
    policy_dirs = sorted(p for p in BASE.iterdir() if p.is_dir() and (wanted is None or p.name in wanted))
    # Each guard runs in its own temp workspace, home and scratch dir with HOME, TMPDIR and the git
    # config pointed at it, and nothing here is shared or written, so guards cannot see each other.
    # Results are read back in submission order: policy order, then guard order.
    with ThreadPoolExecutor(max_workers=max(args.jobs, 1)) as pool:
        pending = [pool.submit(task) for d in policy_dirs for task in policy_tasks(d, bash)]
        failures = [f for future in pending for f in future.result()]
    checked = [d.name for d in policy_dirs if guard_scripts(d)]

    if failures:
        print(f"Declared effects do not match observed behaviour ({len(failures)} problem(s)):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nEither the guard should not write, or the manifest should declare "
            "`writes_workspace`/`writes_external` and accept the EFF-1 approval gate.",
            file=sys.stderr,
        )
        return 1

    print(f"Effects match observed behaviour: {len(checked)} guard-shipping policies checked ({', '.join(checked)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
