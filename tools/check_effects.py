#!/usr/bin/env python3
"""Fail if a policy declaring `read_only` ships a guard script that writes."""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

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


#: A script named for a git event is run by the installed hook at that event, with no argv.
GIT_EVENTS = ("pre-commit", "pre-push")
GUARD_SUFFIXES = (".sh", ".py")


def guard_scripts(policy_dir: Path) -> list[Path]:
    """Every guard this policy ships, shell or Python. A .py one was invisible here before."""
    return sorted(p for s in GUARD_SUFFIXES for p in policy_dir.glob(f"implementations/*{s}"))


def is_event_script(guard: Path, policy_id: str) -> bool:
    """True when the hook runs this script at a git event rather than on a tool call."""
    return guard.stem in {f"{policy_id}-{event}" for event in GIT_EVENTS}


def init_repo(workspace: Path) -> None:
    """A git-event guard reads the staged change, so it needs a repo with a commit to read."""
    for args in (
        ["init", "--quiet", "."],
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


def run_guard(bash: str, guard: Path, command: str | None, workspace: Path, home: Path, scratch: Path) -> None:
    """Invoke the guard as its runtime does, inside the throwaway workspace.

    `command` is None for a git-event script: the hook passes it no argv and it reads the
    staged change from git itself.
    """
    env = dict(os.environ, HOME=str(home), TMPDIR=str(scratch), GIT_CONFIG_GLOBAL=str(home / ".gitconfig"))
    argv = [] if command is None else shlex.split(command)
    try:
        subprocess.run(
            [interpreter(bash, guard), str(guard), *argv],
            cwd=workspace,
            env=env,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise RuntimeError(f"could not run guard: {exc}") from exc


def check_policy(policy_dir: Path, bash: str) -> list[str]:
    manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    effects = set(manifest.get("effects") or [])
    guards = guard_scripts(policy_dir)

    if not guards or effects & WRITING or not effects & NON_WRITING:
        return []

    policy_id = manifest.get("id") or policy_dir.name
    # A git-event script takes no argv, so an eval case's command is not its exercise: running
    # it with none, in a repo with nothing staged, is exactly what the hook does.
    if all(is_event_script(g, policy_id) for g in guards):
        commands: list[str | None] = [None]
    else:
        commands = list(eval_commands(policy_dir))
        if not commands:
            return [f"{policy_dir.name}: declares {sorted(effects)} and ships a guard, but no eval case exercises it"]

    failures: list[str] = []
    for guard in guards:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace, home, scratch = base / "workspace", base / "home", base / "scratch"
            for d in (workspace, home, scratch):
                d.mkdir()
            plant(workspace)
            plant(home)
            if any(is_event_script(g, policy_id) for g in guards):
                init_repo(workspace)

            before = {"workspace": snapshot(workspace), "home": snapshot(home)}
            for command in commands:
                try:
                    run_guard(bash, guard, command, workspace, home, scratch)
                except RuntimeError as exc:
                    failures.append(f"{policy_dir.name}/{guard.name}: {exc}")
                    break
            after = {"workspace": snapshot(workspace), "home": snapshot(home)}

            for where in ("workspace", "home"):
                for diff in differences(before[where], after[where]):
                    failures.append(
                        f"{policy_dir.name}/{guard.name} declares {sorted(effects & NON_WRITING)} "
                        f"but wrote to the {where}: {diff}"
                    )
    return failures


def main() -> int:
    bash = shutil.which("bash")
    if not bash:
        print("No bash on PATH; cannot observe guard behaviour.", file=sys.stderr)
        return 2

    policy_dirs = sorted(p for p in BASE.iterdir() if p.is_dir())
    failures = [f for d in policy_dirs for f in check_policy(d, bash)]
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
