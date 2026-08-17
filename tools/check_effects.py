#!/usr/bin/env python3
"""Fail if a policy declaring `read_only` ships a guard script that writes.

`spec/methodology.md` defines `read_only` as "reads repo/state but does not write". Every
guard in this catalog declares it, and nothing checked it. The manifest said one thing and the
shell said whatever it said.

This observes the effect rather than reading the source. A lint over shell would have to decide
whether `rm` in `git|rm|kubectl|terraform)` is a command or a `case` pattern, and whether
`echo ... >&2` is a file write -- both appear in `block-destructive.sh`, and both are the kind
of false positive that gets a check deleted within a week. Running the guard and looking at the
filesystem afterwards asks the question the manifest actually answers.

That is the witness principle again, the same one behind coverage refusing to credit `ci-gate`
without an installer and `verify` judging the vendored runner: a claim is worth what an
independent re-derivation says it is worth.

The eval suite supplies the inputs. Each case's `execute.command` is the argv the guard is
invoked with in `chock check --only evals`, so coverage here grows automatically as the suite grows,
and a contributor extending a guard extends its effects check in the same PR.

Scope, stated because a green check must not imply more than it did:
  - Only policies that BOTH declare `read_only` AND ship `implementations/*.sh`. Two today.
  - Only the argv the eval suite exercises. A write on an untested path is not detected.
  - Gate policies are excluded: their behaviour is the framework's vendored runner, not
    catalog content, and is covered by the framework's own tests.

Usage:  python tools/check_effects.py
"""

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

#: Declaring any of these is a claim that the artifact does not write. `writes_workspace` and
#: `writes_external` are the honest declarations for a guard that does, so a policy carrying
#: one of those is skipped rather than failed -- the check is for contradictions, not for
#: discouraging writes.
NON_WRITING = {"read_only", "none", "reads_private", "network"}
WRITING = {"writes_workspace", "writes_external", "irreversible"}

#: Files planted in the throwaway workspace. Content is irrelevant; their hashes are the
#: evidence. A guard that truncates one, or drops a new file beside them, is caught either way.
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


def plant(workspace: Path) -> None:
    for rel, content in CANARIES.items():
        dest = workspace / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def run_guard(bash: str, guard: Path, command: str, workspace: Path, home: Path, scratch: Path) -> None:
    """Invoke the guard exactly as the runtime adapter does, inside the throwaway workspace.

    Output is discarded and the exit code ignored: a guard blocking a command is the normal
    case and says nothing about whether it wrote. Only the filesystem is evidence.

    TMPDIR is redirected outside the observed tree on purpose. `read_only` is about the
    adopter's repo and environment; a guard using `mktemp` is not writing in the sense the
    declaration is about, and failing it would be the over-block that gets a check disabled.
    """
    env = dict(os.environ, HOME=str(home), TMPDIR=str(scratch), GIT_CONFIG_GLOBAL=str(home / ".gitconfig"))
    try:
        subprocess.run(
            [bash, str(guard), *shlex.split(command)],
            cwd=workspace,
            env=env,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        # A guard that will not run cannot be shown to be read-only, so this is reported as a
        # failure by the caller rather than passed over.
        raise RuntimeError(f"could not run guard: {exc}") from exc


def check_policy(policy_dir: Path, bash: str) -> list[str]:
    manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    effects = set(manifest.get("effects") or [])
    guards = sorted(policy_dir.glob("implementations/*.sh"))

    if not guards or effects & WRITING or not effects & NON_WRITING:
        return []

    commands = eval_commands(policy_dir)
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
        # Skipping silently would make this a check that cannot fail.
        print("No bash on PATH; cannot observe guard behaviour.", file=sys.stderr)
        return 2

    policy_dirs = sorted(p for p in BASE.iterdir() if p.is_dir())
    failures = [f for d in policy_dirs for f in check_policy(d, bash)]
    checked = [d.name for d in policy_dirs if any(d.glob("implementations/*.sh"))]

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
