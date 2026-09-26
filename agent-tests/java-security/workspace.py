"""The workspace an agent works in: a git repository, and the state the kit keeps in its .git.

Nothing here knows about scenarios or grading; kit.py drives it, doctor.py checks it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

STATE = "agent-tests.json"
RESULTS = "agent-tests-results.jsonl"
BASELINE = "agent-tests-baseline"
SCENARIO_BASE = "agent-tests-scenario"
#: What an agent, an IDE or a build keeps beside the code: never the turn's work, and never wiped
#: between scenarios -- a permission granted in .claude/settings.local.json must outlive a reset,
#: or every scenario re-asks it and the runs stop being comparable.
LOCAL_ONLY = (
    ".claude/settings.local.json",
    ".vscode/",
    ".idea/",
    "*.iml",
    "target/",
    "build/",
    ".gradle/",
    "out/",
    ".DS_Store",
)
#: How much of the commit hook's answer is kept: enough to name every rule it refused.
COMMIT_OUTPUT = 4000


def git(workspace: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """git with paths printed as they are: unquoted, UTF-8, whatever the machine's settings."""
    argv = ["git", "-c", "core.quotePath=false", *args]
    return subprocess.run(argv, cwd=workspace, capture_output=True, text=True, encoding="utf-8", check=check)


def state_path(workspace: Path) -> Path:
    return workspace / ".git" / STATE


def write_state(workspace: Path, state: dict) -> None:
    state_path(workspace).write_text(json.dumps(state, indent=2), encoding="utf-8", newline="\n")


def read_state(workspace: Path) -> dict:
    path = state_path(workspace)
    if not path.is_file():
        sys.exit(f"{workspace} is not a kit workspace; run `python kit.py setup --dir {workspace}` first")
    return json.loads(path.read_text(encoding="utf-8"))


def changed_files(workspace: Path) -> list[str]:
    """Every file the turn added or changed, NUL-separated so a space or an accent in a path survives."""
    tracked = git(workspace, "diff", "-z", "--name-only", "--diff-filter=ACMR", SCENARIO_BASE).stdout.split("\0")
    untracked = git(workspace, "ls-files", "-z", "--others", "--exclude-standard").stdout.split("\0")
    return sorted({p for p in tracked + untracked if p and not p.startswith((".chock/", ".agents/"))})


def commit_gate(workspace: Path) -> dict | None:
    """Commit the turn's work as a developer would; the pre-commit hook answers or it does not.

    None when there is nothing to commit -- the agent committed it already, and its own commit
    went through the same hook -- so git's "nothing to commit" is never read as a refusal.
    """
    git(workspace, "add", "-A")
    if git(workspace, "diff", "--cached", "--quiet", check=False).returncode == 0:
        return None
    done = git(workspace, "commit", "-q", "-m", "agent turn", check=False)
    return {"refused": done.returncode != 0, "output": (done.stderr or done.stdout).strip()[-COMMIT_OUTPUT:]}
