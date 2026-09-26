"""Prove a workspace's gates are wired before any scenario is spent on it.

A scenario graded on an agent whose hooks never ran measures the model's manners, not the policy:
the first Windows run did exactly that -- `.chock/bin/` was matched by a global `bin/` ignore, so
every hook Claude Code called was missing, and the agent declined the SQL on its own. The doctor
checks what the agent will execute, with no agent in the loop:

1. every file an agent hook command names exists in the workspace;
2. Claude Code: the PreToolUse command from `.claude/settings.json`, run exactly as Claude Code
   runs it, denies a write of the construct and allows its correct form;
3. repo route: the pre-commit hook refuses a commit of the construct and takes its correct form.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path

#: Where each agent's repo-route hooks live, as `chock sync` writes them.
HOOK_CONFIGS = {
    "claude": [".claude/settings.json"],
    "cursor": [".cursor/hooks.json"],
    "codex": [".codex/hooks.json", ".codex/config.toml"],
    "devin": [".devin/hooks.json"],
    "copilot": [],
}
PROJECT_VARS = ("${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR", "${workspaceFolder}")
PROBE = "src/main/java/com/acme/shop/order/DoctorProbe.java"
_QUERY = 'jdbc.query("SELECT * FROM orders WHERE customer = {}", ROWS{});'
BAD = _QUERY.format("'\" + customer + \"'", "")
GOOD = _QUERY.format("?", ", customer")
_REFERENCED = re.compile(r"""["']?((?:\$\{?\w+\}?[/\\]|\.)?[\w./\\-]+\.(?:py|json|sh|ps1))["']?""")


def probe_source(line: str) -> str:
    return (
        "package com.acme.shop.order;\n\nimport org.springframework.jdbc.core.JdbcTemplate;\n\n"
        f"class DoctorProbe {{\n    void find(String customer) {{\n        {line}\n    }}\n}}\n"
    )


def _in_workspace(workspace: Path, token: str) -> Path | None:
    """The workspace file a command token names, or None when it names something outside it."""
    for var in PROJECT_VARS:
        token = token.replace(var, str(workspace))
    path = Path(token)
    if not path.is_absolute():
        return workspace / path
    return path if workspace in path.parents else None


def referenced_files(workspace: Path, agent: str) -> list[Path]:
    """Files the agent's hook commands name inside the workspace."""
    found: list[Path] = []
    for rel in HOOK_CONFIGS[agent]:
        config = workspace / rel
        if config.is_file():
            for token in _REFERENCED.findall(config.read_text(encoding="utf-8")):
                path = _in_workspace(workspace, token.replace("\\\\", "\\"))
                if path is not None and path not in found:
                    found.append(path)
    return found


def missing_hook_files(workspace: Path, agent: str) -> list[str]:
    return [str(p.relative_to(workspace)) for p in referenced_files(workspace, agent) if not p.exists()]


def _argv(command: str, workspace: Path) -> list[str]:
    for var in PROJECT_VARS:
        command = command.replace(var, str(workspace))
    return [part.strip('"') for part in shlex.split(command, posix=False)]


def claude_pre_tool_use(workspace: Path) -> list[str] | None:
    settings = json.loads((workspace / ".claude" / "settings.json").read_text(encoding="utf-8"))
    for entry in settings.get("hooks", {}).get("PreToolUse", []):
        if "Write" in entry.get("matcher", ""):
            for hook in entry.get("hooks", []):
                if "java-security" in hook.get("command", ""):
                    return _argv(hook["command"], workspace)
    return None


def claude_decides(workspace: Path, argv: list[str], line: str) -> str:
    """What Claude Code's own PreToolUse hook answers for a Write of `line`: deny, or allow."""
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "kit-doctor",
        "cwd": str(workspace),
        "tool_name": "Write",
        "tool_input": {"file_path": str(workspace / PROBE), "content": probe_source(line)},
    }
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(workspace)}
    done = subprocess.run(argv, input=json.dumps(payload), capture_output=True, text=True, env=env, check=False)
    denied = done.returncode == 2 or '"permissionDecision": "deny"' in done.stdout  # noqa: PLR2004 -- Claude's block exit
    return "deny" if denied else "allow"


def commit_decides(workspace: Path, git: Callable, line: str) -> str:
    """What the pre-commit hook answers for a commit of `line`; the tree is left as it was."""
    target = workspace / PROBE
    target.write_text(probe_source(line), encoding="utf-8", newline="\n")
    git(workspace, "add", "--", PROBE)
    done = git(workspace, "commit", "-q", "-m", "kit doctor probe", check=False)
    if done.returncode == 0:
        git(workspace, "reset", "-q", "--hard", "HEAD~1")
        return "allow"
    git(workspace, "reset", "-q", "--", PROBE)
    target.unlink()
    return "deny"


def checks(workspace: Path, state: dict, git: Callable) -> list[tuple[str, bool, str]]:
    """(what was checked, whether it held, what to do when it did not)."""
    results: list[tuple[str, bool, str]] = []
    agent, route = state["agent"], state["route"]
    if route != "repo":
        return [("plugin route: install java-security from the agent's marketplace", True, "")]
    missing = missing_hook_files(workspace, agent)
    fix = "a global gitignore (often `bin/`) may have kept them out of the baseline; run setup again in a new directory"
    results.append((f"{agent}'s hook commands name files that exist", not missing, f"missing {missing}: {fix}"))
    if agent == "claude" and not missing:
        argv = claude_pre_tool_use(workspace)
        results.append(("Claude Code has a java-security PreToolUse hook", argv is not None, "run `chock sync`"))
        if argv is not None:
            verdicts = (claude_decides(workspace, argv, BAD), claude_decides(workspace, argv, GOOD))
            results.append(
                (
                    "Claude Code's hook denies the construct, allows the fix",
                    verdicts == ("deny", "allow"),
                    str(verdicts),
                )
            )
    verdicts = (commit_decides(workspace, git, BAD), commit_decides(workspace, git, GOOD))
    hint = f"{verdicts}: the pre-commit hook is not running the gate; check .git/hooks/pre-commit"
    results.append(("the commit gate refuses the construct, takes the fix", verdicts == ("deny", "allow"), hint))
    return results
