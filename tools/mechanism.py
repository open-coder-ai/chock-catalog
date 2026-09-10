"""The one classifier for what actually enforces a policy, read from what the policy ships.

Three tools need this answer and each had its own copy: check_registry.py labelled the
registry, check_readme.py counted the README's badges and tier tables, and the brand assets
and figures read the label check_registry.py had blessed. Copies drift, and when they do the
repo publishes two different numbers for the same question.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

#: A policy whose check cannot be expressed as a declarative gate ships its own script, named
#: for the git event that runs it. The hook runs it, so its ceiling is the gate's.
GIT_EVENTS = ("pre-commit", "pre-push")
SCRIPT_SUFFIXES = (".py", ".sh")

GATE = "gate"
EVENT_SCRIPT = "event_script"
GUARD = "guard"
NONE = "none"

#: What each kind can actually promise. The wording is the registry's and the README's alike.
CEILING = {
    GATE: "enforced-at-commit",
    EVENT_SCRIPT: "enforced-at-commit",
    GUARD: "best-effort (pre-tool-use, once hooks are installed; fails open if the hook crashes)",
    NONE: "advisory",
}


def is_event_script(path: Path, policy_id: str) -> bool:
    """True when `path` is named for a git event, so the hook runs it, not a tool call."""
    return path.stem in {f"{policy_id}-{event}" for event in GIT_EVENTS}


def event_scripts(policy_dir: Path, policy_id: str) -> list[Path]:
    """The policy's git-event scripts, in a stable order."""
    impl = Path(policy_dir) / "implementations"
    if not impl.is_dir():
        return []
    return sorted(
        impl / f"{policy_id}-{event}{suffix}"
        for event in GIT_EVENTS
        for suffix in SCRIPT_SUFFIXES
        if (impl / f"{policy_id}-{event}{suffix}").exists()
    )


def command_guards(policy_dir: Path, policy_id: str) -> list[Path]:
    """Guards invoked with a command's argv: the in-agent kind, never the event scripts."""
    impl = Path(policy_dir) / "implementations"
    if not impl.is_dir():
        return []
    return sorted(
        p
        for suffix in SCRIPT_SUFFIXES
        for p in impl.glob(f"*{suffix}")
        if not is_event_script(p, policy_id)
    )


def classify(policy_dir: Path, manifest: dict[str, Any]) -> tuple[str, str]:
    """Return (kind, the mechanism label), strongest mechanism first."""
    policy_id = str(manifest.get("id") or Path(policy_dir).name)
    gate = (manifest.get("hook") or {}).get("gate") or {}
    if gate.get("kind"):
        return GATE, str(gate["kind"])
    if event_scripts(policy_dir, policy_id):
        return EVENT_SCRIPT, "commit-time guard script"
    if command_guards(policy_dir, policy_id):
        return GUARD, "guard script"
    return NONE, "rule text only"
