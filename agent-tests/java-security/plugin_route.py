"""The plugin route: a plain repository, and the plugin the agent installed from its marketplace.

Most adopters will never run `chock init`. They open an ordinary repository, install
java-security from their agent's marketplace, and start working. There is no git hook, no
AGENTS.md line and no `.chock/` on this route, so the only gate is the one the plugin brings,
and the doctor proves that one before a scenario is spent on it:

1. the workspace really is plain -- nothing chock wrote is in it;
2. Claude Code: the plugin is installed, at the version this catalog tests;
3. the interpreter its hook command names is on PATH (the hook runs `python3`, which a Windows
   machine often does not have);
4. its PreToolUse hook, run as Claude Code runs it, denies the construct and allows the fix, as
   a Write and as an Edit.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import doctor

NAME = "java-security"
MANIFEST = Path(__file__).resolve().parents[2] / "base" / NAME / "manifest.yaml"
#: What `chock init` / `chock sync` leave in a repository; none of it belongs on this route.
CHOCK_FILES = (".chock", ".agents", "chock.lock")
PLUGIN_ROOT_VARS = ("${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT")
INSTALL = (
    "in Claude Code: /plugin marketplace add open-coder-ai/chock-claude-plugins, then "
    f"/plugin install {NAME}@chock -- or pass --plugin-dir <the installed plugin>"
)


def catalog_version() -> tuple[int, ...]:
    found = re.search(r'^version:\s*"?([\d.]+)"?', MANIFEST.read_text(encoding="utf-8"), re.MULTILINE)
    return _parse(found.group(1)) if found else (0,)


def _parse(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version)[:3]) or (0,)


def _manifest(root: Path) -> dict:
    path = root / ".claude-plugin" / "plugin.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def installed(home: Path) -> list[Path]:
    """Every Claude-format java-security plugin under Claude Code's plugin store, newest first."""
    store = home / ".claude" / "plugins"
    roots = (
        [p.parent.parent for p in store.rglob("plugin.json") if p.parent.name == ".claude-plugin"]
        if store.is_dir()
        else []
    )
    ours = [root for root in roots if _manifest(root).get("name") == NAME]
    return sorted(ours, key=lambda root: _parse(str(_manifest(root).get("version", "0"))), reverse=True)


def hook_argv(root: Path, workspace: Path) -> list[str] | None:
    """The plugin's PreToolUse command for writes, as Claude Code would run it."""
    try:
        hooks = json.loads((root / "hooks" / "hooks.json").read_text(encoding="utf-8")).get("hooks", {})
    except (OSError, ValueError):
        return None
    for entry in hooks.get("PreToolUse", []):
        if "Write" in entry.get("matcher", ""):
            for hook in entry.get("hooks", []):
                command = hook.get("command", "")
                for var in PLUGIN_ROOT_VARS:
                    command = command.replace(var, str(root))
                return doctor._argv(command, workspace)
    return None


def checks(workspace: Path, state: dict) -> list[tuple[str, bool, str]]:
    """(what was checked, whether it held, what to do when it did not)."""
    leftovers = [name for name in CHOCK_FILES if (workspace / name).exists()]
    results = [
        (
            "the repository is plain: nothing chock wrote is in it",
            not leftovers,
            f"found {leftovers}: set up a new directory with --route plugin",
        )
    ]
    if state["agent"] != "claude":
        note = f"{state['agent']}: install {NAME} from its marketplace; the doctor probes only Claude Code's plugin"
        return [*results, (note, True, "")]
    given = state.get("plugin_dir")
    roots = [Path(given).expanduser().resolve()] if given else installed(Path.home())
    if not roots or not _manifest(roots[0]):
        return [*results, (f"Claude Code has the {NAME} plugin installed", False, INSTALL)]
    root, want = roots[0], catalog_version()
    have = str(_manifest(root).get("version", "?"))
    fresh = _parse(have) >= want
    wanted = ".".join(map(str, want))
    results.append(
        (
            f"the installed plugin ({have}, {root}) is this catalog's {NAME} ({wanted}) or newer",
            fresh,
            "the scenarios test rules an older plugin does not have: /plugin marketplace update chock",
        )
    )
    argv = hook_argv(root, workspace)
    if argv is None:
        return [*results, ("the plugin has a PreToolUse hook for writes", False, "reinstall the plugin")]
    interpreter = shutil.which(argv[0])
    results.append(
        (
            f"the hook's interpreter `{argv[0]}` is on PATH",
            interpreter is not None,
            "Claude Code cannot start this hook, so nothing is gated: put a Python 3 on PATH under that name",
        )
    )
    if interpreter is not None:
        for tool in ("Write", "Edit"):
            verdicts = (
                doctor.claude_decides(workspace, argv, doctor.BAD, tool),
                doctor.claude_decides(workspace, argv, doctor.GOOD, tool),
            )
            results.append(
                (
                    f"the plugin's hook denies the construct, allows the fix ({tool})",
                    verdicts == ("deny", "allow"),
                    f"{verdicts}: the plugin is not judging this write",
                )
            )
    return results
