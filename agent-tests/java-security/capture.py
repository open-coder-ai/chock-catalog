"""Capture what an agent really sends its hooks when it writes and edits files.

chock gates a write before it lands only where the agent's write payload is known: Claude
Code's is recorded, Cursor's full-file Write was seen once, and for every other agent the edit
payload was never captured -- so chock installs no pre-write hook there, and the turn's end is
the first check. This records the evidence: a logging hook (`capture_hook.py`) is wired beside
chock's own, for every tool event the agent has, the agent makes a few edits, and the log shows
each payload's event, tool and field shapes.

    python kit.py capture --dir ~/shop-codex            # wire the logger
    ... in the agent: create a file, change a line, change two places in one file ...
    python kit.py capture --dir ~/shop-codex --show     # what arrived
    python kit.py capture --dir ~/shop-codex --stop     # unwire it

The log lives in .git/, so it never shows in the turn's diff; `start` resets the hook configs,
so capture is a session of its own, not part of a scenario. `--stop` removes only the entries
this kit wrote (tagged with its owner); a hook entry without that tag is never touched.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from workspace import git, read_state

HOOK = Path(__file__).resolve().parent / "capture_hook.py"
OWNER = "agent-tests-capture"
#: The kit's agent names, as agentseam spells them.
VENDOR = {
    "claude": "claude_code",
    "cursor": "cursor",
    "codex": "codex_cli",
    "devin": "devin",
    "copilot": "vscode_copilot",
}
#: Every event a write or an edit could reach, in the order a tool call meets them.
EVENTS = ("pre_tool", "post_tool", "file_changed")
PROMPT = """Now, in {vendor}, open this workspace and ask for these three changes, one chat each:

  1. Create src/main/java/com/acme/shop/order/CaptureProbe.java with an empty class CaptureProbe.
  2. In OrderService.java, rename the parameter `status` of withStatus to `wanted`.
  3. In OrderRepository.java, change both "SELECT *" occurrences to "SELECT id, customer".

Then: python kit.py capture --dir {workspace} --show"""


def log_path(workspace: Path) -> Path:
    return workspace / ".git" / "agent-tests-capture.jsonl"


def _agentseam():
    try:
        import agentseam  # noqa: PLC0415 -- installed with chock; only this command needs it
        import agentseam.install  # noqa: PLC0415
    except ImportError:
        sys.exit("capture needs chock's agentseam in this Python: pip install chock")
    return agentseam


def wireable(vendor: str) -> list[str]:
    """The events in EVENTS this agent has a hook for."""
    adapter = _agentseam().adapters.get(vendor)
    return [event for event in EVENTS if event in getattr(adapter, "REVERSE_EVENT_MAP", {})]


def start(workspace: Path, vendor: str) -> str:
    """Wire the logger for every write-reachable event this agent has; returns the config written."""
    seam = _agentseam()
    command = f'"{sys.executable}" "{HOOK}" "{log_path(workspace)}" "{vendor}"'
    # One call for all events: a second install under the same owner replaces the first.
    written = seam.install.install(vendor, wireable(vendor), command, str(workspace), owner=OWNER, fail_closed=False)
    if vendor == "vscode_copilot":
        _complete_copilot(Path(written))
    return str(Path(written).resolve().relative_to(workspace.resolve()))


def _complete_copilot(config: Path) -> None:
    """Give the kit's Copilot entries the `bash` and `powershell` keys agentseam <= 0.3.4 omits.

    Copilot's Windows runtime runs a bare `command` in PowerShell, which cannot execute a quoted
    path; `powershell` mirrors `windows` and `bash` mirrors `command`. Only the kit's entries.
    """
    data = json.loads(config.read_text(encoding="utf-8"))
    changed = False
    for entries in data.get("hooks", {}).values():
        for entry in entries:
            if entry.get("_agentseam") != OWNER:
                continue
            for key, source in (("bash", "command"), ("powershell", "windows")):
                if key not in entry and source in entry:
                    entry[key] = entry[source]
                    changed = True
    if changed:
        config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def _holds_no_hooks(config: Path) -> bool:
    return not any(json.loads(config.read_text(encoding="utf-8")).get("hooks", {}).values())


def stop(workspace: Path, vendor: str) -> None:
    """Unwire the logger. A config the baseline tracks goes back to its exact bytes, not a re-dump."""
    seam = _agentseam()
    config = Path(seam.install.config_path(vendor, str(workspace)))
    seam.install.uninstall(vendor, str(workspace), owner=OWNER)
    rel = str(config.resolve().relative_to(workspace.resolve()))
    if git(workspace, "ls-files", "--", rel).stdout.strip():
        git(workspace, "checkout", "-q", "--", rel)
    elif vendor == "vscode_copilot" and config.is_file() and _holds_no_hooks(config):  # agentseam.json is ours alone
        config.unlink()


def _shape(value, depth: int = 0):
    """A value's structure without its bulk: types, keys, lengths -- what a parser has to handle."""
    if isinstance(value, dict):
        return {key: _shape(item, depth + 1) for key, item in value.items()} if depth < 3 else "{...}"  # noqa: PLR2004
    if isinstance(value, list):
        return [_shape(value[0], depth + 1), f"x{len(value)}"] if value else []
    if isinstance(value, str):
        return f"str({len(value)})"
    return type(value).__name__


def _pick(payload: dict, *keys: str) -> str:
    return next((str(payload[key]) for key in keys if payload.get(key) not in (None, "")), "?")


def summarise(workspace: Path) -> list[str]:
    """One block per captured call: the event, the tool, and the shape of what it carried."""
    path = log_path(workspace)
    if not path.is_file():
        return ["nothing captured yet: is the agent's workspace this one, and did it trust the hooks?"]
    lines = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        entry = json.loads(raw)
        payload = entry["payload"] if isinstance(entry["payload"], dict) else {"(raw)": entry["payload"]}
        event = _pick(payload, "hook_event_name", "hookEventName", "event", "hook")
        tool = _pick(payload, "tool_name", "toolName", "tool")
        lines.append(f"#{number} {entry['agent']}  event={event}  tool={tool}")
        lines.append("   " + json.dumps(_shape(payload)))
    lines.append(f"full payloads: {path} -- they include this machine's paths and session ids; review before sharing")
    return lines


def command(args: argparse.Namespace) -> None:
    """`kit.py capture`: wire the logger, show what it caught, or unwire it."""
    workspace = Path(args.dir).expanduser().resolve()
    vendor = args.vendor or VENDOR[read_state(workspace)["agent"]]
    if args.show:
        print("\n".join(summarise(workspace)))
    elif args.stop:
        stop(workspace, vendor)
        print(f"{vendor}: capture hook removed; the log stays at {log_path(workspace)}")
    else:
        config = start(workspace, vendor)
        print(f"{vendor}: capture hook wired in {config} for {', '.join(wireable(vendor))}")
        print(PROMPT.format(vendor=vendor, workspace=workspace))
