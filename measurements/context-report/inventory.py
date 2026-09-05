"""Inventory chock's built plugin bundles as context-report subjects, one per (policy, format)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Per build format: the target agent id context-report knows, the variable the client sets to
# the plugin's root, and where the bundle declares its hooks. Facts about chock's bundle layout.
FORMATS: dict[str, dict[str, str]] = {
    "claude": {
        "target": "claude_code",
        "root_var": "CLAUDE_PLUGIN_ROOT",
        "hooks": "hooks/hooks.json",
    },
    "codex": {
        "target": "codex_cli",
        "root_var": "PLUGIN_ROOT",
        "hooks": "hooks/hooks.json",
    },
    "copilot": {
        "target": "copilot",
        "root_var": "PLUGIN_ROOT",
        "hooks": "com.github.copilot/hooks/hooks.json",
    },
    "cursor": {
        "target": "cursor",
        "root_var": "CURSOR_PLUGIN_ROOT",
        "hooks": "hooks/hooks.json",
    },
}


def _commands(hooks_file: Path) -> list[str]:
    """Every `command` string under any event key, in declaration order."""
    if not hooks_file.is_file():
        return []
    doc = json.loads(hooks_file.read_text(encoding="utf-8"))
    out: list[str] = []
    for entries in doc.get("hooks", {}).values():
        for entry in entries:
            if "command" in entry:  # cursor: flat entries
                out.append(entry["command"])
            for hook in entry.get("hooks", []):  # claude/codex/copilot: matcher wrapper
                if "command" in hook:
                    out.append(hook["command"])
    return out


def inventory(bundles: Path) -> list[dict]:
    targets: list[dict] = []
    for fmt, facts in FORMATS.items():
        for bundle in sorted(p for p in (bundles / fmt).iterdir() if p.is_dir()):
            cmds = _commands(bundle / facts["hooks"])
            targets.append(
                {
                    "subject_name": f"chock/{bundle.name}",
                    "subject_kind": "plugin",
                    "path": str(bundle.relative_to(bundles)),
                    "target": facts["target"],
                    "format": fmt,
                    "plugin_root_var": facts["root_var"],
                    "hook_commands": cmds,
                    "has_hook": bool(cmds),
                }
            )
    return targets


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--bundles", required=True, help="dir holding <format>/<policy>/ bundles"
    )
    ap.add_argument("--out", required=True, help="where to write the inventory JSON")
    args = ap.parse_args(argv)
    targets = inventory(Path(args.bundles))
    Path(args.out).write_text(json.dumps(targets, indent=2) + "\n", encoding="utf-8")
    hooked = sum(t["has_hook"] for t in targets)
    sys.stderr.write(f"{len(targets)} subjects, {hooked} with a hook command\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
