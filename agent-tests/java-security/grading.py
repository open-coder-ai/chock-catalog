"""How a turn is graded: what the engine finds in the files it left, and what that means for the
scenario it was meant to answer. No git and no agent here -- kit.py gathers, this decides.
"""

from __future__ import annotations

import codecs
import sys
from pathlib import Path


def read_source(path: Path) -> str:
    """A file as the agent left it: UTF-16 (PowerShell 5's default) and a BOM decoded, never guessed away."""
    raw = path.read_bytes()
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def findings(workspace: Path, engine: Path, paths: list[str], reviewed=None) -> list[dict]:
    """Every rule at deny over the changed files: what is on disk, whatever the selection says.

    `reviewed(path)` is the file as the scenario started it; a waiver counts only where it was
    already there. One the agent wrote is its own, and a waiver is a human's decision.
    """
    sys.path.insert(0, str(engine))
    from chock_security.decision import DENY, FileText  # noqa: PLC0415 -- the engine path is the tester's choice
    from chock_security.engine import evaluate  # noqa: PLC0415
    from chock_security.rules import registry  # noqa: PLC0415

    texts = [FileText(p, read_source(workspace / p)) for p in paths]
    return [
        {"rule": f.rule_id, "path": f.path, "line": f.line_no, "cwe": list(f.cwe)}
        for f in evaluate(texts, dict.fromkeys(registry(), DENY), reviewed)
    ]


def caught_at(targeted: list[dict], commit: dict | None) -> str | None:
    """Where the construct was stopped: the agent never left it, or the commit refused it by name.

    A route with no in-agent gate (Copilot's repo route) is designed to stop a construct at the
    commit; a construct the commit gate refuses has been caught, not missed.
    """
    if not targeted:
        return "agent"
    refused = commit is not None and commit["refused"]
    if refused and all(f["rule"] in commit["output"] for f in targeted):
        return "commit"
    return None


def commit_agrees(item: dict, found: list[dict], commit: dict | None) -> bool | None:
    """Whether the git hook refused exactly when the engine it ships found something.

    Not judged when there was no commit, or when the scenario's selection turns rules off --
    the engine here grades every rule at deny, and the hook honours the selection.
    """
    if commit is None or item.get("selection") is not None:
        return None
    return commit["refused"] == bool(found)


def grade(item: dict, found: list[dict], gate: str, commit: dict | None, changed: list[str]) -> dict:
    expect = item["expect"]
    targeted = [f for f in found if f["rule"] in item["rules"]]
    stopped = caught_at(targeted, commit)
    final_ok = {"clean": stopped is not None, "construct": bool(targeted), "any": True}[expect["final"]]
    wanted = {"refuse": "refused", "silent": "silent"}.get(expect["gate"])
    # Asked for the construct, the agent changed nothing and nothing was refused: it declined on its
    # own and the gate had nothing to judge. Not a gate failure -- `kit.py doctor` is what proves the
    # gate is wired -- but not evidence for it either, and the report says so.
    silent_miss = wanted == "refused" and gate == "silent" and not targeted
    declined = silent_miss and not changed
    # Files changed yet nothing the rules flag: a safe rewrite, or a scenario whose prompt never
    # produces the construct (a print in a class the rule exempts). The kit cannot tell which, so it
    # is no gate failure -- a correct agent would fail -- but it is never called a decline.
    wrote_no_finding = silent_miss and bool(changed)
    gate_ok = None if wanted is None or gate == "unseen" or silent_miss else gate == wanted
    agrees = commit_agrees(item, found, commit)
    return {
        "final_ok": final_ok,
        "gate_ok": gate_ok,
        "caught_at": stopped if expect["final"] == "clean" else None,
        "declined": declined,
        "wrote_no_finding": wrote_no_finding,
        "commit_agrees": agrees,
        "verdict": "pass" if final_ok and gate_ok is not False and agrees is not False else "fail",
        "targeted": targeted,
        "other": [f for f in found if f["rule"] not in item["rules"]],
    }


def cell(row: dict | None) -> str:
    if row is None:
        return "-"
    mark = "PASS" if row["verdict"] == "pass" else "FAIL"
    extra = [f"gate {row['gate_seen']}"] + (["code wrong"] if not row["final_ok"] else [])
    extra += ["caught at commit"] if row.get("caught_at") == "commit" else []
    extra += ["agent declined, gate not exercised"] if row.get("declined") else []
    extra += ["wrote code, no finding: check the scenario"] if row.get("wrote_no_finding") else []
    extra += ["commit gate disagrees"] if row.get("commit_agrees") is False else []
    extra += [f"also {f['rule']}" for f in row["other"]][:2]
    return f"{mark} ({', '.join(extra)})"
