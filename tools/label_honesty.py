"""Per-client label wording derived from agentseam's data and the manifests, never typed per policy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from agentseam import matrix
from agentseam.vendor_config import VENDOR_CONFIG
from chock import vendors
from chock.plugin import bundle_grade

#: Said by a policy whose declared enforcement no plugin hook carries (a git hook or CI gate, or a
#: `tool_call` warn): the plugin ships its skill text and nothing else.
TEXT_ONLY_SAYS = "text only in a plugin: nothing in the plugin stops a violation; the enforcement the manifest declares is not carried by a plugin"
#: Policies whose shipped data tables age inside an installed plugin (BV-1 section 5.3): the label
#: states the oldest table's `as_of`. Which policies is a catalog decision; the date is read from the tables.
DATED_DATA = ("compromised-package-ioc", "verify-mcp-allowlist")
DATED_SAYS = "data as of {as_of}; an installed plugin does not update it: re-running the install is the update"


def status_label(manifest: dict) -> dict:
    """The manifest's `lifecycle.status`, and what replaced a deprecated policy."""
    lifecycle = manifest.get("lifecycle") or {}
    status = str(lifecycle.get("status") or "unknown")
    says = f"lifecycle status: {status}"
    if status == "deprecated":
        says = "deprecated" + (f": use {lifecycle['replacement_id']}" if lifecycle.get("replacement_id") else "")
        says += f" (since {str(lifecycle['deprecated_at'])[:10]})" if lifecycle.get("deprecated_at") else ""
    return {"keyword": status, "says": says}


def data_label(policy_dir: Path) -> dict | None:
    """The oldest `as_of` among a dated-data policy's tables, with what re-running the install does."""
    manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8"))
    if manifest["id"] not in DATED_DATA:
        return None
    dates = []
    for table in sorted((policy_dir / "implementations").rglob("data/*.json")):
        as_of = json.loads(table.read_text(encoding="utf-8")).get("as_of")
        if as_of:
            dates.append(str(as_of))
    if not dates:
        sys.exit(f"{manifest['id']}: DATED_DATA lists it but no table has an as_of")
    return {"as_of": min(dates), "says": DATED_SAYS.format(as_of=min(dates))}


def fail_open_qualifier(agent: str) -> str:
    """What to add where the matrix records a fail-open pre-tool hook resting on vendor docs alone."""
    unwitnessed = matrix.basis(agent) == "vendor-docs"
    if matrix.capability(agent, "pre_tool")["fail_mode"] == matrix.FAIL_OPEN and unwitnessed:
        return "; fails open: a hook error lets the call proceed (vendor docs only, not witnessed)"
    return ""


def honest_asks(grade: int, says: str, hooks_text: str, agent: str) -> tuple[int, str]:
    """Regrade an asking gate by what each wired event honours (agentseam `verdicts.gates`).

    A client that cannot prompt at an event degrades the engine's `ask` to a block there, so the
    label says "refuses" for that event and keeps "asks" only where `honours_escalate` is true.
    """
    if grade != bundle_grade.ASKS:
        return grade, says
    doc = json.loads(hooks_text)
    gates = VENDOR_CONFIG[agent]["verdicts"]["gates"]
    pre_tool, stop = vendors.pre_tool_event(agent), vendors.stop_event(agent)
    writes = pre_tool in bundle_grade.events_for(doc, "--gate")

    def honours(event: str) -> bool:
        return bool(gates.get(event, {}).get("honours_escalate"))

    cannot = "(this client cannot prompt there)"
    turn_end = "asks at turn end" if honours(stop) else f"refuses at turn end {cannot}"
    only = "asks at turn end only" if honours(stop) else f"refuses at turn end only {cannot}"
    if writes:
        on_writes = (
            "asks on an agent's file writes" if honours(pre_tool) else f"refuses an agent's file writes {cannot}"
        )
        tail = f"{on_writes}; {turn_end}"
    else:
        tail = f"{only}; the write itself is not judged"
    if not honours(pre_tool if writes else stop):
        grade = bundle_grade.BLOCKS if writes else bundle_grade.STOP_ONLY
    return grade, says[: says.index("asks ")] + tail
