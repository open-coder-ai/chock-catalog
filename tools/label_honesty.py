"""Per-client label wording derived from agentseam's data and the manifests, never typed per policy."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml
from agentseam import matrix
from agentseam.vendor_config import VENDOR_CONFIG
from chock import vendors
from chock.gate.runtime_bundle import pre_tool_can_ask
from chock.plugin import bundle_grade

#: Said by a policy whose declared enforcement no plugin hook carries (a git hook or CI gate, or a
#: `tool_call` warn): the plugin ships its skill text and nothing else.
TEXT_ONLY_SAYS = (
    "text only in a plugin. Nothing in the plugin stops a violation."
    " The plugin does not carry the enforcement the manifest declares"
)
#: Policies whose shipped data tables age inside an installed plugin (BV-1 section 5.3): the label
#: states the oldest table's `as_of`. Which policies is a catalog decision; the date is read from the tables.
DATED_DATA = ("compromised-package-ioc", "verify-mcp-allowlist")
DATED_SAYS = "data as of {as_of}. An installed plugin does not update it. Re-run the install to update it"
#: Command guards that only ever ask (exit 3), never refuse, and let a call through where the engine sets
#: CHOCK_CAN_ASK=0: a catalog decision, since the engine grades every guard as refusing.
#: tests/build_tools/test_registry_labels.py holds each to a guard with no refusing exit.
ASK_ONLY_GUARDS = ("ask-credential-switching",)
GUARD_ASKS = "asks before a matched shell command runs"
GUARD_NOT_ENFORCED = "not enforced (this client cannot prompt before a shell command)"
#: Added where the matrix records a pre-tool hook that lets the call through on an error, on vendor docs alone.
FAIL_OPEN_SAYS = (
    ". If the hook errors, the action goes through. That comes from the vendor's docs only."
    " Chock has not seen it happen in a live run"
)
CANNOT = "because this client cannot prompt there"
CANNOT_EITHER = "because this client cannot prompt at either point"
#: Where the engine's asking gate text starts, after any guard text.
GATE_ASKS = re.compile(r"(?:^|; |\. )[Aa]sks ")
#: An asking gate wired at the write and at turn end, keyed (honours at the write, honours at turn end).
ASK_TAILS = {
    (True, True): "asks on an agent's file writes and at turn end",
    (True, False): f"asks on an agent's file writes. It refuses at turn end, {CANNOT}",
    (False, True): f"refuses an agent's file writes, {CANNOT}. It asks at turn end",
    (False, False): f"refuses an agent's file writes and refuses at turn end, {CANNOT_EITHER}",
}
#: An asking gate wired at turn end only, keyed by whether the client honours an ask there.
ASK_STOP_ONLY = {
    True: "asks at turn end only. It does not check a file write when it happens",
    False: f"refuses at turn end only, {CANNOT}. It does not check a file write when it happens",
}
#: One bundle read by two products that spell the wired event differently, one able to prompt and one not.
GUARD_SPLIT = {
    "vscode_copilot": f"{GUARD_ASKS} in VS Code. Not enforced in Copilot CLI, because it cannot prompt there",
}


def status_label(manifest: dict) -> dict | None:
    """A badge for a deprecated policy, naming what replaced it; draft and production show none (BV-C3)."""
    lifecycle = manifest.get("lifecycle") or {}
    if lifecycle.get("status") != "deprecated":
        return None
    says = "deprecated" + (f": use {lifecycle['replacement_id']}" if lifecycle.get("replacement_id") else "")
    says += f" (since {str(lifecycle['deprecated_at'])[:10]})" if lifecycle.get("deprecated_at") else ""
    return {"keyword": "deprecated", "says": says}


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
        return FAIL_OPEN_SAYS
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

    tail = ASK_TAILS[honours(pre_tool), honours(stop)] if writes else ASK_STOP_ONLY[honours(stop)]
    if not honours(pre_tool if writes else stop):
        grade = bundle_grade.BLOCKS if writes else bundle_grade.STOP_ONLY
    # A guard's half comes first: the engine joins it with "; " (before VOICE-3a) or ". ".
    guard = says[: GATE_ASKS.search(says).start()]
    return grade, f"{guard}. {tail[:1].upper()}{tail[1:]}" if guard else tail


def guard_can_ask(hooks_text: str, agent: str) -> set[bool]:
    """CHOCK_CAN_ASK at each event a guard is wired at, from the engine's own map (agentseam `verdicts.gates`).

    Every spelling of a wired event counts (Copilot: VS Code's PreToolUse, Copilot CLI's preToolUse); an
    event the map does not list gets 0, as the engine passes.
    """
    can_ask = pre_tool_can_ask(agent)
    values: set[bool] = set()
    for event in bundle_grade.events_for(json.loads(hooks_text), "--guard"):
        values |= {v for name, v in can_ask.items() if name.lower() == event.lower()} or {False}
    return values


def honest_guard(policy_id: str, grade: int, says: str, hooks_text: str, agent: str) -> tuple[int, str]:
    """An ask-only guard's label: it asks where the client prompts at the wired event, and is not enforced elsewhere."""
    if policy_id not in ASK_ONLY_GUARDS or grade != bundle_grade.BLOCKS:
        return grade, says
    values = guard_can_ask(hooks_text, agent)
    if values == {True}:
        return bundle_grade.ASKS, GUARD_ASKS
    if True not in values:
        return bundle_grade.ADVISORY, GUARD_NOT_ENFORCED
    if agent not in GUARD_SPLIT:
        sys.exit(f"{policy_id}: {agent} prompts at some spellings of its wired event only; add GUARD_SPLIT wording")
    return bundle_grade.ASKS, GUARD_SPLIT[agent]
