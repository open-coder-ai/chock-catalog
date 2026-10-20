"""Per-client label wording derived from agentseam's data and the manifests, never typed per policy."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NamedTuple

import yaml
from agentseam import matrix
from agentseam.matrix_evidence import claim_basis
from agentseam.matrix_terms import CLAIM_FAIL_MODE
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
#: Added where the matrix records a pre-tool hook that lets the call through on an error, on every
#: client whose cell says so; how that was established follows, by the basis of the fail-mode claim.
FAIL_OPEN_SAYS = ". If the hook errors, the action goes through"
FAIL_OPEN_BASIS = {
    matrix.BASIS_LIVE: " (measured)",
    matrix.BASIS_LIVE_PARTIAL: " (not witnessed; the vendor's row is only partly live-run)",
    "vendor-source": " (vendor source only, not witnessed)",
    "vendor-docs": " (vendor docs only, not witnessed)",
}
CANNOT = "because this client cannot prompt there"
CANNOT_EITHER = "because this client cannot prompt at either point"
CANNOT_SHELL = "because this client cannot prompt before a shell command"
#: The engine's own words for a refusing guard (chock.plugin.bundle_grade); a test pins them.
GUARD_SAYS = "refuses a matched shell command before it runs"
#: Where the engine's asking gate text starts, after any guard text: joined with "; " (before VOICE-3a) or ". ".
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
#: A blocking gate with cases it answers ask (the description's "asks"), keyed like ASK_TAILS: the ask
#: degrades to a refusal where the client cannot prompt, so the label says which it is at each point.
MIXED_SAYS = "where its description says it asks, it"
MIXED_TAILS = {
    (True, True): f"{MIXED_SAYS} asks at the write and at turn end",
    (True, False): f"{MIXED_SAYS} asks at the write and refuses at turn end, {CANNOT}",
    (False, True): f"{MIXED_SAYS} refuses at the write, {CANNOT}, and asks at turn end",
    (False, False): f"{MIXED_SAYS} refuses at both points, {CANNOT_EITHER}",
}
MIXED_STOP_ONLY = {
    True: f"{MIXED_SAYS} asks at turn end",
    False: f"{MIXED_SAYS} refuses at turn end, {CANNOT}",
}
#: A refusing guard with cases it answers ask, by CHOCK_CAN_ASK at the events it is wired at.
GUARD_MIXED = {True: f"{MIXED_SAYS} asks", False: f"{MIXED_SAYS} refuses, {CANNOT_SHELL}"}
GUARD_MIXED_SPLIT = {
    "vscode_copilot": f"{MIXED_SAYS} asks in VS Code and refuses in Copilot CLI, because it cannot prompt there",
}


class Asks(NamedTuple):
    """Which of a policy's units have an executed eval case they answer with ask."""

    gate: bool
    guard: bool


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


def fail_open_basis(agent: str) -> str | None:
    """The basis of the matrix's fail-mode claim for a fail-open pre-tool hook, else None.

    agentseam's own rule resolves it: a partly live-run row backs only the events it observed, and
    an unobserved one falls back to what the rest of the row rests on.
    """
    if matrix.capability(agent, "pre_tool")["fail_mode"] != matrix.FAIL_OPEN:
        return None
    return str(claim_basis(matrix.MATRIX[agent], "pre_tool", CLAIM_FAIL_MODE) or matrix.basis(agent))


def fail_open_qualifier(agent: str) -> str:
    """What to add where the matrix records a fail-open pre-tool hook, and how that was established."""
    basis = fail_open_basis(agent)
    if basis is None:
        return ""
    if basis not in FAIL_OPEN_BASIS:
        sys.exit(f"{agent}: the fail-mode basis {basis!r} has no label wording; add it to FAIL_OPEN_BASIS")
    return FAIL_OPEN_SAYS + FAIL_OPEN_BASIS[basis]


def asks_in_evals(policy_dir: Path, gate_text: str | None) -> Asks:
    """Which units the executed eval cases prove answer ask: a `command` case drives the guard, any other the gate.

    An `action: ask` gate asks by design and honest_asks already words it, so its gate half counts as none.
    """
    suite = policy_dir / "evals" / "suite.yaml"
    if not suite.is_file():
        return Asks(gate=False, guard=False)
    loaded = yaml.safe_load(suite.read_text(encoding="utf-8")) or {}
    block = loaded.get("suite") or loaded.get("eval_suite") or {}
    runs = [c["execute"] for c in block.get("cases") or block.get("test_cases") or [] if c.get("execute")]
    asked = [run for run in runs if run.get("expect") == "ask"]
    action = str((json.loads(gate_text) if gate_text else {}).get("action") or "block")
    gate = action == "block" and any("command" not in run for run in asked)
    return Asks(gate, any("command" in run for run in asked))


def _honours(agent: str, event: str) -> bool:
    """Whether the client honours an ask at `event` (agentseam `verdicts.gates`)."""
    return bool(VENDOR_CONFIG[agent]["verdicts"]["gates"].get(event, {}).get("honours_escalate"))


def honest_asks(grade: int, says: str, hooks_text: str, agent: str) -> tuple[int, str]:
    """Regrade an asking gate by what each wired event honours (agentseam `verdicts.gates`).

    A client that cannot prompt at an event degrades the engine's `ask` to a block there, so the
    label says "refuses" for that event and keeps "asks" only where `honours_escalate` is true.
    """
    if grade != bundle_grade.ASKS:
        return grade, says
    doc = json.loads(hooks_text)
    pre_tool, stop = vendors.pre_tool_event(agent), vendors.stop_event(agent)
    writes = pre_tool in bundle_grade.events_for(doc, "--gate")
    tail = (
        ASK_TAILS[_honours(agent, pre_tool), _honours(agent, stop)] if writes else ASK_STOP_ONLY[_honours(agent, stop)]
    )
    if not _honours(agent, pre_tool if writes else stop):
        grade = bundle_grade.BLOCKS if writes else bundle_grade.STOP_ONLY
    # A guard's half comes first: the engine joins it with "; " (before VOICE-3a) or ". ".
    guard = says[: GATE_ASKS.search(says).start()]
    return grade, f"{guard}. {_sentence(tail)}" if guard else tail


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


def _by_can_ask(hooks_text: str, agent: str, whole: dict[bool, str], split: tuple[str, dict[str, str]]) -> str:
    """A guard's wording by CHOCK_CAN_ASK at its wired events: one answer, or a two-product client's named split."""
    values = guard_can_ask(hooks_text, agent)
    if len(values) == 1:
        return whole[True in values]
    name, wording = split
    if agent not in wording:
        sys.exit(f"{agent} prompts at some spellings of its wired event only; add {name} wording")
    return wording[agent]


def honest_guard(policy_id: str, grade: int, says: str, hooks_text: str, agent: str) -> tuple[int, str]:
    """An ask-only guard's label: it asks where the client prompts at the wired event, and is not enforced elsewhere."""
    if policy_id not in ASK_ONLY_GUARDS or grade != bundle_grade.BLOCKS:
        return grade, says
    whole = {True: GUARD_ASKS, False: GUARD_NOT_ENFORCED}
    said = _by_can_ask(hooks_text, agent, whole, ("GUARD_SPLIT", GUARD_SPLIT))
    return (bundle_grade.ADVISORY if said == GUARD_NOT_ENFORCED else bundle_grade.ASKS), said


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:]


def _halves(says: str) -> tuple[str, str]:
    """(the engine's guard text, the gate text after it), either empty when the package has no such unit."""
    if not says.startswith(GUARD_SAYS):
        return "", says
    return GUARD_SAYS, says[len(GUARD_SAYS) :].removeprefix("; ").removeprefix(". ")


def _mixed_gate(doc: dict, agent: str) -> str:
    pre_tool, stop = vendors.pre_tool_event(agent), vendors.stop_event(agent)
    if pre_tool in bundle_grade.events_for(doc, "--gate"):
        return MIXED_TAILS[_honours(agent, pre_tool), _honours(agent, stop)]
    return MIXED_STOP_ONLY[_honours(agent, stop)]


def honest_mixed(grade: int, says: str, hooks_text: str, agent: str, asks: Asks) -> tuple[int, str]:
    """Say what a blocking unit's ask cases do on this client: ask where it prompts, refuse where it cannot.

    The grade stays, since the unit refuses its block cases everywhere. Only the sentence the description's
    "asks" rests on changes, so a client that cannot prompt reads "refuses" there (catalog review M1).
    """
    if grade in (bundle_grade.ADVISORY, bundle_grade.WARNS):
        return grade, says
    guard, gate = _halves(says)
    split = ("GUARD_MIXED_SPLIT", GUARD_MIXED_SPLIT)
    guard_tail = _by_can_ask(hooks_text, agent, GUARD_MIXED, split) if guard and asks.guard else ""
    gate_tail = _mixed_gate(json.loads(hooks_text), agent) if gate and asks.gate else ""
    if not (guard_tail or gate_tail):
        return grade, says
    guard = f"{guard}. {_sentence(guard_tail)}" if guard_tail else guard
    gate = f"{gate}. {_sentence(gate_tail)}" if gate_tail else gate
    return grade, f"{guard}. {_sentence(gate)}" if guard and gate else guard or gate
