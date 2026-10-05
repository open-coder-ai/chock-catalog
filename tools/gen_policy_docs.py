#!/usr/bin/env python3
"""Generate docs/<policy-id>/README.md for every published policy."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from policy_doc_text import CEILING, PRIMITIVE, SURFACES, TOOL_USE_REACH
from mechanism import (
    EVENT_SCRIPT,
    GATE,
    GUARD,
    classify,
    command_guards,
    event_scripts,
    script_mechanism,
    tool_use_gate_kind,
)
from trees import policy_dirs

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROSE = DOCS / "policy-prose.yaml"
LABEL_WORD = {"block": "blocks", "ask": "asks", "warn": "warns", "advise": "advisory"}  # label keyword -> page word
MARK_START = "<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->"
MARK_END = "<!-- generated:end -->"


#: The one classifier (tools/mechanism.py), so this page and the registry cannot disagree.
_KIND = {GATE: "gate", EVENT_SCRIPT: "script", GUARD: "guard"}


WARN_ONLY_PRIMITIVE = (
    "A **warn-only gate**. `recompile` writes it under `.chock/compiled/{id}/` for each surface its `on` "
    "names (the git hook, CI, the agent's write path) beside the ambient rule. It runs and prints, but "
    "its exit never refuses a commit or a write."
)
WARN_ONLY_REACH = "`advisory` — the gate runs and prints its findings; it never refuses"


def kind_of(policy_dir: Path, manifest: dict) -> str:
    return _KIND.get(classify(policy_dir, manifest)[0], "text")


def _mechanism(kind: str, gate: dict, scripts: list[str], manifest: dict) -> str:
    if kind == "gate":
        return f"{gate['kind']} gate"
    if kind == "script":
        return script_mechanism(manifest).replace("guard script", f"guard script `{scripts[0]}`", 1)
    if scripts:
        return f"guard script `{scripts[0]}`"
    return f"warn-only `{gate['kind']}` gate" if _warn_only(gate) else "rule text"


def _warn_surfaces(gate: dict) -> list[str]:
    """Where a warn-only gate is compiled: the gate surfaces, the agent's write path for tool_use."""
    tool_use = ["`pre-tool-use`"] if "tool_use" in (gate.get("on") or []) else []
    return [*SURFACES["gate"][:-1], *tool_use, SURFACES["gate"][-1]]


def _warn_only(gate: dict) -> bool:
    """True for a gate that runs but whose declared action is only to warn."""
    return bool(gate.get("kind")) and gate.get("action") == "warn"


def load_cases(policy_dir: Path) -> list[dict]:
    suite_path = policy_dir / "evals" / "suite.yaml"
    if not suite_path.exists():
        return []
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8")) or {}
    block = suite.get("suite") or suite.get("eval_suite") or {}
    return block.get("cases") or block.get("test_cases") or []


def render(policy_id: str, policy_dir: Path, manifest: dict, prose: dict, label: dict) -> str:
    kind = kind_of(policy_dir, manifest)
    tree = policy_dir.parent.name
    gate = (manifest.get("hook") or {}).get("gate") or {}
    cases = load_cases(policy_dir)
    warn_only = kind == "text" and _warn_only(gate)
    executed = sum(1 for c in cases if c.get("execute")) if kind != "text" or warn_only else 0
    scripts = [p.name for p in command_guards(policy_dir, policy_id)] if kind == "guard" else []
    if kind == "script":
        scripts = [p.name for p in event_scripts(policy_dir, policy_id)]
    tool_use = kind == "script" and tool_use_gate_kind(manifest) is not None
    disabled = "disabled by default" in (manifest.get("description") or "")

    lines: list[str] = [
        f"# {manifest.get('name', policy_id)}",
        "",
        f"`{policy_id}` · {'hook' if kind == 'gate' else 'rule'} · {'enforces' if kind != 'text' else 'advises'}",
        "",
        MARK_START,
        "",
        "| | |",
        "| :--- | :--- |",
        f"| **Type** | `{manifest.get('artifact')}` |",
        f"| **On Claude Code** | {LABEL_WORD[label['keyword']]} — {label['says']} |",
        f"| **Manifest tier** | `enforcement: {manifest.get('enforcement')}` "
        "(propagation and index ranking; not what it blocks) |",
        f"| **Mechanism** | {_mechanism(kind, gate, scripts, manifest)} |",
        f"| **Reaches** | {WARN_ONLY_REACH if warn_only else CEILING[kind]}{TOOL_USE_REACH if tool_use else ''} |",
        f"| **Compiles to** | {', '.join(_warn_surfaces(gate) if warn_only else SURFACES[kind])} |",
        f"| **Eval cases** | {len(cases)} total, {executed} executable |",
        f"| **Enabled by default** | {'no — opt in' if disabled else 'yes'} |",
        "",
        MARK_END,
        "",
        "## What it is about",
        "",
        (manifest.get("description") or "").strip(),
        "",
        "## What it solves",
        "",
        prose["solves"].strip(),
        "",
        "## How it works",
        "",
    ]

    if kind == "gate":
        lines += [
            f"A declarative `{gate['kind']}` gate, evaluated on "
            f"{' and '.join('`' + e + '`' for e in gate.get('on', []))}, action `{gate.get('action')}`.",
            "",
            "Parameters, from `manifest.yaml`:",
            "",
            *[f"- `{k}`" for k in sorted((gate.get("params") or {}).keys())],
            "",
            "On a match it prints:",
            "",
            "> " + " ".join((gate.get("message") or "").split()),
            "",
        ]
    elif kind == "script":
        lines += [
            f"A guard script, `implementations/{scripts[0]}`, run by the git hook at every commit with no "
            "arguments. It reads the staged revision of each file from git and exits non-zero to refuse the commit.",
            "",
            *(
                [
                    f"A `{tool_use_gate_kind(manifest)}` gate also runs at tool use, on what a write would leave "
                    "and on what the turn left at its end. That point is best-effort: it needs the agent's hook "
                    "installed and fails open if the hook crashes. The commit is the enforced point.",
                    "",
                ]
                if tool_use
                else []
            ),
            "The rule text ships alongside, so an agent reading its context knows the constraint before it stages the change rather than only after being refused:",
            "",
            "```text",
            ((manifest.get("rule") or {}).get("text") or "").strip(),
            "```",
            "",
        ]
    elif kind == "guard":
        lines += [
            f"A guard script, `implementations/{scripts[0]}`, run before the agent executes a Bash "
            "command. It inspects the proposed command and exits non-zero to refuse it.",
            "",
            "The rule text ships alongside, so an agent reading its context knows the constraint before it proposes the command rather than only after being refused:",
            "",
            "```text",
            ((manifest.get("rule") or {}).get("text") or "").strip(),
            "```",
            "",
        ]
    elif _warn_only(gate):
        events = " and ".join("`" + e + "`" for e in gate.get("on", []))
        lines += [
            f"A `{gate['kind']}` gate runs on {events} and only warns: its action is `warn`, so it prints "
            "its findings and never refuses. It does not enforce anything, so the policy counts as advisory.",
            "",
            "On a finding it prints:",
            "",
            "> " + " ".join((gate.get("message") or "").split()),
            "",
        ]
        if rule_text := ((manifest.get("rule") or {}).get("text") or "").strip():
            lines += [
                "The rule text ships alongside, in the agent's ambient context:",
                "",
                "```text",
                rule_text,
                "```",
                "",
            ]
    else:
        lines += [
            "There is no mechanism. The rule text is compiled into the agent's ambient context:",
            "",
            "```text",
            ((manifest.get("rule") or {}).get("text") or "").strip(),
            "```",
            "",
            "It is read, not executed. Treat it as guidance you have made legible to the agent, not as a control -- if you need the behaviour guaranteed, you need a gate or a guard.",
            "",
        ]

    lines += [
        "## Which primitive it becomes",
        "",
        WARN_ONLY_PRIMITIVE.format(id=policy_id)
        if warn_only
        else PRIMITIVE[kind].format(id=policy_id, script=scripts[0] if scripts else ""),
        "",
        "## Installing it",
        "",
        "```bash",
        f"chock add {policy_id}",
        "chock sync ." if kind != "text" else "chock sync --repo .",
        "```",
        "",
        "Or copy the folder — it does the same thing, byte for byte:",
        "",
        "```bash",
        f"cp -r {tree}/{policy_dir.name}  <your-repo>/.agents/policies/{policy_dir.name}",
        "cd <your-repo> && chock sync --repo .",
        "```",
    ]

    if disabled:
        lines += [
            "",
            f"This one ships disabled. Enable it with `chock enable {policy_id}` once its prerequisites are in place.",
        ]

    lines += [
        "",
        "## Customising it",
        "",
        prose["customise"].strip(),
        "",
        "Once copied, the policy is **yours**. `recompile` reads your copy as the source, so an edit reaches the compiled artifact and changes what actually happens. Nothing upstream overwrites it; re-copying from this repo is an explicit act.",
        "",
        "After any edit:",
        "",
        "```bash",
        "chock sync --repo .   # rebuild the compiled artifact",
        "chock check           # check it still conforms",
        f"chock check --only evals {policy_id}".rstrip(),
        "```",
        "",
        "---",
        "",
        "[Adoption transcript](adoption.md) — the output of installing exactly this policy into an empty repository, re-derived in CI so it cannot go stale.",
        "",
        f"Source: [`{tree}/{policy_dir.name}/`](../../{tree}/{policy_dir.name}/) · [all policies](../README.md)",
        "",
    ]
    return "\n".join(lines)


def build() -> dict[Path, str]:
    prose = yaml.safe_load(PROSE.read_text(encoding="utf-8"))
    rows = yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))["policies"]
    lab = {p["id"]: p["label"]["claude-code"] for p in rows}
    out: dict[Path, str] = {}
    for policy_dir in policy_dirs():
        manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8"))
        policy_id = manifest["id"]
        if policy_id not in prose:
            raise SystemExit(f"docs/policy-prose.yaml has no entry for '{policy_id}'")
        out[DOCS / policy_id / "README.md"] = render(policy_id, policy_dir, manifest, prose[policy_id], lab[policy_id])
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate per-policy documentation.")
    parser.add_argument("--check", action="store_true", help="Fail if any doc is out of date.")
    args = parser.parse_args(argv)

    pages = build()
    stale = [p for p, text in pages.items() if not p.exists() or p.read_text(encoding="utf-8") != text]

    if args.check:
        if stale:
            print("Policy docs are out of date:")
            for p in stale:
                print(f"  {p.relative_to(ROOT).as_posix()}")
            print("Run `python tools/gen_policy_docs.py` and commit the result.")
            return 1
        print(f"All {len(pages)} policy docs match their manifests.")
        return 0

    for path, text in pages.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"Wrote {len(pages)} policy docs ({len(stale)} changed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
