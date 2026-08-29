#!/usr/bin/env python3
"""Generate docs/<policy-id>/README.md for every published policy.

Hand-written policy docs drift the first time a policy changes, and a doc that says
`enforced` about advisory text is worse than no doc -- it is the overclaim this project
exists to prevent, published in the place adopters read first.

So the facts are derived from base/<id>/ and compliance/<id>/, and the judgement lives in
docs/policy-prose.yaml.
`--check` regenerates into memory and diffs, the same shape as `chock sync
--check`, so CI fails when the two disagree.

Usage:
  python tools/gen_policy_docs.py
  python tools/gen_policy_docs.py --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from trees import policy_dirs

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROSE = DOCS / "policy-prose.yaml"


#: What a policy reaches at its best, given what it ships. `advisory` is not a lesser
#: entry, it is an honest ceiling.
CEILING = {
    "gate": "`enforced-at-commit` — the command exits non-zero and the commit does not happen",
    # Not a flat `enforced`: agentseam's own per-agent vocabulary applies once installed
    # (chock owner decision #9) -- `best-effort` on Claude Code (its PreToolUse fails
    # OPEN, so a crashed hook silently allows), `enforceable` on Cursor (can be told to
    # fail closed, but does not by default). Neither is the weaker claim `advisory` is;
    # both are a real, installed, in-agent block that only a crashed hook gets past.
    "guard": (
        "`best-effort`/`enforceable` once `chock sync` has run — the tool call is refused "
        "before it runs, on a hook that is actually wired up"
    ),
    "text": "`advisory` — an agent reads it and may or may not follow it",
}

SURFACES = {
    "gate": ["`git-hook`", "`ci-gate`", "`ambient-rule`"],
    "guard": ["`pre-tool-use`", "`ambient-rule`"],
    "text": ["`ambient-rule`"],
}

PRIMITIVE = {
    "gate": (
        "A **git hook**. `recompile` writes `.chock/compiled/{id}/git-hook/gate.json`, and "
        "`install-hooks` registers a dispatcher entry under `.git/hooks/pre-commit.d/`. The gate is "
        "declarative: the compiled JSON is the whole check, so reviewing it reviews the effect rather "
        "than the intent."
    ),
    "guard": (
        "A **PreToolUse guard**. `recompile` writes `.chock/compiled/{id}/pre-tool-use/"
        "pretooluse.json`, and `install-hooks` merges it into `.claude/settings.json` so the agent "
        "consults the guard script before running a Bash command. Until that install runs, the "
        "fragment is compiled and enforces nothing, and coverage says so."
    ),
    "text": (
        "An **ambient rule**. `recompile` writes `.chock/compiled/{id}/ambient-rule/ambient.md`, "
        "and `refresh` folds it into the agent-readable rule surface. Nothing executes: the text "
        "reaches the agent's context and that is the entire mechanism."
    ),
}

MARK_START = "<!-- generated:start — tools/gen_policy_docs.py; edit policy-prose.yaml, not this -->"
MARK_END = "<!-- generated:end -->"


def kind_of(policy_dir: Path, manifest: dict) -> str:
    if ((manifest.get("hook") or {}).get("gate") or {}).get("kind"):
        return "gate"
    impl = policy_dir / "implementations"
    if impl.is_dir() and any(impl.glob("*.sh")):
        return "guard"
    return "text"


def load_cases(policy_dir: Path) -> list[dict]:
    suite_path = policy_dir / "evals" / "suite.yaml"
    if not suite_path.exists():
        return []
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8")) or {}
    block = suite.get("suite") or suite.get("eval_suite") or {}
    return block.get("cases") or block.get("test_cases") or []


def render(policy_id: str, policy_dir: Path, manifest: dict, prose: dict) -> str:
    kind = kind_of(policy_dir, manifest)
    tree = policy_dir.parent.name
    gate = (manifest.get("hook") or {}).get("gate") or {}
    cases = load_cases(policy_dir)
    executed = sum(1 for c in cases if c.get("execute")) if kind != "text" else 0
    scripts = sorted(p.name for p in (policy_dir / "implementations").glob("*.sh")) if kind == "guard" else []
    disabled = "disabled by default" in (manifest.get("description") or "")

    lines: list[str] = [
        f"# {manifest.get('name', policy_id)}",
        "",
        f"`{policy_id}` · {'hook' if kind == 'gate' else 'rule'} · "
        f"{'enforces' if kind != 'text' else 'advises'}",
        "",
        MARK_START,
        "",
        "| | |",
        "| :--- | :--- |",
        f"| **Type** | `{manifest.get('artifact')}` (`enforcement: {manifest.get('enforcement')}`) |",
        f"| **Mechanism** | {gate['kind'] + ' gate' if kind == 'gate' else ('guard script `' + scripts[0] + '`' if scripts else 'rule text')} |",
        f"| **Reaches** | {CEILING[kind]} |",
        f"| **Compiles to** | {', '.join(SURFACES[kind])} |",
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
        PRIMITIVE[kind].format(id=policy_id),
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
            f"This one ships disabled. Enable it with `chock enable {policy_id}` once its "
            "prerequisites are in place.",
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
        f"Source: [`{tree}/{policy_dir.name}/`](../../{tree}/{policy_dir.name}/) · "
        "[all policies](../README.md)",
        "",
    ]
    return "\n".join(lines)


def build() -> dict[Path, str]:
    prose = yaml.safe_load(PROSE.read_text(encoding="utf-8"))
    out: dict[Path, str] = {}
    for policy_dir in policy_dirs():
        manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8"))
        policy_id = manifest["id"]
        if policy_id not in prose:
            raise SystemExit(f"docs/policy-prose.yaml has no entry for '{policy_id}'")
        out[DOCS / policy_id / "README.md"] = render(policy_id, policy_dir, manifest, prose[policy_id])
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
