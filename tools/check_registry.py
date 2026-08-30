"""registry.yaml matches the policies on disk -- ids, paths, and honesty labels.

Extracted verbatim from the inline CI step so the commit-time conformance hook and CI
run one implementation instead of a drifting copy. The `mechanism` / `enforces` labels
are what an adopter chooses on; a label that drifts from the policy is worse than no
label, because it would state a control exists where only text does.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    reg = yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))
    listed = {p["id"]: p["path"] for p in reg["policies"]}
    listed |= {s["id"]: s["path"] for s in reg.get("skills") or []}
    sys.path.insert(0, str(ROOT / "tools"))
    from trees import policy_dirs

    on_disk = {}
    for d in policy_dirs(ROOT):
        m = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
        on_disk[m["id"]] = d.relative_to(ROOT).as_posix()
    # The catalog publishes no skills today, so `skills/` does not exist. Iterating a
    # missing directory must not be an error; it comes back when a skill earns its place.
    skills = ROOT / "skills"
    if skills.is_dir():
        for d in sorted(p for p in skills.iterdir() if p.is_dir()):
            on_disk[d.name] = f"skills/{d.name}"
    if listed != on_disk:
        print("registry.yaml is stale.")
        print("  missing from registry:", sorted(set(on_disk) - set(listed)))
        print("  listed but absent:    ", sorted(set(listed) - set(on_disk)))
        return 1
    print(f"registry lists all {len(on_disk)} entries")

    ceiling = {
        "gate": "enforced-at-commit",
        # Not a flat `enforced` (chock owner decision #9): agentseam's per-agent vocabulary
        # applies once installed -- best-effort on Claude Code (fails open if the hook
        # crashes), enforceable on Cursor. See gen_policy_docs.py's CEILING for the same
        # wording used in the generated per-policy docs.
        "guard": "best-effort (pre-tool-use, once hooks are installed; fails open if the hook crashes)",
        "none": "advisory",
    }
    wrong = []
    for p in reg["policies"]:
        d = ROOT / p["path"]
        m = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
        gate = (m.get("hook") or {}).get("gate") or {}
        impl = d / "implementations"
        if gate.get("kind"):
            kind, detail = "gate", gate["kind"]
        elif impl.is_dir() and any(impl.glob("*.sh")):
            kind, detail = "guard", "guard script"
        else:
            kind, detail = "none", "rule text only"
        if p.get("mechanism") != detail or p.get("enforces") != ceiling[kind]:
            wrong.append(
                f"{p['id']}: labelled {p.get('mechanism')!r}/{p.get('enforces')!r}, "
                f"is {detail!r}/{ceiling[kind]!r}"
            )
    if wrong:
        print("registry labels do not match the policies:")
        for w in wrong:
            print("  " + w)
        return 1
    print("mechanism and enforces labels match every policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
