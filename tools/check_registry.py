"""registry.yaml matches the policies on disk -- ids, paths, honesty labels, versions, evals."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from mechanism import CEILING, classify

ROOT = Path(__file__).resolve().parents[1]


def suite_counts(policy_dir: Path) -> tuple[int, int]:
    """Executed and total eval cases, read the way check_readme.py reads them."""
    suite = policy_dir / "evals" / "suite.yaml"
    if not suite.is_file():
        return 0, 0
    loaded = yaml.safe_load(suite.read_text(encoding="utf-8")) or {}
    block = loaded.get("suite") or loaded.get("eval_suite") or {}
    cases = block.get("cases") or block.get("test_cases") or []
    return sum(1 for c in cases if c.get("execute")), len(cases)


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

    wrong = []
    stale = []
    for p in reg["policies"]:
        d = ROOT / p["path"]
        m = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
        kind, detail = classify(d, m)
        if p.get("mechanism") != detail or p.get("enforces") != CEILING[kind]:
            wrong.append(
                f"{p['id']}: labelled {p.get('mechanism')!r}/{p.get('enforces')!r}, "
                f"is {detail!r}/{CEILING[kind]!r}"
            )
        # The labels were checked from this file's first version and the facts beside them
        # never were, so every number in a row could go stale with the check green -- and
        # thirteen did, one of them by five releases, while a policy's own page and the
        # README stayed right. A registry is read as the summary of what a policy is.
        if str(p.get("version")) != str(m["version"]):
            stale.append(
                f"{p['id']}: version {p.get('version')}, manifest says {m['version']}"
            )
        executed, total = suite_counts(d)
        if p.get("eval_cases") != total:
            stale.append(
                f"{p['id']}: eval_cases {p.get('eval_cases')}, suite has {total}"
            )
        # Absent is a claim of none, and four rows omitted it while their suites executed
        # every case they ship.
        if p.get("eval_executed", 0) != executed:
            stale.append(
                f"{p['id']}: eval_executed {p.get('eval_executed', 'absent')}, suite executes {executed}"
            )
    if wrong:
        print("registry labels do not match the policies:")
        for w in wrong:
            print("  " + w)
    if stale:
        print("registry facts do not match the policies:")
        for s in stale:
            print("  " + s)
    if wrong or stale:
        return 1
    print("mechanism, enforces, version and eval counts match every policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
