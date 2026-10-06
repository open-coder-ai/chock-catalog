"""registry.yaml matches the policies on disk -- ids, paths, labels, versions, evals, text."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import owasp_llm
import yaml
from mechanism import CEILING, classify

ROOT = Path(__file__).resolve().parents[1]
#: Reserved for a user's own policies (builder v2, decision D5): no catalog policy id may start with it.
RESERVED_PREFIX = "my-"


def reserved_ids(ids: list[str]) -> list[str]:
    """The ids that start with the prefix reserved for user policies."""
    return sorted(i for i in ids if i.startswith(RESERVED_PREFIX))


def said(text: str | None) -> str:
    """One line of text, so a row that only rewrapped its description does not read as drift."""
    return re.sub(r"\s+", " ", text or "").strip()


def suite_counts(policy_dir: Path) -> tuple[int, int]:
    """Executed and total eval cases, read the way check_readme.py reads them."""
    suite = policy_dir / "evals" / "suite.yaml"
    if not suite.is_file():
        return 0, 0
    loaded = yaml.safe_load(suite.read_text(encoding="utf-8")) or {}
    block = loaded.get("suite") or loaded.get("eval_suite") or {}
    cases = block.get("cases") or block.get("test_cases") or []
    return sum(1 for c in cases if c.get("execute")), len(cases)


def entries_on_disk() -> dict[str, str]:
    """Policy and skill ids found under the trees and skills/, each with its repo-relative path."""
    sys.path.insert(0, str(ROOT / "tools"))
    from trees import policy_dirs

    found = {}
    for d in policy_dirs(ROOT):
        m = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
        found[m["id"]] = d.relative_to(ROOT).as_posix()
    skills = ROOT / "skills"
    if skills.is_dir():
        for d in sorted(p for p in skills.iterdir() if p.is_dir()):
            found[d.name] = f"skills/{d.name}"
    return found


def main() -> int:
    reg = yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))
    listed = {p["id"]: p["path"] for p in reg["policies"]}
    listed |= {s["id"]: s["path"] for s in reg.get("skills") or []}
    on_disk = entries_on_disk()
    from gen_lib_copies import problems as lib_problems

    if lib := lib_problems(ROOT):
        print("lib/ copies do not match lib/consumers.yaml and lib/ (python tools/gen_lib_copies.py):")
        print("\n".join("  " + problem for problem in lib))
        return 1
    import check_data_tables

    if check_data_tables.main([], ROOT):
        return 1
    if reserved := reserved_ids([*on_disk, *listed]):
        print(f"ids starting with {RESERVED_PREFIX!r} are reserved for user policies: {', '.join(reserved)}")
        return 1
    if listed != on_disk:
        print("registry.yaml is stale.")
        print("  missing from registry:", sorted(set(on_disk) - set(listed)))
        print("  listed but absent:    ", sorted(set(listed) - set(on_disk)))
        return 1
    print(f"registry lists all {len(on_disk)} entries")

    wrong = []
    stale = []
    claims = []
    for p in reg["policies"]:
        d = ROOT / p["path"]
        text = (d / "manifest.yaml").read_text(encoding="utf-8")
        m = yaml.safe_load(text)
        kind, detail = classify(d, m)
        # A framework id is a claim like any other: it names a real entry of the edition it cites.
        claims += [f"{p['id']}: {problem}" for problem in owasp_llm.problems(m, text)]
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
        lifecycle = (m.get("lifecycle") or {}).get("status")
        if p.get("status") != lifecycle:
            stale.append(f"{p['id']}: status {p.get('status')}, manifest lifecycle says {lifecycle}")
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
        # The description is the policy's own, verbatim: 34 rows had drifted from theirs, some
        # truncated mid-word and some still describing a policy that had been superseded.
        if said(p.get("description")) != said(m.get("description")):
            stale.append(f"{p['id']}: description is not the manifest's")
    if wrong:
        print("registry labels do not match the policies:")
        for w in wrong:
            print("  " + w)
    if stale:
        print("registry facts do not match the policies:")
        for s in stale:
            print("  " + s)
    if claims:
        print("framework claims name the wrong entry:")
        for c in claims:
            print("  " + c)
    if wrong or stale or claims:
        return 1
    print(
        "mechanism, enforces, version, eval counts and descriptions match every policy"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
