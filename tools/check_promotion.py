#!/usr/bin/env python3
"""A policy is `production` only with a measurement on record: both directions, for its current version, bar met.

`measurements/promotion/<id>.json` is the record (record.schema.json); `pending.json` lists the production policies
grandfathered without one, and only shrinks. `--settle <id>` fills the rate and `bar_met` from the judged triage.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from trees import ROOT, policy_dirs

FOLDER = Path("measurements") / "promotion"
VERDICTS = ("correct_work", "true_catch")


def judged(record: dict) -> int:
    return sum(c["judged"] for c in record["corpora"])


def rate(record: dict) -> float | None:
    """Correct work refused over commits judged; None while a fire is unjudged or nothing was judged."""
    if any(t["verdict"] not in VERDICTS for t in record["triage"]) or not judged(record):
        return None
    return round(sum(t["verdict"] == "correct_work" for t in record["triage"]) / judged(record), 4)


def bar_met(record: dict) -> bool:
    """Every fire judged, correct work refused at or under 5% of commits judged (D15's line), every authored case right."""
    if rate(record) is None:
        return False
    wrong = sum(t["verdict"] == "correct_work" for t in record["triage"])
    block, allow = record["eval"]["block"], record["eval"]["allow"]
    return (
        wrong * 20 <= judged(record)
        and 0 < block["total"] == block["caught"]
        and 0 < allow["total"] == allow["allowed"]
        and record["misses"]["read"]
    )


def settle(record: dict) -> dict:
    return record | {"correct_work_rate": rate(record), "bar_met": bar_met(record)}


def production(root: Path) -> dict[str, str]:
    """Each production policy's id and manifest version."""
    found = {}
    for folder in policy_dirs(root):
        manifest = yaml.safe_load((folder / "manifest.yaml").read_text(encoding="utf-8")) or {}
        if (manifest.get("lifecycle") or {}).get("status") == "production":
            found[folder.name] = str(manifest["version"])
    return found


def numbers(record: dict) -> list[str]:
    """What is wrong with the counts and verdicts of a record that validates."""
    out = []
    repos = {c["repo"] for c in record["corpora"]}
    if len(repos) != len(record["corpora"]) or any(t["repo"] not in repos for t in record["triage"]):
        out.append("lists a corpus twice, or triages a fire from a repo it did not replay")
    if len(record["triage"]) != sum(c["fires"] for c in record["corpora"]):
        out.append("has a triage entry count that differs from the fires")
    if any(c["judged"] > c["commits"] for c in record["corpora"]):
        out.append("judged more commits than it replayed")
    unjudged = sum(t["verdict"] not in VERDICTS for t in record["triage"])
    if unjudged:
        out.append(f"has {unjudged} fire(s) without a verdict")
    if any(t["verdict"] in VERDICTS and not t["reason"].strip() for t in record["triage"]):
        out.append("has a verdict without a reason")
    block, allow = record["eval"]["block"], record["eval"]["allow"]
    if block["caught"] > block["total"] or allow["allowed"] > allow["total"]:
        out.append("counts more eval cases passed than exist")
    return out


def defects(record: dict, policy: str, version: str, schema: dict) -> list[str]:
    """What stops this record from standing for the policy at this version."""
    errors = [
        f"{'/'.join(map(str, e.path)) or 'record'}: {e.message}"
        for e in Draft202012Validator(schema).iter_errors(record)
    ]
    if errors:
        return ["does not validate: " + "; ".join(sorted(errors))]
    out = [f"names policy {record['policy']!r}"] if record["policy"] != policy else []
    if record["version"] != version:
        out.append(f"is for version {record['version']}, the manifest is {version}")
    out += numbers(record)
    if record["correct_work_rate"] != rate(record) or record["bar_met"] != bar_met(record):
        out.append("states a rate or bar_met that its numbers do not give")
    elif not record["bar_met"]:
        out.append("does not meet the bar")
    return out


def check(root: Path = ROOT) -> list[str]:
    folder = root / FOLDER
    schema = json.loads((folder / "record.schema.json").read_text(encoding="utf-8"))
    pending = json.loads((folder / "pending.json").read_text(encoding="utf-8"))["pending"]
    live = production(root)
    problems = [f"pending.json lists {pid}, which is not a production policy" for pid in pending if pid not in live]
    for pid, version in sorted(live.items()):
        path = folder / f"{pid}.json"
        if pid in pending:
            if path.exists():
                problems.append(f"{pid} has a record: remove it from pending.json")
        elif not path.exists():
            problems.append(f"{pid} is production with no record: run measure_false_positives.py --record {pid}")
        else:
            problems += [
                f"{pid}: record {d}" for d in defects(json.loads(path.read_text("utf-8")), pid, version, schema)
            ]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settle", metavar="ID", help="recompute correct_work_rate and bar_met in ID's record")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.settle:
        path = args.root / FOLDER / f"{args.settle}.json"
        path.write_text(json.dumps(settle(json.loads(path.read_text("utf-8"))), indent=2) + "\n", encoding="utf-8")
        return 0
    problems = check(args.root)
    print("\n".join(problems) if problems else f"{len(production(args.root))} production policies: records hold")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
