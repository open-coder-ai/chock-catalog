#!/usr/bin/env python3
"""Replay a pack's gate over first-parent history and report how often it fires (D15); `--record` writes a promotion record.

`judged` counts commits with a file in the gate's scope (`applies_to.paths`); a gate with no paths judges every
commit, so its rate is fires per commit. Packs named on the command line are measured whatever their action
(warn, ask or block); with none named, every pack whose gate declares `warn`. `--root` runs the pack scripts of that
repo (the gate engine is this repo's): point it only at a trusted repo. A shallow clone is refused unless
`--allow-shallow`. `--record <id> --corpus REPO=PATH ...` replays one pack over each repo and writes
`measurements/promotion/<id>.json` with every verdict left empty, for a person to judge (check_promotion.py).
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import yaml
from check_promotion import FOLDER, settle
from promotion_record import eval_counts, misses_listed

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ".chock/bin/gate.py"
DEFAULT_LIMIT = 300
REFUSED = 2
#: git's empty tree: the parent a root commit is diffed against.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
#: A pack that imports one of these could reach the network; the measurement runs offline, so it declines.
NETWORK = re.compile(r"^\s*(?:import|from)\s+(socket|urllib\.request|http\.client|requests|ftplib|smtplib)\b", re.M)


def load_engine() -> ModuleType:
    """The vendored gate runner, imported by path: the code a hook runs is the code replayed."""
    spec = importlib.util.spec_from_file_location("chock_gate_engine", ROOT / ENGINE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def git(root: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "core.quotePath=false", *args], cwd=root, capture_output=True, text=True, check=True
    )
    return done.stdout


def is_shallow(root: Path) -> bool:
    return git(root, "rev-parse", "--is-shallow-repository").strip() == "true"


def commits(root: Path, limit: int) -> list[tuple[str, str, str]]:
    """The last `limit` first-parent commits, newest first, as (sha, first parent, subject).

    A parentless commit is diffed against the empty tree only in a full clone, where it is a true root;
    in a shallow clone it is the cut-off boundary, whose real parent is missing, so it is skipped.
    """
    shallow = is_shallow(root)
    rows = git(root, "rev-list", "--first-parent", f"--max-count={limit}", "--format=%H %P|%s", "HEAD").splitlines()
    out = []
    for row in rows[1::2]:
        head, _, subject = row.partition("|")
        sha, *parents = head.split()
        if parents or not shallow:
            out.append((sha, parents[0] if parents else EMPTY_TREE, subject))
    return out


def pack_dir(root: Path, pack: str) -> Path | None:
    found = sorted(root.glob(f"*/{pack}/manifest.yaml"))
    return found[0].parent if found else None


def observe_packs(root: Path) -> list[str]:
    """Every pack whose gate declares `warn`, the per-policy form of the observe rollout."""
    ids = []
    for manifest in sorted(root.glob("*/*/manifest.yaml")):
        gate = ((yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}).get("hook") or {}).get("gate") or {}
        if gate.get("action") == "warn":
            ids.append(manifest.parent.name)
    return ids


def load_pack(root: Path, engine: ModuleType, pack: str) -> dict:
    """The gate spec the runtime would build from the manifest, or {"reason": ...} when it cannot be replayed."""
    folder = pack_dir(root, pack)
    if folder is None:
        return {"reason": "no such pack"}
    manifest = yaml.safe_load((folder / "manifest.yaml").read_text(encoding="utf-8")) or {}
    gate = (manifest.get("hook") or {}).get("gate")
    if not gate:
        return {"reason": "the pack declares no hook gate"}
    if "commit" not in gate.get("on", []):
        return {"reason": "the gate is not judged at commit"}
    if gate.get("kind") not in engine.KINDS:
        return {"reason": f"gate kind {gate.get('kind')!r} cannot be replayed from a commit"}
    for source in sorted((folder / "implementations").rglob("*.py")):
        reach = NETWORK.search(source.read_text(encoding="utf-8", errors="replace"))
        if reach:
            return {"reason": f"{source.name} imports {reach.group(1)}, so it cannot run offline"}
    params = dict(gate.get("params", {}))
    if "script" in params:
        params["script"] = str(folder / "implementations" / params["script"])
    paths = (manifest.get("applies_to") or {}).get("paths") or ()
    return {"kind": gate["kind"], "action": gate.get("action", "block"), "params": params, "paths": tuple(paths)}


def replay_context(engine: ModuleType, root: Path, spec: dict, at: tuple[str, str], cache: dict) -> object:
    """A gate context that judges commit `at[0]` against its first parent `at[1]`, as a pre-commit hook would."""
    sha, parent = at

    class Replay(engine.GateContext):
        def _range(self) -> list[str]:
            return [parent, sha]

        def _git(self, *args: str) -> str:
            if args not in cache:
                cache[args] = super()._git(*args)
            return cache[args]

        def staged_blob(self, path: str) -> str:
            return self._git("show", f"{sha}:{path}")

        def head_blob(self, path: str) -> str:
            return self._git("show", f"{parent}:{path}")

        committed_blob = head_blob

    return Replay(repo_root=root, scope=spec["paths"])


def items_of(result: object) -> list[dict]:
    """What a refusal names: a script's findings, else a content gate's matched paths, else its message."""
    if result.findings:
        return [
            {"path": f["path"], "line": f["line"], "rule": f.get("rule", ""), "message": f["message"]}
            for f in result.findings
        ]
    if result.matches:
        split = [m.partition(": ") for m in result.matches]
        return [{"path": path, "line": 0, "rule": "", "message": message} for path, _, message in split]
    return [{"path": "", "line": 0, "rule": "", "message": result.message}]


def measure_pack(root: Path, engine: ModuleType, spec: dict, history: list[tuple[str, str, str]]) -> dict:
    judged = errors = 0
    fires = []
    for sha, parent, subject in history:
        ctx = replay_context(engine, root, spec, (sha, parent), {})
        if not ctx.staged_paths():
            continue
        judged += 1
        result = engine.KINDS[spec["kind"]](ctx, spec["params"], "commit")
        verdict = engine._verdict(result, spec["action"])
        if verdict == "allow":
            continue
        if engine._UNDECIDED in result.message:
            errors += 1
        fires.append({"commit": sha, "subject": subject, "verdict": verdict, "items": items_of(result)})
    return {"status": "measured", "judged": judged, "fires": len(fires), "errors": errors, "details": fires}


def measure(root: Path, packs: list[str], limit: int) -> dict:
    engine = load_engine()
    history = commits(root, limit)
    report = []
    for pack in sorted(set(packs)):
        spec = load_pack(root, engine, pack)
        row = {"pack": pack, "replayed": len(history)}
        if "reason" in spec:
            row |= {"status": "unmeasurable", "reason": spec["reason"]}
        else:
            row |= measure_pack(root, engine, spec, history)
            row["rate"] = round(100 * row["fires"] / row["judged"], 1) if row["judged"] else None
        report.append(row)
    return {"head": git(root, "rev-parse", "HEAD").strip(), "commits": len(history), "packs": report}


def build_record(root: Path, pack: str, corpora: dict[str, Path], limit: int, date: str) -> dict:
    """The promotion record for `pack` as of `root`'s HEAD: replay over each corpus, eval counts, every verdict empty."""
    engine = load_engine()
    spec = load_pack(root, engine, pack)
    if "reason" in spec:
        msg = f"{pack} cannot be measured: {spec['reason']}"
        raise ValueError(msg)
    folder = pack_dir(root, pack)
    manifest = yaml.safe_load((folder / "manifest.yaml").read_text(encoding="utf-8"))
    rows, triage = [], []
    for repo, path in corpora.items():
        history = commits(path, limit)
        done = measure_pack(path, engine, spec, history)
        if done["errors"]:
            msg = f"the gate could not decide {done['errors']} commit(s) in {repo}"
            raise ValueError(msg)
        rows.append({"repo": repo, "commits": len(history), "judged": done["judged"], "fires": done["fires"]})
        triage += [
            {"repo": repo, "commit": f["commit"], "path": f["items"][0]["path"], "rule": f["items"][0]["rule"]}
            | {"verdict": "", "reason": ""}
            for f in done["details"]
        ]
    return settle(
        {
            "policy": pack,
            "version": str(manifest["version"]),
            "engine": (root / ".framework-ref").read_text(encoding="utf-8").strip(),
            "catalog": git(root, "rev-parse", "HEAD").strip(),
            "date": date,
            "corpora": rows,
            "triage": triage,
            "eval": eval_counts(root, folder),
            "misses": {"read": False, "listed": misses_listed(str(manifest.get("description", "")))},
            "correct_work_rate": None,
            "bar_met": False,
        }
    )


def render(report: dict) -> str:
    lines = [f"head {report['head']}, {report['commits']} first-parent commits replayed", ""]
    lines.append(f"{'pack':<34}{'judged':>7}{'fires':>7}{'errors':>7}{'rate':>8}")
    for row in report["packs"]:
        if row["status"] == "unmeasurable":
            lines.append(f"{row['pack']:<34}unmeasurable: {row['reason']}")
            continue
        rate = "n/a" if row["rate"] is None else f"{row['rate']}%"
        lines.append(f"{row['pack']:<34}{row['judged']:>7}{row['fires']:>7}{row['errors']:>7}{rate:>8}")
    for row in report["packs"]:
        for fire in row.get("details", []):
            lines.append("")
            lines.append(f"{row['pack']} {fire['verdict']} at {fire['commit'][:10]} {fire['subject']}")
            lines.extend(f"  {i['path']}:{i['line']} [{i['rule']}] {i['message']}" for i in fire["items"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packs", nargs="*", help="pack ids; default: every pack whose gate declares warn")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="first-parent commits to replay")
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    parser.add_argument(
        "--allow-shallow", action="store_true", help="measure a shallow clone (its boundary is skipped)"
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="the catalog repo to measure")
    parser.add_argument("--record", metavar="ID", help="write measurements/promotion/<id>.json (needs --corpus)")
    parser.add_argument(
        "--corpus", action="append", default=[], metavar="REPO=PATH", help="a repo to replay for --record"
    )
    parser.add_argument("--date", default=datetime.date.today().isoformat(), help="the record's date (default: today)")
    args = parser.parse_args(argv)
    if args.record and (args.packs or not args.corpus):
        parser.error("--record takes no pack ids and needs at least one --corpus REPO=PATH")
    corpora = {name: Path(path) for name, _, path in (item.partition("=") for item in args.corpus)}
    if args.record:
        args.allow_shallow = False
    for path in [args.root, *corpora.values()]:
        if is_shallow(path) and not args.allow_shallow:
            print(
                "refusing a shallow clone: its history is cut off; run `git fetch --unshallow` or pass --allow-shallow",
                file=sys.stderr,
            )
            return REFUSED
    if args.record:
        try:
            record = build_record(args.root, args.record, corpora, args.limit, args.date)
        except ValueError as refusal:
            print(refusal, file=sys.stderr)
            return REFUSED
        target = args.root / FOLDER / f"{args.record}.json"
        target.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {target.relative_to(args.root)}: {len(record['triage'])} fire(s) to judge")
        return 0
    started = time.monotonic()
    report = measure(args.root, args.packs or observe_packs(args.root), args.limit)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render(report))
    print(f"wall time {time.monotonic() - started:.1f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
