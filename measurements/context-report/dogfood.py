"""Measure chock's built plugin bundles with context-report, plugin-root variable set and unset."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

from context_report.produce.run import produce_statement

PRODUCER_ID = "https://github.com/open-coder-ai/context-report#local-dogfood"


def _rows(stmt: dict) -> dict[str, dict]:
    return {a["attribute"]: a for a in stmt["predicate"]["attributes"]}


def _run(target: dict, env: dict[str, str], out: Path, suffix: str, n: int) -> dict:
    hook = target["hook_commands"][0] if target["hook_commands"] else None
    stmt = produce_statement(
        subject=target["abs_path"],
        subject_kind=target["subject_kind"],
        target=target["target"],
        hook_command=hook,
        env=env,
        producer_id=PRODUCER_ID,
        n=n,
    )
    dest = out / target["format"] / f"{Path(target['path']).name}{suffix}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(stmt, indent=2) + "\n", encoding="utf-8")
    return stmt


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--bundles", required=True, help="dir the inventory paths are relative to"
    )
    ap.add_argument(
        "--targets", required=True, help="inventory JSON written by inventory.py"
    )
    ap.add_argument(
        "--out", required=True, help="directory for statements and SUMMARY.md"
    )
    ap.add_argument("--n", type=int, default=20)
    args = ap.parse_args(argv)
    targets = json.loads(Path(args.targets).read_text(encoding="utf-8"))
    bundles = Path(args.bundles).resolve()
    for t in targets:
        t["abs_path"] = bundles / t["path"]
    out = Path(args.out)

    per_format: dict[str, dict] = defaultdict(
        lambda: {
            "bundles": 0,
            "hook_bundles": 0,
            "reach_pass_resolved": 0,
            "reach_pass_unresolved": 0,
            "allow_on_malformed_resolved": 0,
            "allow_on_malformed_unresolved": 0,
            "latency_p50_resolved": [],
            "latency_p95_resolved": [],
            "latency_error_unresolved": 0,
            "context_tokens": [],
        }
    )
    for t in targets:
        agg = per_format[t["format"]]
        agg["bundles"] += 1
        if not t["has_hook"]:
            stmt = _run(t, {}, out, "", args.n)
            ct = _rows(stmt)["cost.context_tokens"]
            if ct["result"] == "PASSED":
                agg["context_tokens"].append(ct["measurement"]["mean"])
            continue
        agg["hook_bundles"] += 1
        resolved = _run(
            t, {t["plugin_root_var"]: str(t["abs_path"])}, out, ".resolved", args.n
        )
        unresolved = _run(t, {}, out, ".unresolved", args.n)
        r_res, r_un = _rows(resolved), _rows(unresolved)
        agg["reach_pass_resolved"] += r_res["reachability"]["result"] == "PASSED"
        agg["reach_pass_unresolved"] += r_un["reachability"]["result"] == "PASSED"
        for key, rows in (("resolved", r_res), ("unresolved", r_un)):
            mo = rows["fault.malformedOutput"]
            if mo["result"] == "PASSED":
                agg[f"allow_on_malformed_{key}"] += mo["values"]["on_malformed_json"][
                    "would_allow"
                ]
        lat = r_res["cost.latency_ms"]
        if lat["result"] == "PASSED":
            agg["latency_p50_resolved"].append(lat["measurement"]["percentiles"]["50"])
            agg["latency_p95_resolved"].append(lat["measurement"]["percentiles"]["95"])
        agg["latency_error_unresolved"] += r_un["cost.latency_ms"]["result"] == "Error"
        ct = r_res["cost.context_tokens"]
        if ct["result"] == "PASSED":
            agg["context_tokens"].append(ct["measurement"]["mean"])
        sys.stderr.write(f"measured {t['format']}/{Path(t['path']).name}\n")

    lines = [
        "# chock's plugin bundles, measured by context-report v0.1",
        "",
        (
            "Every hook bundle was measured twice: with the plugin-root variable the client would set "
            "(`resolved`) and without it (`unresolved`). Latency is per hook invocation with a benign "
            f"PreToolUse payload, n={args.n}, on the build machine -- `environmentSensitive`, so read "
            "the shape, not the absolute number."
        ),
        "",
        (
            "`allow on malformed JSON` counts bundles whose hook exited 0 with no deny in stdout when "
            "fed unparseable stdin. `unresolved` runs with no plugin-root variable at all, which is "
            "how a hook runs when the client does not set one."
        ),
        "",
        (
            "| format | bundles | with hook | reachable (resolved) | reachable (unresolved) | "
            "allow on malformed JSON (resolved / unresolved) | "
            "latency p50 ms (median across bundles) | latency p95 ms (median) | "
            "latency Error when unresolved | context tokens (median per bundle) |"
        ),
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for fmt in sorted(per_format):
        a = per_format[fmt]
        med = lambda xs: f"{statistics.median(xs):.1f}" if xs else "n/a"
        lines.append(
            f"| {fmt} | {a['bundles']} | {a['hook_bundles']} | {a['reach_pass_resolved']} | "
            f"{a['reach_pass_unresolved']} | {a['allow_on_malformed_resolved']} / "
            f"{a['allow_on_malformed_unresolved']} | {med(a['latency_p50_resolved'])} | "
            f"{med(a['latency_p95_resolved'])} | {a['latency_error_unresolved']} | "
            f"{med(a['context_tokens'])} |"
        )
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
