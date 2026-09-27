#!/usr/bin/env python3
"""Write registry.yaml's rows and the README's counts from the policies on disk.

check_registry.py and check_readme.py verify these facts; this writes them, so a version bump or
an eval case is never a hand edit to two files. A row is rebuilt from its manifest, keeping only
the description's hand wrapping while the text is unchanged; a removed policy's row goes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from check_readme import classify_readme
from check_registry import said, suite_counts
from mechanism import CEILING, classify
from trees import ROOT, policy_dirs

#: Every row field but `id` and `description`, in the order each row lists them.
FIELDS = (
    "path",
    "version",
    "artifact",
    "enforcement",
    "mandatory",
    "mechanism",
    "enforces",
    "eval_cases",
    "eval_executed",
)
#: The README's tier rows, as check_readme.py reads them, and which kinds each counts.
LADDER = (("enforced-at-commit", ("gate",)), ("in-agent", ("guard",)), ("advisory", ("text",)))
BADGES = (("policies", ("gate", "guard", "text")), ("enforced", ("gate", "guard")), ("advisory", ("text",)))
#: A table cell; `\|` is an escaped pipe inside a cell, not a column break (see check_readme.py).
CELL = r"(?:\\\||[^\r\n|])*"


def facts(policy_dir: Path, root: Path = ROOT) -> dict:
    """One registry row, derived from the policy folder alone."""
    manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8"))
    kind, mechanism = classify(policy_dir, manifest)
    executed, total = suite_counts(policy_dir)
    return {
        "id": manifest["id"],
        "path": policy_dir.relative_to(root).as_posix(),
        "version": str(manifest["version"]),
        "artifact": manifest.get("artifact"),
        "enforcement": manifest.get("enforcement"),
        "mandatory": bool(manifest.get("mandatory")),
        "mechanism": mechanism,
        "enforces": CEILING[kind],
        "eval_cases": total,
        "eval_executed": executed,
        "description": manifest.get("description") or "",
    }


def _scalar(value: object) -> str:
    return yaml.safe_dump(value, width=10**6).removesuffix("\n").removesuffix("\n...")


def _description(text: str, old: list[str]) -> list[str]:
    """The old description lines while they say the same thing, else the text wrapped fresh."""
    start = next((i for i, line in enumerate(old) if line.startswith("  description:")), None)
    if start is not None:
        end = start + 1
        while end < len(old) and old[end].startswith("    "):
            end += 1
        kept = old[start:end]
        if said(yaml.safe_load("\n".join(line[2:] for line in kept))["description"]) == said(text):
            return kept
    dumped = yaml.safe_dump({"description": said(text)}, width=96, allow_unicode=True)
    return ["  " + line for line in dumped.splitlines()]


def render_row(row: dict, old: list[str]) -> list[str]:
    return [
        f"- id: {row['id']}",
        *(f"  {k}: {_scalar(row[k])}" for k in FIELDS),
        *_description(row["description"], old),
    ]


def split_rows(lines: list[str]) -> tuple[list[str], dict[str, list[str]], list[str]]:
    """(everything through `policies:`, each row's lines by id, everything after the list)."""
    start = lines.index("policies:") + 1
    end = next((i for i in range(start, len(lines)) if lines[i] and lines[i][0] not in " -"), len(lines))
    rows: dict[str, list[str]] = {}
    current: list[str] = []
    for line in lines[start:end]:
        if line.startswith("- id: "):
            current = rows.setdefault(line.removeprefix("- id: ").strip(), [])
        current.append(line)
    return lines[:start], rows, lines[end:]


def _settle(path: Path, before: str, after: str, *, write: bool, summary: str) -> str:
    if after == before:
        return f"{path.name} already current"
    if not write:
        return f"{path.name} is stale: run python tools/gen_registry.py"
    path.write_text(after, encoding="utf-8", newline="\n")
    return summary


def update_registry(root: Path = ROOT, *, write: bool = True) -> str:
    path = root / "registry.yaml"
    before = path.read_text(encoding="utf-8")
    head, rows, tail = split_rows(before.splitlines())
    on_disk = {row["id"]: row for row in (facts(d, root) for d in policy_dirs(root))}
    order = [pid for pid in rows if pid in on_disk] + [pid for pid in on_disk if pid not in rows]
    body = [line for pid in order for line in render_row(on_disk[pid], rows.get(pid, []))]
    removed = sorted(set(rows) - set(on_disk))
    summary = f"registry.yaml rewritten ({len(on_disk)} rows" + (f"; removed {', '.join(removed)})" if removed else ")")
    return _settle(path, before, "\n".join([*head, *body, *tail]) + "\n", write=write, summary=summary)


def readme_text(text: str, kinds: dict[str, list[str]], evals: dict[str, tuple[int, int]]) -> str:
    """The README with every count check_readme.py verifies set to what the repo holds."""
    for label, counted in BADGES:
        n = sum(len(kinds[k]) for k in counted)
        text = re.sub(rf"(badge/{label}-)\d+(-)", rf"\g<1>{n}\g<2>", text)
        text = re.sub(rf'(alt=")\d+( {label}")', rf"\g<1>{n}\g<2>", text)
    for row, counted in LADDER:
        n = sum(len(kinds[k]) for k in counted)
        text = re.sub(rf"(\| `?{re.escape(row)}`? \|[^\r\n|]*\|[ \t]*)\d+([ \t]*\|)", rf"\g<1>{n}\g<2>", text)
    for policy_id, (executed, total) in evals.items():
        cells = rf"(`{re.escape(policy_id)}`\]\([^)]*\){CELL}\|{CELL}\|[ \t]*)\d+/\d+([ \t]*\|)"
        text = re.sub(cells, rf"\g<1>{executed}/{total}\g<2>", text)
    return text


def update_readme(root: Path = ROOT, *, write: bool = True) -> str:
    path = root / "README.md"
    before = path.read_text(encoding="utf-8")
    after = readme_text(before, *classify_readme())
    return _settle(path, before, after, write=write, summary="README.md counts rewritten")


def main(argv: list[str] | None = None) -> int:
    """Write both files; with --check, write nothing and fail if either would change."""
    write = "--check" not in (sys.argv[1:] if argv is None else argv)
    results = [update_registry(write=write), update_readme(write=write)]
    print("\n".join(results))
    return int(any("is stale" in line for line in results))


if __name__ == "__main__":
    sys.exit(main())
