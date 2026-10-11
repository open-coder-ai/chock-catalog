#!/usr/bin/env python3
"""Write registry.yaml's rows, the README's counts and the prose counts from the policies on disk.

check_registry.py and check_readme.py verify these facts; this writes them, so a version bump or
an eval case is never a hand edit to two files. A row is rebuilt from its manifest, keeping only
the description's hand wrapping while the text is unchanged; a removed policy's row goes.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import prose_counts
import yaml
from agentseam import packaging
from check_readme import classify_readme
from check_registry import said, suite_counts
from chock.plugin import bundle_build, bundle_grade
from chock.plugin.store import SCRIPTS_TEMPLATE
from label_honesty import TEXT_ONLY_SAYS, data_label, fail_open_qualifier, honest_asks, status_label
from mechanism import CEILING, NONE, classify
from trees import ROOT, TREES, policy_dirs

#: Every row field but `id` and `description`, in the order each row lists them.
FIELDS = (
    "path",
    "version",
    "artifact",
    "enforcement",
    "status",
    "mandatory",
    "mechanism",
    "enforces",
    "eval_cases",
    "eval_executed",
)
#: Label key, build format, then the engine's own hooks path and agent for that format.
LABEL_FORMATS = (
    ("claude-code", "claude"),
    ("cursor", "cursor"),
    ("codex", "codex"),
    ("copilot", "copilot"),
    ("devin", "devin"),
)
#: The marker whose trailing sentence is what a policy says it misses.
MISSES = re.compile(r"(?:Misses|Not caught here):\s*(.*?\.(?=\s|$)|.*)", re.S)
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
        "status": (manifest.get("lifecycle") or {}).get("status"),
        "mandatory": bool(manifest.get("mandatory")),
        "mechanism": mechanism,
        "enforces": CEILING[kind],
        "eval_cases": total,
        "eval_executed": executed,
        "description": manifest.get("description") or "",
    }


def misses(description: str) -> str | None:
    """The sentence after the first `Misses:` or `Not caught here:`, or None."""
    found = MISSES.search(" ".join(description.split()))
    return found.group(1).strip() if found else None


def derive_labels(root: Path = ROOT) -> dict[str, dict]:
    """Each policy's label, graded by the engine from the hooks its built packages ship."""
    labels: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for tree in TREES:
            if (root / tree).is_dir():
                subprocess.run(
                    ["chock", "plugin", "build", "--repo", str(root), "--policies-dir", tree, "--format", "all",
                     "--out-dir", str(Path(tmp) / tree)],
                    check=True, capture_output=True, text=True,
                )  # fmt: skip
        for policy_dir in policy_dirs(root):
            manifest = yaml.safe_load((policy_dir / "manifest.yaml").read_text(encoding="utf-8"))
            built = Path(tmp) / policy_dir.parent.name
            policy_kind, _ = classify(policy_dir, manifest)
            label: dict = {}
            for key, fmt in LABEL_FORMATS:
                client = bundle_build.CLIENTS[fmt]
                package = built / fmt / manifest["id"]
                hooks = package / packaging.supports(client.package_agent, packaging.HOOKS)
                gate = package / SCRIPTS_TEMPLATE.format(name="gate.json")
                hooks_text = hooks.read_text(encoding="utf-8") if hooks.is_file() else None
                grade, says = bundle_grade.grade_of(
                    hooks_text, gate.read_text(encoding="utf-8") if gate.is_file() else None, client.agent
                )
                if hooks_text is None and policy_kind != NONE:
                    says = TEXT_ONLY_SAYS
                elif hooks_text is not None:
                    grade, says = honest_asks(grade, says, hooks_text, client.agent)
                    says += fail_open_qualifier(client.agent)
                label[key] = {"keyword": bundle_grade.enforcement_keyword(grade), "says": says}
            if status := status_label(manifest):
                label["status"] = status
            if dated := data_label(policy_dir):
                label["data"] = dated
            label["misses"] = misses(manifest.get("description") or "")
            labels[manifest["id"]] = label
    return labels


def _flow(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def _label(label: dict) -> list[str]:
    """The `label:` block, one flow mapping per format (JSON is valid YAML flow)."""
    return [
        "  label:",
        *(f"    {k}: {_flow(v)}" for k, v in label.items() if k != "misses"),
        f"    misses: {_flow(label['misses'])}",
    ]


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


def _old_label(old: list[str]) -> list[str]:
    """The label lines an existing row already carries, for a caller that derives none."""
    start = next((i for i, line in enumerate(old) if line == "  label:"), None)
    if start is None:
        return []
    end = start + 1
    while end < len(old) and old[end].startswith("    "):
        end += 1
    return old[start:end]


def render_row(row: dict, old: list[str]) -> list[str]:
    return [
        f"- id: {row['id']}",
        *(f"  {k}: {_scalar(row[k])}" for k in FIELDS),
        *(_label(row["label"]) if "label" in row else _old_label(old)),
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
    labels = derive_labels(root)
    on_disk = {row["id"]: {**row, "label": labels[row["id"]]} for row in (facts(d, root) for d in policy_dirs(root))}
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


def update_prose(root: Path = ROOT, *, write: bool = True) -> str:
    """SECURITY.md and CONTRIBUTING.md counts, from the registry this module just wrote."""
    return "\n".join(prose_counts.update(root, write=write))


def main(argv: list[str] | None = None) -> int:
    """Write every file; with --check, write nothing and fail if any would change.

    --registry-only touches registry.yaml alone: the rows adopters read from main stay current on
    every PR, while the README and prose counts lag until the release.
    """
    args = sys.argv[1:] if argv is None else argv
    write = "--check" not in args
    updates = (update_registry,) if "--registry-only" in args else (update_registry, update_readme, update_prose)
    results = [update(write=write) for update in updates]
    print("\n".join(results))
    return int(any("is stale" in result for result in results))


if __name__ == "__main__":
    sys.exit(main())
