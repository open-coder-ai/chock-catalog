#!/usr/bin/env python3
"""D7: every curated data table carries a valid envelope and is fresh on `--today` (default: the real date).

    python tools/check_data_tables.py                     # today's date: what CI runs
    python tools/check_data_tables.py --today 2027-01-31  # any date, for a deterministic check

A table is any `data/*.json` at the root or at any depth under a published policy. Each is read
by lib/chock_scan/data_table.py: envelope (schema, kind, as_of, source) and freshness (ioc 120
days, top-n and curated 365). Only the envelope is checked here; the payload belongs to the
consumer, which loads the table with its own keys and checks. A pre-D7 rule-configuration file
is listed in LEGACY with its reason; a listed path that is gone fails, so the list only shrinks.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import importlib.util
import sys
from pathlib import Path

from trees import ROOT, policy_dirs


def _lib_module() -> object:
    """lib/chock_scan/data_table.py under a private name: tests/ also holds a `chock_scan` package."""
    package = ROOT / "lib" / "chock_scan"
    spec = importlib.util.spec_from_file_location(
        "_lib_chock_scan", package / "__init__.py", submodule_search_locations=[str(package)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return importlib.import_module("_lib_chock_scan.data_table")


data_table = _lib_module()

JAVA = "base/java-security/implementations/chock_security/data/"
A11Y = "base/no-a11y-regression/implementations/data/"
#: Rule configuration that predates D7 (patterns, scopes, names the rules match), not dated
#: snapshots of an outside list; retrofitting the envelope changes those policies, so it is
#: its own PR per policy. A new table is never added here.
LEGACY = {
    **{
        JAVA + f"{name}.json": "java-security rule configuration (pre-D7)"
        for name in [
            "android",
            "bugs",
            "build",
            "concurrency",
            "crypto",
            "cwe",
            "exceptions",
            "jakarta",
            "java",
            "logging",
            "performance",
            "persistence",
            "resources",
            "spring",
            "style",
            "templates",
            "testing",
        ]
    },
    A11Y + "element_requirements.json": "no-a11y-regression rule configuration (pre-D7)",
    A11Y + "uninformative_names.json": "no-a11y-regression rule configuration (pre-D7)",
}


def tables(root: Path = ROOT) -> list[Path]:
    """Every data/*.json at the root and under each published policy, at any depth."""
    found = {p for d in root.iterdir() if d.is_dir() for p in d.glob("*") if _is_table(p)}
    for policy in policy_dirs(root):
        found |= {p for p in policy.rglob("*") if _is_table(p)}
    return sorted(found)


def _is_table(path: Path) -> bool:
    """Case-blind, so `Data/x.JSON` cannot slip past the check on a case-sensitive filesystem."""
    return path.parent.name.casefold() == "data" and path.suffix.casefold() == ".json"


def problems(today: dt.date, root: Path = ROOT) -> list[str]:
    """Every table that is malformed or stale on `today`, and every LEGACY entry that is gone."""
    out: list[str] = []
    seen: set[str] = set()
    for path in tables(root):
        rel = path.relative_to(root).as_posix()
        seen.add(rel)
        if rel in LEGACY:
            continue
        try:
            doc = data_table.read(path)
            data_table.check_fresh(doc, today, rel)
        except data_table.TableError as exc:
            out += [f"{rel}: {p}" for p in exc.problems]
    return out + [f"{rel}: listed in LEGACY but not found; delete the entry" for rel in sorted(LEGACY.keys() - seen)]


def _date(value: str) -> dt.date:
    if not data_table.DATE.fullmatch(value):
        msg = f"not a YYYY-MM-DD date: {value}"
        raise argparse.ArgumentTypeError(msg)
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--today", type=_date, default=None, help="the date to judge freshness on (YYYY-MM-DD)")
    args = parser.parse_args(argv)
    today = args.today or dt.datetime.now(dt.UTC).date()
    if found := problems(today, root):
        print(f"data tables are malformed or stale on {today} (re-check each against its sources):")
        print("\n".join("  " + p for p in found))
        return 1
    count = sum(p.relative_to(root).as_posix() not in LEGACY for p in tables(root))
    print(f"data tables: {count} checked, fresh on {today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
