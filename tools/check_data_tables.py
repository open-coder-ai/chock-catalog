#!/usr/bin/env python3
"""D7: every curated data table carries a valid envelope and is fresh on `--today` (default: the real date).

    python tools/check_data_tables.py                     # today's date: what CI runs
    python tools/check_data_tables.py --today 2027-01-31  # any date, for a deterministic check

A candidate is any file whose name holds `.json` under a folder named `data` (compared after
NFKC and case folding), and any symlink named `data`, anywhere in the repository but SKIP;
symlinks are reported, not followed. Each is read by lib/chock_scan/data_table.py, which refuses
anything but a regular `*.json` directly in `data/`, so a table cannot sit where this check does
not look: place, envelope (schema, kind, as_of, source) and freshness (ioc 120 days, top-n and
curated 365). Only the envelope is checked here; the payload belongs to the
consumer, which loads the table with its own keys and checks. A pre-D7 rule-configuration file
is listed in LEGACY with its reason; a listed path that is gone, or that gained an envelope key,
fails, so the list only shrinks.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import importlib.util
import os
import sys
import unicodedata
from pathlib import Path

from trees import ROOT


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
safe_read = importlib.import_module("_lib_chock_scan.safe_read")

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


#: Not shipped and not tables: version control, the framework checkout CI makes, test fixtures.
SKIP = frozenset({".git", ".framework", "node_modules", "tests"})
SKIP_PARTS = frozenset((s,) for s in SKIP)


def _fold(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold()


def tables(root: Path = ROOT) -> list[Path]:
    """Every candidate table under `root` (see the module docstring), without following symlinks."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        if here == root:
            dirnames[:] = [d for d in dirnames if d not in SKIP]
        found += [here / d for d in dirnames if _fold(d) == "data" and (here / d).is_symlink()]
        if "data" in map(_fold, here.relative_to(root).parts):
            found += [here / f for f in filenames if ".json" in _fold(f)]
    return sorted(found)


def links(root: Path = ROOT) -> list[Path]:
    """Symlinked folders leading outside what `tables` scans: a table behind one would load unseen."""
    real = root.resolve()
    found: list[Path] = []
    for dirpath, dirnames, _ in os.walk(root):
        here = Path(dirpath)
        if here == root:
            dirnames[:] = [d for d in dirnames if d not in SKIP]
        for d in dirnames:
            target = (here / d).resolve()
            if (here / d).is_symlink() and (
                not target.is_relative_to(real) or target.relative_to(real).parts[:1] in SKIP_PARTS
            ):
                found.append(here / d)
    return sorted(found)


def _show(rel: str) -> str:
    return rel if rel.isprintable() else repr(rel)


def _legacy(path: Path) -> list[str]:
    try:
        doc = data_table.parse(safe_read.read_text(path, data_table.LIMIT))
    except (safe_read.UnreadableError, data_table.TableError) as exc:
        return [f"listed in LEGACY but unreadable ({exc})"]
    if keys := sorted(doc.keys() & {"as_of", "kind"}):
        return [f"listed in LEGACY but carries {', '.join(keys)}: check it as a table and delete the entry"]
    return []


def problems(today: dt.date, root: Path = ROOT) -> list[str]:
    """Every table that is misplaced, malformed or stale on `today`, and every LEGACY entry that is wrong."""
    out: list[str] = []
    seen: set[str] = set()
    for path in tables(root):
        rel = path.relative_to(root).as_posix()
        seen.add(rel)
        if rel in LEGACY:
            out += [f"{rel}: {p}" for p in _legacy(path)]
            continue
        try:
            doc = data_table.read(path)
            data_table.check_fresh(doc, today, rel)
        except data_table.TableError as exc:
            out += [f"{_show(rel)}: {p}" for p in exc.problems]
    out += [f"{rel}: listed in LEGACY but not found; delete the entry" for rel in sorted(LEGACY.keys() - seen)]
    hidden = (_show(p.relative_to(root).as_posix()) for p in links(root))
    return out + [f"{rel}: a symlinked folder leading outside the scan could hide a table" for rel in hidden]


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
