#!/usr/bin/env python3
"""Regenerate every derived file in dependency order, then run every check CI runs, once.

    python tools/regen_all.py                # regenerate, then check everything CI checks
    python tools/regen_all.py --fast         # the same, without pytest --cov and the staged adopter
    python tools/regen_all.py --check-only   # write nothing; run the checks
    python tools/regen_all.py --base main    # the ref whose diff picks the transcripts to re-make

Order is load-bearing: plugin packages -> sync (the lockfile hashes packaged files) -> registry
and README counts -> docs, matrix, figures, brand card (read the registry) -> adoption
transcripts (adopt the packaged folder). Checks run cheapest first, in parallel; transcripts
are checked only once the plugin packages are known current.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from importlib.util import find_spec
from pathlib import Path
from typing import NamedTuple

import gen_registry
from gen_adoption_transcript import changed_policy_ids
from trees import ROOT, TREES, policy_dirs

PY = sys.executable
Cmd = list[str] | str
#: Written by `chock sync` with this machine's interpreter path. They are regenerated on purpose
#: when the framework changes (tools/adopt_framework.py), never as a side effect of this tool.
VENDOR_HOOK_CONFIGS = (
    ".claude/settings.json",
    ".cursor",
    ".codex",
    ".devin",
    ".gemini",
    ".github/hooks",
    ".grok",
    ".tabnine",
    ".windsurf",
    ".kimi-code",
    ".chock/bin",
)


#: What `ruff format --check` holds to the formatter; ci.yml's lint step lists the same paths.
FORMATTED = (
    "base/java-security",
    "agentic-security/agentic-code-security",
    "tests",
    "tools/gen_java_security_contract.py",
    "tools/regen_all.py",
    "tools/gen_registry.py",
    "tools/check_installed.py",
    "tools/owasp_llm.py",
    "tools/prose_counts.py",
)


class Result(NamedTuple):
    label: str
    rc: int
    secs: float
    out: str


def run(label: str, cmd: Cmd, cwd: Path = ROOT) -> Result:
    start = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=isinstance(cmd, str),
        check=False,
    )
    return Result(label, proc.returncode, time.monotonic() - start, (proc.stdout + proc.stderr).strip())


def report(result: Result) -> int:
    print(f"  {'ok  ' if result.rc == 0 else 'FAIL'} {result.secs:6.1f}s  {result.label}")
    if result.rc:
        print("\n".join("        " + line for line in result.out.splitlines()[-25:]))
    return result.rc


def plugin_build(tree: str, *, check: bool = False) -> list[str]:
    return ["chock", "plugin", "build", "--repo", ".", "--policies-dir", tree, *(["--check"] if check else [])]


def snapshot(root: Path = ROOT) -> dict[Path, bytes]:
    files = [p for entry in VENDOR_HOOK_CONFIGS for p in [root / entry, *(root / entry).rglob("*")]]
    return {p: p.read_bytes() for p in files if p.is_file()}


def restore(saved: dict[Path, bytes], root: Path = ROOT) -> list[str]:
    """Put the vendor hook configs back as they were; return what sync had rewritten."""
    rewritten = [p for p, data in saved.items() if not p.is_file() or p.read_bytes() != data]
    for path in rewritten:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(saved[path])
    return sorted(p.relative_to(root).as_posix() for p in rewritten)


def sync() -> int:
    """`chock sync`, only when compiled output has drifted, leaving the vendor hook configs alone."""
    if run("sync --check", ["chock", "sync", "--repo", ".", "--check"]).rc == 0:
        return 0
    saved = snapshot()
    rc = report(
        run("chock sync (after packaging: the lockfile hashes packaged files)", ["chock", "sync", "--repo", "."])
    )
    if kept := restore(saved):
        print(f"        kept as committed (adopt_framework.py regenerates them): {', '.join(kept)}")
    return rc


def regenerate(base: str) -> int:
    print("== regenerate (dependency order)")
    rc = max([0] + [report(run(f"plugin build {tree}", plugin_build(tree))) for tree in TREES])
    rc = max(rc, sync())
    for update in (gen_registry.update_registry, gen_registry.update_readme, gen_registry.update_prose):
        start = time.monotonic()
        print(f"  ok   {time.monotonic() - start:6.1f}s  {update()}")
    steps: list[tuple[str, Cmd]] = [
        ("policy docs", [PY, "tools/gen_policy_docs.py"]),
        ("coverage matrix", [PY, "tools/gen_coverage_matrix.py"]),
        ("java-security setup contract", [PY, "tools/gen_java_security_contract.py"]),
        ("quickstart.sh", [PY, "tools/gen_quickstart_sh.py"]),
        ("figures", f'cd docs/figures && for g in make_*.py; do "{PY}" "$g" || exit 1; done'),
    ]
    if find_spec("cairosvg"):
        steps.append(("brand card", f'cd docs/assets && "{PY}" gen_brand_assets.py'))
    else:
        print("  skip          brand card: pip install cairosvg==2.9.0 to regenerate (CI checks the SVG)")
    rc = max([rc] + [report(run(label, cmd)) for label, cmd in steps])
    published = {d.name for d in policy_dirs()}
    for pid in sorted(changed_policy_ids(base) & published):
        rc = max(
            rc, report(run(f"adoption transcript {pid}", [PY, "tools/gen_adoption_transcript.py", "--policy", pid]))
        )
    return rc


def figures_check(scratch: Path) -> Cmd:
    """Re-render the figures in a copy and diff: --check-only writes nothing in the tree."""
    copy = scratch / "figures"
    return (
        f'mkdir -p "{copy}/docs" && cp -r docs/figures "{copy}/docs/" && cp registry.yaml "{copy}/" && '
        f'(cd "{copy}/docs/figures" && for g in make_*.py; do "{PY}" "$g" >/dev/null || exit 1; done) && '
        f'diff -r -x __pycache__ docs/figures "{copy}/docs/figures"'
    )


def fast_checks(scratch: Path) -> list[tuple[str, Cmd]]:
    checks: list[tuple[str, Cmd]] = [
        (name, [PY, f"tools/{script}", *args])
        for name, script, *args in (
            ("registry", "check_registry.py"),
            ("registry, README and prose counts --check", "gen_registry.py", "--check"),
            ("installed policies vs their source", "check_installed.py"),
            ("readme", "check_readme.py"),
            ("policy docs --check", "gen_policy_docs.py", "--check"),
            ("coverage matrix --check", "gen_coverage_matrix.py", "--check"),
            ("java contract --check", "gen_java_security_contract.py", "--check"),
            ("quickstart.sh --check", "gen_quickstart_sh.py", "--check"),
            ("console", "check_console.py"),
            ("workflows", "check_workflows.py"),
            ("effects", "check_effects.py"),
            ("a11y rules", "check_a11y_rules.py"),
            ("a11y table", "check_a11y_table.py"),
        )
    ]
    checks += [
        ("ruff check", ["ruff", "check", "."]),
        ("ruff format", ["ruff", "format", "--check", *FORMATTED]),
        ("sync --check", ["chock", "sync", "--repo", ".", "--check"]),
        ("figures", figures_check(scratch)),
        *((f"plugin --check {tree}", plugin_build(tree, check=True)) for tree in TREES),
    ]
    if find_spec("cairosvg"):
        checks.append(("brand card --check", f'cd docs/assets && "{PY}" gen_brand_assets.py --check'))
    return checks


def stage_adopter(dest: Path) -> Cmd:
    """Every published policy installed into an empty repo, as CI's staged-adopter job does."""
    trees = " ".join(f'"{ROOT / tree}"/*' for tree in TREES)
    return (
        f'set -e; cd "{dest}"; git init -q .; git config user.email ci@chock.invalid; git config user.name ci; '
        f"chock init . --skip-hooks >/dev/null; cp -r {trees} .agents/policies/; "
        f'if [ -d "{ROOT}/skills" ]; then cp -r "{ROOT}"/skills/* .agents/skills/; fi; '
        "chock sync --repo . --skip-hooks >/dev/null; chock check --repo .; "
        'r=$(chock compliance report --framework owasp_asi); ! printf "%s" "$r" | grep -q uncovered'
    )


def slow_checks(base: str, scratch: Path, *, fast: bool, packaged: bool) -> list[tuple[str, Cmd]]:
    checks: list[tuple[str, Cmd]] = [("chock check (validate, lockfile, every eval)", ["chock", "check"])]
    if packaged:
        checks.append(
            ("adoption transcripts --check", [PY, "tools/gen_adoption_transcript.py", "--check", "--base", base])
        )
    if not fast:
        adopter = scratch / "adopter"
        adopter.mkdir()
        checks.append(("staged adopter: check + OWASP claim", stage_adopter(adopter)))
        checks.append(("pytest --cov -n auto", [PY, "-m", "pytest", "--cov", "-n", "auto", "-p", "no:cacheprovider"]))
    return checks


def run_all(checks: list[tuple[str, Cmd]]) -> list[Result]:
    with ThreadPoolExecutor(max_workers=max(len(checks), 1)) as pool:
        return list(pool.map(lambda check: run(*check), checks))


def check(base: str, *, fast: bool) -> int:
    with tempfile.TemporaryDirectory(prefix="catalog-check-") as tmp:
        scratch = Path(tmp)
        print("== checks, fast (parallel)")
        results = run_all(fast_checks(scratch))
        rc = max(report(r) for r in results)
        packaged = all(r.rc == 0 for r in results if r.label.startswith("plugin --check"))
        print("== checks, slow (parallel)" + (": --fast skips pytest --cov and the staged adopter" if fast else ""))
        if not packaged:
            print("  skip          adoption transcripts: plugin packages are stale; run without --check-only")
        return max([rc] + [report(r) for r in run_all(slow_checks(base, scratch, fast=fast, packaged=packaged))])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check-only", action="store_true", help="write nothing; run the checks")
    parser.add_argument("--fast", action="store_true", help="skip pytest --cov and the staged adopter")
    parser.add_argument("--base", default="origin/main", help="ref policies are diffed against")
    args = parser.parse_args(argv)
    if shutil.which("chock") is None:
        print("chock is not on PATH: pip install the framework at the ref in .framework-ref", file=sys.stderr)
        return 1
    start = time.monotonic()
    rc = 0 if args.check_only else regenerate(args.base)
    rc = max(rc, check(args.base, fast=args.fast))
    print(f"== {'CLEAN' if rc == 0 else 'FAILED'} in {time.monotonic() - start:.0f}s")
    return rc


if __name__ == "__main__":
    sys.exit(main())
