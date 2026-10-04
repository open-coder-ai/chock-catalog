"""Every file a generator writes is derived (no test reads it) or belongs to one policy: none forces a full run."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import select_tests
import untraced
from trees import policy_dirs

ROOT = select_tests.ROOT
KEEP = ("tools", "lib", "base", "compliance", "agentic-security", "docs", "skills")
ROOT_FILES = ("registry.yaml", "README.md", "SECURITY.md", "CONTRIBUTING.md", "pyproject.toml")
#: command, working directory. cairosvg is stubbed: the generators only need it to exist to write their PNGs.
GENERATORS = [
    (["tools/gen_registry.py"], "."),
    (["tools/gen_policy_docs.py"], "."),
    (["tools/gen_coverage_matrix.py"], "."),
    (["tools/gen_java_security_contract.py"], "."),
    (["tools/gen_quickstart_sh.py"], "."),
    (["tools/gen_lib_copies.py"], "."),
    (["tools/gen_adoption_transcript.py", "--policy", sorted(p.name for p in policy_dirs())[0]], "."),
    (["make_enforcement.py"], "docs/figures"),
    (["make_family.py"], "docs/figures"),
    (["make_social.py"], "docs/figures"),
    (["gen_brand_assets.py"], "docs/assets"),
]
STUB = "from pathlib import Path\n\n\ndef svg2png(**kw):\n    Path(kw['write_to']).write_bytes(b'')\n"


def test_every_generator_in_the_catalog_is_run_here() -> None:
    """A new generator must be added to GENERATORS, so its outputs are classified."""
    found = {
        p.relative_to(ROOT).as_posix()
        for pattern in ("tools/gen_*.py", "docs/figures/make_*.py", "docs/assets/gen_*.py")
        for p in ROOT.glob(pattern)
    }
    listed = {f"{cwd}/{cmd[0]}".removeprefix("./") if cwd != "." else cmd[0] for cmd, cwd in GENERATORS}
    assert found == {f.removeprefix("./") for f in listed}


def written_by_the_generators(tmp_path: Path) -> list[str]:
    """Run each generator in a copy of the repo whose files all start at time 0; what moved was written.

    Outside the coverage tracer: a copy's tools are not the ones under test, and the paths they would
    leave in the coverage data are gone by the time `coverage report` reads it.
    """
    copy = tmp_path / "repo"
    skip = shutil.ignore_patterns("__pycache__", "*.pyc")
    for name in KEEP:
        if (ROOT / name).exists():
            shutil.copytree(ROOT / name, copy / name, ignore=skip)
    for name in ROOT_FILES:
        shutil.copy(ROOT / name, copy / name)
    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "cairosvg.py").write_text(STUB, encoding="utf-8")
    for path in copy.rglob("*"):
        if path.is_file():
            os.utime(path, (0, 0))
    env = {**untraced.clean_env(), "PYTHONPATH": str(stub), "PYTHONUTF8": "1"}
    for cmd, cwd in GENERATORS:
        script = (copy / cwd / cmd[0]).as_posix()
        proc = subprocess.run(
            [sys.executable, script, *cmd[1:]], cwd=copy / cwd, env=env, capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, f"{cmd[0]}: {proc.stderr[-400:]}"
    return sorted(
        p.relative_to(copy).as_posix()
        for p in copy.rglob("*")
        if p.is_file() and p.stat().st_mtime > 0 and "__pycache__" not in p.parts
    )


def test_every_file_a_generator_writes_is_derived_or_one_policys(tmp_path: Path) -> None:
    written = written_by_the_generators(tmp_path)
    assert {"docs/quickstart.sh", "docs/assets/social-preview.png", "docs/figures/social-card.svg"} <= set(written)
    ids, graph = set(select_tests.policy_ids(ROOT)), select_tests.import_graph(ROOT)
    back = select_tests.importers(graph)
    forcing = [rel for rel in written if select_tests.attribute(ROOT, rel, ids, graph, back) is None]
    assert forcing == [], f"each of these forces a full run; classify it in select_tests.GENERATED: {forcing}"
