"""scan-suppression-markers: the bypasses an adversarial review found, each now reported, and its cost bounds."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from policies import scriptkit

NAME = "scan-suppression-markers-gate.py"
mod = scriptkit.load("scan-suppression-markers", NAME)


def rules(path: str, text: str) -> list[tuple[int, str]]:
    return [(f["line"], f["rule"]) for f in mod.file_findings(path, text)]


NS = "no" + "sec"
REVIEW_BYPASSES = {
    "form feed before the marker": ("a.py", f"call('ls', shell=True)  #\x0c{NS}\n"),
    "next-line before the marker": ("a.py", f"x  #\x85{NS}\n"),
    "line separator before the marker": ("a.py", f"x  #\u2028{NS}\n"),
    "semgrep marker after text": ("a.py", "eval(x)  # reviewed: no" + "semgrep\n"),
    "semgrep marker in a VB comment": ("a.vb", "eval(x) ' no" + "semgrep\n"),
    "ruff file-level noqa": ("a.py", "# ruff: no" + "qa: S602\n"),
    "flake8 file-level noqa": ("a.py", "# flake8: no" + "qa: S602\n"),
    "eslint inline config off": ("a.js", "/* eslint no-" + 'eval: "off" */\n'),
    "eslint inline config 0": ("a.js", "/* es" + "lint security/detect-object-injection: 0 */\n"),
    "eslint disable over two lines": ("a.js", "/* eslint-" + "disable\n   no-" + "eval */\neval(x)\n"),
    "detect-secrets whitelist form": ("a.py", "x = 1  # pragma: white" + "list secret\n"),
    "detect-secrets hyphen form": ("a.py", "x = 1  # pragma: allow" + "list-secret\n"),
    "detect-secrets VB comment": ("a.vb", "x = 1 ' pragma: allow" + "list secret\n"),
    "gitleaks marker in JSON data": ("k.json", '{"k": "A", "note": "git' + 'leaks:allow"}\n'),
    "trufflehog marker in JSON data": ("k.json", '{"k": "A", "note": "truffle' + 'hog:ignore"}\n'),
    "code named like a changelog": ("src/history.py", f"x  # {NS}\n"),
    "hadolint global ignore": ("Dockerfile", "# hadolint global ig" + "nore=DL3008\n"),
    "checkov kubernetes annotation": ("k8s/pod.yaml", "  annotations:\n    checkov.io/s" + "kip1: CKV_K8S_20=ok\n"),
}
CI_BYPASSES = {
    "checkov soft-fail flag": "      - run: checkov -d . --soft-fail\n",
    "trivy exit code 0": "      - run: trivy fs --exit-code 0 .\n",
    "quoted or-true": "      - run: bash -c 'gitleaks detect || true'\n",
    "or bin true": "      - run: bandit -r . || /bin/true\n",
    "or echo": "      - run: bandit -r . || echo failed\n",
    "set +e": "      - name: b\n        run: |\n          set +e\n          bandit -r .\n",
    "flow mapping": "      - {uses: github/codeql-action/analyze@v3, continue-on-error: true}\n",
    "quoted key": "      - uses: github/codeql-action/analyze@v3\n        'continue-on-error': true\n",
}


@pytest.mark.parametrize("case", sorted(REVIEW_BYPASSES))
def test_the_review_bypasses_are_reported(case: str) -> None:
    assert mod.file_findings(*REVIEW_BYPASSES[case]), case


@pytest.mark.parametrize("case", sorted(CI_BYPASSES))
def test_the_review_ci_bypasses_are_reported(case: str) -> None:
    text = "jobs:\n  s:\n    steps:\n" + CI_BYPASSES[case]
    assert rules(".github/workflows/a.yml", text)[-1][1] == "ci-scan-soft-fail", case


@pytest.mark.parametrize(
    "text",
    [
        "sast:\n  allow_failure:\n    exit_codes: 1\n",
        "secret_detection:\n  allow_failure: true\n",
        "x:\n  script: semgrep ci\n  allow_failure: {exit_codes: 1}\n",
    ],
)
def test_gitlab_soft_fail_shapes_are_reported(text: str) -> None:
    assert rules(".gitlab-ci.yml", text)[0][1] == "ci-scan-soft-fail"


def test_an_or_true_on_its_own_step_is_judged_by_that_step_only() -> None:
    text = "jobs:\n  build:\n    steps:\n      - run: make || true\n      - run: semgrep ci\n"
    assert rules(".github/workflows/a.yml", text) == []
    named = "jobs:\n  s:\n    steps:\n      - name: Build security docs\n        run: make docs || true\n"
    assert rules(".github/workflows/a.yml", named) == []


def test_an_eslint_block_names_only_its_security_lines() -> None:
    text = "/* eslint-" + "disable\n   no-console,\n   no-" + "eval */\n/* eslint-" + "disable no-console */\nx()\n"
    assert rules("a.js", text) == [(3, "eslint-disable-security")]


def test_a_minified_line_is_judged_in_linear_time() -> None:
    started = time.monotonic()
    assert mod.file_findings("dist/app.min.js", "a=b*c--d//e;" * 40000 + "\n") == []
    assert time.monotonic() - started < 2


def test_the_gate_writes_no_bytecode_where_it_runs(tmp_path: Path) -> None:
    source = scriptkit.script_path("scan-suppression-markers", NAME).parent
    copy = tmp_path / "implementations"
    shutil.copytree(source, copy, ignore=shutil.ignore_patterns("__pycache__"))
    proc = subprocess.run(
        [sys.executable, str(copy / NAME)],
        input=json.dumps({"event": "commit", "writes": {"a.py": "x = 1\n"}}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert not list(copy.rglob("__pycache__")), "the gate is read_only: it caches no bytecode"
