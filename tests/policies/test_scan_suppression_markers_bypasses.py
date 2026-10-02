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


W, J = ".github/workflows/a.yml", "jobs:\n  s:\n    steps:\n"
SECOND_ROUND_ASKS = {
    "value after a comment": (
        W,
        J + "      - uses: github/codeql-action/analyze@v3\n        continue-on-" + "error: # ok\n",
    ),
    "bool tag": (W, J + "      - uses: github/codeql-action/analyze@v3\n        continue-on-" + "error: !!bool true\n"),
    "brace true": (W, J + "      - run: bandit -r . || { true; }\n"),
    "or printf": (W, J + "      - run: bandit -r . || printf ''\n"),
    "or command true": (W, J + "      - run: bandit -r . || command true\n"),
    "shell bash +e": (W, J + "      - run: bandit -r .\n        shell: bash +e {0}\n"),
    "bandit exit-zero": (W, J + "      - run: bandit -r . --exit-zero\n"),
    "trivy action exit-code": (
        W,
        J + "      - uses: aquasecurity/trivy-action@0.28.0\n        with:\n          exit-code: '0'\n",
    ),
    "gosec no-fail": (W, J + "      - run: gosec -no-fail ./...\n"),
    "zizmor no exit codes": (W, J + "      - run: zizmor --no-exit-codes .\n"),
    "gitlab template disabled": (".gitlab-ci.yml", 'variables:\n  SAST_DISABLED: "true"\n'),
    "eslint directive after a bare opener": ("a.js", "/*\neslint-" + "disable no-" + "eval\n*/\n"),
    "eslint config array": ("a.js", "/* es" + "lint no-" + "eval: [0] */\n"),
    "eslint config quoted key": ("a.js", "/* es" + 'lint "no-' + 'eval": "off" */\n'),
    "gitleaks marker in a README": ("README.md", "AKIAX  # git" + "leaks:allow\n"),
    "detect-secrets pragma in notes": ("notes.txt", "x  # pragma: allow" + "list secret\n"),
    "a script named history": ("bin/history", f"x  # {NS}\n"),
}
SECOND_ROUND_ALLOWS = {
    "early exit in a scan step": (
        W,
        J + '      - name: gitleaks\n        run: |\n          if [ -z "$F" ]; then\n'
        "            exit 0\n          fi\n          gitleaks detect\n",
    ),
    "exit code captured and passed on": (
        W,
        J + "      - run: |\n          set +e\n          trivy fs --exit-code 1 .\n"
        "          rc=$?\n          set -e\n          exit $rc\n",
    ),
    "or echo inside a substitution": (W, J + "      - run: V=$(semgrep --version || echo unknown)\n"),
    "a root env block": (W, "env:\n  SNYK_TOKEN: x\n  FOO: 'a || true'\njobs:\n  b:\n    steps:\n      - run: make\n"),
    "an eslint-enable block": ("a.js", "/* eslint-" + "enable\n no-" + "eval */\n"),
    "a plain block comment": ("a.js", "/*\n  see the es" + "lint docs: no-" + "eval is banned\n*/\n"),
    "a nosec mention in a README": ("README.md", f"use # {NS}\n"),
    "a secret pragma in an installed policy": (".agents/policies/x/SKILL.md", "k  # pragma: allow" + "list secret\n"),
}


@pytest.mark.parametrize("case", sorted(SECOND_ROUND_ASKS))
def test_the_second_review_bypasses_are_reported(case: str) -> None:
    assert mod.file_findings(*SECOND_ROUND_ASKS[case]), case


@pytest.mark.parametrize("case", sorted(SECOND_ROUND_ALLOWS))
def test_the_second_review_false_positives_are_gone(case: str) -> None:
    assert mod.file_findings(*SECOND_ROUND_ALLOWS[case]) == [], case


@pytest.mark.parametrize(
    "piece",
    [
        "eslint-" + "disable ",
        "/* es" + "lint ",
        "@Sup" + "press(",
        "NO" + "SONAR ",
        "rubo" + "cop:disable ",
        "#pragma warning disable ",
        "//no" + "lint:",
        "#[allow(",
        "Suppress" + "Message(",
        "# no" + "qa: ",
    ],
)
def test_a_repeated_marker_prefix_is_judged_in_linear_time(piece: str) -> None:
    started = time.monotonic()
    mod.file_findings("a.js", piece * 20000 + "\n")
    assert time.monotonic() - started < 5


def test_a_long_ci_run_block_is_judged_in_linear_time() -> None:
    started = time.monotonic()
    text = J + "      - run: |\n" + "          bandit x || true\n" * 8000
    assert len(mod.file_findings(W, text)) == 8000
    assert time.monotonic() - started < 5


THIRD_ROUND = {
    "set +e after an earlier set -e": (
        W,
        J + "      - run: |\n          set -e\n          set +e\n          gitleaks detect\n",
        1,
    ),
    "exit status passed on only in a comment": (
        W,
        J + "      - run: |\n          set +e\n          gitleaks x\n          # exit $rc\n",
        1,
    ),
    "root defaults bash +e": (
        W,
        "defaults:\n  run:\n    shell: bash +e {0}\njobs:\n  s:\n    steps:\n      - run: gitleaks x\n",
        1,
    ),
    "root defaults bash +e with no scan": (
        W,
        "defaults:\n  run:\n    shell: bash +e {0}\njobs:\n  s:\n    steps:\n      - run: make\n",
        0,
    ),
    "quoted gitleaks marker in prose": ("SECURITY.md", "token: ghp_x `git" + "leaks:allow`\n", 1),
    "pragma after a quoted value in prose": ("x.rst", "password = 'hunter2'  # pragma: allow" + "list secret\n", 1),
    "eval suite outside the policy trees": ("src/evals/suite.yaml", "key: AKIA # git" + "leaks:allow\n", 1),
    "a .chock folder below the root": ("app/.chock/x.py", f"x  # {NS}\n", 1),
    "a backticked secret pragma in prose": ("notes.md", "AWS_SECRET=wJalr `# pragma: allow" + "list secret`\n", 1),
    "a quoted secret pragma in prose": ("notes.md", "password: hunter2 'pragma: allow" + "list secret'\n", 1),
    "eslint config with a bare first line": ("a.js", "/* es" + "lint\n  security/detect-object-injection: 0 */\n", 1),
    "eslint config after a bare opener": ("a.js", "/*\nes" + "lint\n  no-" + "eval: 0 */\n", 1),
    "bash +e on a non-scan step beside a scan job": (
        W,
        "jobs:\n  style:\n    steps:\n      - name: style\n        shell: bash +e {0}\n        run: prettier .\n"
        "  sec:\n    steps:\n      - run: semgrep ci\n",
        0,
    ),
    "set -e after the scan does not restore its failure": (
        W,
        J + "      - run: |\n          set +e\n          semgrep ci --error\n          set -e\n",
        1,
    ),
    "a second block comment on the line": (
        "a.js",
        "/* a */ /* eslint-" + "disable\n  security/detect-eval-with-expression */\n",
        1,
    ),
    "no-fail-fast is not no-fail": (W, J + "      - name: security-check\n        run: cargo test --no-fail-fast\n", 0),
}


@pytest.mark.parametrize("case", sorted(THIRD_ROUND))
def test_the_third_review_cases(case: str) -> None:
    path, text, asks = THIRD_ROUND[case]
    assert bool(mod.file_findings(path, text)) == bool(asks), case


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("a.py", " " * 50000 + "rules_to_" + "suppress"),
        ("a.yaml", "".join(" " * i + "k:\n" for i in range(3000))),
        (W, "- x || true\n" * 100000),
        (W, "jobs:\n" + "".join(" " * i + "- x || true\n" for i in range(1, 201)) + ("#" + "y" * 99 + "\n") * 20000),
        ("a.py", "x=1\n" * 500000),
        (".gitleaks.toml", "[" + "a" * 20000 + "]\n" + "\n" * 1000000),
        ("a.java", "@Sup" + "press(" * 300000),
        ("a.js", "// es" + "lint-disable-line " * 100000),
        (W, "".join(" " * i + "k" * 1000 + ":\n" for i in range(1500)) + "|| true\n"),
        (W, "\n" * 1000000),
    ],
)
def test_long_files_and_deep_nesting_are_judged_in_linear_time(path: str, text: str) -> None:
    started = time.monotonic()
    mod.file_findings(path, text)
    assert time.monotonic() - started < 5


FIFTH_ROUND = {
    "semgrep marker with a long s": ("a.py", "call(cmd, shell=True)  # no" + chr(0x17F) + "em" + "grep\n"),
    "gosec disable directive": ("m.go", "x := md5.New() //go" + "sec:disable G401\n"),
    "checkov cortex skip": ("a.tf", "# cor" + "tex:skip=CKV_AWS_18:x\n"),
    "a security code 600 characters into a noqa list": ("a.py", "x  # no" + "qa: " + "E501, " * 100 + "S603\n"),
}


@pytest.mark.parametrize("case", sorted(FIFTH_ROUND))
def test_the_fifth_review_cases_ask(case: str) -> None:
    assert mod.file_findings(*FIFTH_ROUND[case]), case


def test_a_long_eslint_config_rule_run_is_judged_in_linear_time() -> None:
    chunk = "/*es" + "lint " + "xss/" * 75
    started = time.monotonic()
    mod.file_findings("a.js", (chunk * (2000000 // len(chunk) + 1))[:2000000])
    assert time.monotonic() - started < 5
