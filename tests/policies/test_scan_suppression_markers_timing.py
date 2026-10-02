"""scan-suppression-markers: long lines, long files and deep nesting stay inside the gate's time budget."""

from __future__ import annotations

import time

import pytest
from policies import scriptkit

mod = scriptkit.load("scan-suppression-markers", "scan-suppression-markers-gate.py")
W, J = ".github/workflows/a.yml", "jobs:\n  s:\n    steps:\n"


def test_a_minified_line_is_judged_in_linear_time() -> None:
    started = time.monotonic()
    assert mod.file_findings("dist/app.min.js", "a=b*c--d//e;" * 40000 + "\n") == []
    assert time.monotonic() - started < 2


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


def test_a_long_eslint_config_rule_run_is_judged_in_linear_time() -> None:
    chunk = "/*es" + "lint " + "xss/" * 75
    started = time.monotonic()
    mod.file_findings("a.js", (chunk * (2000000 // len(chunk) + 1))[:2000000])
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("gap", [" " * 970, "\t" * 970])
def test_whitespace_after_an_eslint_config_rule_is_judged_in_linear_time(gap: str) -> None:
    unit = "/* es" + "lint security/a:" + gap + "x"
    started = time.monotonic()
    mod.file_findings("src/a.js", (unit * (2000000 // len(unit) + 1))[:2000000])
    assert time.monotonic() - started < 5
