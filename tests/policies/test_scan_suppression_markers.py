"""scan-suppression-markers: the script gate that asks before a change adds a scanner suppression."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import gatekit, scriptkit

NAME = "scan-suppression-markers-gate.py"
mod = scriptkit.load("scan-suppression-markers", NAME)
POLICY = scriptkit.script_path("scan-suppression-markers", NAME).parents[1]

# Built by concatenation, the way test_block_test_skips.py builds its markers, so this file never
# carries a marker the gate asks about.
NOSEC = "# no" + "sec"
NOQA = "# no" + "qa"
CONTINUE = "continue-on-" + "error: true"


def payload(writes: dict[str, str], event: str = "commit") -> dict:
    return {"event": event, "repo_root": ".", "writes": writes}


def rules(path: str, text: str) -> list[tuple[int, str]]:
    return [(f["line"], f["rule"]) for f in mod.file_findings(path, text)]


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        (f"run(cmd)  {NOSEC}", "nosec"),
        (f"run(cmd)  {NOSEC} B602", "nosec"),
        ("x := k // #no" + "sec G101", "nosec"),
        ("strcpy(d, s); /* reviewed #no" + "sec */", "nosec"),
        (f"run(a)  {NOQA}: S603", "noqa-security"),
        ("run(a)  #NO" + "QA:E501,S608", "noqa-security"),
        ("var y = 1 //no" + "lint:errcheck,go" + "sec", "nolint-gosec"),
        ("q = a + b; // NO" + "SONAR", "nosonar"),
        ("exec(c)  # no" + "semgrep: python.lang.security", "nosemgrep"),
        ("exec(c) // no" + "sem", "nosemgrep"),
        ("// eslint-" + "disable-next-line security/detect-object-injection", "eslint-disable-security"),
        ("/* eslint-" + "disable no-" + "eval */", "eslint-disable-security"),
        ("// eslint-" + "disable-line react/no-" + "danger", "eslint-disable-security"),
        ("# check" + "ov:skip=CKV_AWS_20: reason", "checkov-skip"),
        ("# bridge" + "crew:skip=CKV_AWS_1", "checkov-skip"),
        ("cidr = x #tf" + "sec:ignore:aws-ec2", "tfsec-trivy-ignore"),
        ("# tri" + "vy:ignore:AVD-DS-0002", "tfsec-trivy-ignore"),
        ("# kics-" + "scan ignore-line", "kics-ignore"),
        ("# hado" + "lint ignore=DL3008", "hadolint-ignore"),
        ("      rules_to_" + "suppress:", "cfn-nag-suppress"),
        ("      ignore_" + "checks: [W3005]", "cfn-lint-ignore"),
        ("uses: a/b@main  # ziz" + "mor: ignore[unpinned-uses]", "zizmor-ignore"),
        ("k = 'x'  # git" + "leaks:allow", "gitleaks-allow"),
        ("k = 'x'  # truffle" + "hog:ignore", "trufflehog-ignore"),
        ("k = 'x'  # pragma: allow" + "list secret", "pragma-allowlist-secret"),
        ("k = 'x'  # Pragma: Allow" + "list nextline secret", "pragma-allowlist-secret"),
        ("el.innerHTML = s; // lg" + "tm[js/xss]", "codeql-suppress"),
        ("el.innerHTML = s; // code" + "ql[js/xss]", "codeql-suppress"),
        ("x = 1 // Dev" + "Skim: ignore DS126858", "devskim-ignore"),
        ("// deep" + "code ignore/XSS: escaped", "deepcode-ignore"),
        ("# bea" + "rer:disable ruby_lang_logger", "bearer-disable"),
        ("/** @psalm-" + "suppress TaintedSql */", "psalm-suppress-taint"),
        ("eval(x) # rubo" + "cop:disable Security/Eval", "rubocop-disable-security"),
        ("#![allow(unsafe_" + "code)]", "rust-allow-unsafe-code"),
        ("#[expect(dead_code, unsafe_" + "code)]", "rust-allow-unsafe-code"),
        ('@SuppressFBWarnings("SQL_INJECTION_' + 'JDBC")', "suppress-security-annotation"),
        ('@Suppress("INSECURE_' + 'TLS")', "suppress-security-annotation"),
        ('[SuppressMessage("Microsoft.Se' + 'curity", "CA2100")]', "suppress-message-security"),
        ('[SuppressMessage("Design", "CA5' + '350:weak")]', "suppress-message-security"),
        ("#pragma warning disable CA5" + "351", "pragma-warning-security"),
        ("#pragma warning disable SCS0" + "005", "pragma-warning-security"),
    ],
)
def test_each_inline_marker_is_reported(line: str, rule: str) -> None:
    assert rules("src/app.code", f"first\n{line}\nlast\n") == [(2, rule)]


@pytest.mark.parametrize(
    "line",
    [
        f"from a import b  {NOQA}: F401",
        f"assert f() == 1  {NOQA}: S101",
        "x = 1  # type: ignore",
        '@SuppressWarnings("unchecked")',
        "#pragma warning disable CS0618",
        "// eslint-" + "disable-next-line no-console",
        "#[allow(dead_code)]",
        "message = 'see the nosecurity flag'",
        "Waiver: 'pragma: allow" + "list secret' on the same line",
        "description: checkov" + ":skip is not honoured",
        "@pytest.mark.skip  # chock: al" + "low test-skip",
        "x = 1  # pragma: allow" + "list invisible-unicode",
        "check = checkov_result.skip_reason",
        "# rubo" + "cop:disable Style/Documentation",
        'SuppressMessage("Style", "IDE0001")',
    ],
)
def test_lines_that_suppress_nothing_security_relevant_are_left_alone(line: str) -> None:
    assert rules("src/app.code", line + "\n") == []


@pytest.mark.parametrize(
    "path",
    [
        "docs/scan.md",
        "README.MD",
        "notes/a.rst",
        "a.txt",
        "guide.adoc",
        "x.mdx",
        "CHANGELOG",
        "pkg/CHANGES.yaml",
        ".agents/policies/scan-secrets/manifest.yaml",
        ".chock/config.yaml",
        "base/x/evals/suite.yaml",
    ],
)
def test_prose_and_managed_files_are_not_judged(path: str) -> None:
    assert mod.file_findings(path, f"run(cmd)  {NOSEC}\n") == []


@pytest.mark.parametrize("name", [".gitleaksignore", ".trivyignore", "sub/.trivyignore.yaml", ".semgrepignore"])
def test_every_entry_of_an_ignore_file_is_reported(name: str) -> None:
    assert [n for n, _ in rules(name, "# reviewed\n\nentry-one\n  entry-two\n")] == [3, 4]


def test_ignore_keys_in_scanner_configs_report_the_key_and_its_block() -> None:
    text = "framework: terraform\nskip-check:\n  - CKV_AWS_20\n  # why\n  - CKV_AWS_21\nquiet: true\n"
    assert rules(".checkov.yml", text) == [
        (2, "checkov-config-skip"),
        (3, "checkov-config-skip"),
        (5, "checkov-config-skip"),
    ]
    assert rules(".hadolint.yaml", "ignored:\n- DL3008\n- DL3009\nfailure-threshold: error\n") == [
        (1, "hadolint-config-ignored"),
        (2, "hadolint-config-ignored"),
        (3, "hadolint-config-ignored"),
    ]
    assert rules(".ansible-lint", "warn_list: [risky-shell-pipe]\nprofile: min\n") == [(1, "ansible-lint-skip-list")]
    assert rules(".bandit", "[bandit]\nskips = B602,B603\n") == [(2, "bandit-config-skips")]


def test_a_config_entry_is_keyed_by_its_owner_and_text() -> None:
    found = mod.file_findings("zizmor.yml", "rules:\n  ignore:\n    - x.yml:3\n")[-1]
    assert found["key"] == "zizmor-config-ignore|ignore|- x.yml:3"


def test_the_gitleaks_allowlist_tables_are_reported() -> None:
    text = "[extend]\nuseDefault = true\n[[rules]]\nid = 'x'\n[rules.allowlist]\n# reviewed\nregexes = ['a']\n"
    assert rules(".gitleaks.toml", text) == [(5, "gitleaks-config-allowlist"), (7, "gitleaks-config-allowlist")]


WORKFLOW = """jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Secrets
        uses: gitleaks/gitleaks-action@v2
        {soft}
      # a comment between steps
      - name: Build
        run: make || true
        {soft}
      - name: Audit
        run: |
          npm audit --audit-level=high || exit 0
          echo done
"""


def test_a_soft_failed_scan_step_is_reported_and_a_soft_failed_build_is_not() -> None:
    found = mod.file_findings(".github/workflows/ci.yml", WORKFLOW.format(soft=CONTINUE))
    assert [(f["line"], f["rule"]) for f in found] == [(7, "ci-scan-soft-fail"), (14, "ci-scan-soft-fail")]
    assert found[0]["key"] == f"ci-scan-soft-fail|- name: Secrets|{CONTINUE}"


def test_job_level_and_top_level_soft_fails_are_judged_by_their_job() -> None:
    job = f"jobs:\n  codeql:\n    {CONTINUE}\n    steps:\n      - uses: github/codeql-action/analyze@v3\n"
    assert rules(".github/workflows/a.yml", job) == [(3, "ci-scan-soft-fail")]
    gitlab = "sast:\n  allow_failure: true\n  script:\n    - semgrep ci\nbuild:\n  allow_failure: true\n"
    assert rules(".gitlab-ci.yml", gitlab) == [(2, "ci-scan-soft-fail")]
    assert rules("bitbucket-pipelines.yml", f"{CONTINUE}  # bandit\n") == [(1, "ci-scan-soft-fail")]


def test_soft_fail_outside_ci_files_is_not_a_ci_finding() -> None:
    assert rules("scripts/ci.yml", "steps:\n  - run: bandit -r . || true\n") == []


def test_a_line_matching_both_a_config_rule_and_a_marker_is_reported_once() -> None:
    assert rules(".semgrepignore", f"tests/  {NOSEC}\n") == [(1, "semgrepignore-entry")]


def test_findings_normalize_windows_paths_and_skip_non_text() -> None:
    found = mod.findings(payload({"src\\a.py": f"x  {NOSEC}\n", "b.py": None}))  # type: ignore[dict-item]
    assert [f["path"] for f in found] == ["src/a.py"]


def test_a_long_line_is_truncated_in_the_report() -> None:
    (found,) = mod.file_findings("a.py", f"{'x' * 300}  {NOSEC}\n")
    assert len(found["message"]) < 170


def test_the_policy_folder_holds_no_marker_it_asks_about() -> None:
    for path in sorted(POLICY.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".yaml"} and path.name != "suite.yaml":
            assert mod.file_findings(f"src/{path.name}", path.read_text(encoding="utf-8")) == [], path


def run_main(monkeypatch: pytest.MonkeyPatch, stdin: str) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return mod.main()


def test_main_allows_asks_and_cannot_judge_bad_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_main(monkeypatch, json.dumps(payload({"a.py": "x = 1\n"}))) == 0
    assert json.loads(capsys.readouterr().out) == {"findings": []}
    assert run_main(monkeypatch, json.dumps(payload({"a.py": f"x  {NOSEC}\n"}))) == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out)["findings"][0]["rule"] == "nosec"
    assert "CHOCK_ALLOW=scan-suppression-markers" in captured.err
    for bad in ("not json", "[]", '{"writes": []}', "{}"):
        assert run_main(monkeypatch, bad) == 2
        assert "cannot judge" in capsys.readouterr().err


def engine(repo: Path, writes: dict[str, str], event: str = gatekit.STOP) -> int:
    """The engine's verdict: `stop` lands the writes on disk first, `commit` stages them."""
    if event in (gatekit.STOP, gatekit.COMMIT):
        scriptkit.write(repo, writes)
    if event == gatekit.COMMIT:
        scriptkit.git(repo, "add", "-A")
    return gatekit.judge("scan-suppression-markers", repo, event, writes)[0]


OLD = f"subprocess.call(cmd)  {NOSEC}\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"app/run.py": OLD})


def test_a_marker_already_in_head_does_not_ask_again(repo: Path) -> None:
    assert engine(repo, {"app/run.py": "import os\n" + OLD + "x = os.sep\n"}) == 0
    assert engine(repo, {"app/run.py": "import os\n" + OLD + "x = os.sep\n"}, gatekit.COMMIT) == 0


def test_a_second_copy_and_a_new_marker_ask(repo: Path) -> None:
    assert engine(repo, {"app/run.py": OLD + OLD}, gatekit.COMMIT) == 1
    assert engine(repo, {"app/new.py": f"eval(x)  {NOQA}: S307\n"}, gatekit.PRE_TOOL_USE) == 3


def test_the_ask_names_only_the_new_marker(repo: Path) -> None:
    code, err = gatekit.judge("scan-suppression-markers", repo, gatekit.PRE_TOOL_USE, {"app/run.py": OLD + OLD})
    assert code == 3
    assert "app/run.py:2" in err
    assert "app/run.py:1:" not in err
    assert not list(repo.rglob("suppression_*.pyc")), "the gate is read_only: it caches no bytecode"


def test_the_script_runs_as_a_process_the_way_the_runner_starts_it(tmp_path: Path) -> None:
    proc = scriptkit.run_script_full(
        "scan-suppression-markers", NAME, tmp_path, json.dumps(payload({"a.tf": "# check" + "ov:skip=CKV_AWS_1\n"}))
    )
    assert proc.returncode == 3
    assert json.loads(proc.stdout)["findings"][0]["rule"] == "checkov-skip"
