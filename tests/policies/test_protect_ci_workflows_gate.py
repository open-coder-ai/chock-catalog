"""protect-ci-workflows: the tool_use gate that asks a person before an Edit/Write to CI, hook or bot config."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

import pytest
from chock.gate import runner
from chock.gate.write_gate import repo_paths
from policies import gatekit, guardkit, scriptkit
from trees import ROOT

POLICY = "protect-ci-workflows"
guard = guardkit.load_guard(POLICY)
PATHS = [
    ".github/workflows/ci.yml",
    ".github/workflows/release.yaml",
    ".github/workflows",
    ".github/actions/setup/action.yml",
    ".github/workflow-templates/ci.yml",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    ".gitlab/CODEOWNERS",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "ci/build.gitlab-ci.yml",
    ".gitlab/ci/test.yml",
    ".gitlab-ci/deploy.yml",
    "Jenkinsfile",
    "Jenkinsfile.release",
    "ci/Jenkinsfile",
    "Jenkinsfile-prod.groovy",
    "Jenkinsfile_nightly",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    "azure-pipelines-release.yaml",
    ".azure-pipelines/build.yml",
    "bitbucket-pipelines.yml",
    ".buildkite/pipeline.yml",
    "buildkite.yml",
    ".drone.yml",
    ".drone.jsonnet",
    ".drone.star",
    "cloudbuild.yaml",
    "deploy/cloudbuild-prod.json",
    "renovate.json",
    "renovate.json5",
    ".github/renovate.json",
    ".renovaterc",
    ".renovaterc.json",
    ".pre-commit-config.yaml",
    ".husky/pre-commit",
    ".husky",
    "lefthook.yml",
    ".lefthook.yaml",
    "lefthook-local.toml",
    ".githooks/pre-push",
    ".lefthook/pre-commit/lint.sh",
    ".lefthook-local/pre-push/x.sh",
    ".travis.yml",
    "action.yml",
    "tools/lint/action.yaml",
    ".woodpecker.yml",
    ".woodpecker/build.yml",
    "appveyor.yml",
    ".appveyor.yml",
    ".cirrus.yml",
    "buildspec.yml",
    "buildspec-test.yaml",
    ".semaphore/semaphore.yml",
    ".tekton/pipeline.yaml",
    "bitrise.yml",
    "codemagic.yaml",
    # Respellings: case, backslashes, repeated and dot segments, Windows trailing dots and spaces, NTFS streams.
    ".GITHUB/WORKFLOWS/CI.YML",
    ".GitHub/Workflows/ci.yml",
    "jenkinsfile",
    ".github\\workflows\\ci.yml",
    ".github//workflows/ci.yml",
    ".github/./workflows/ci.yml",
    ".github/.//./workflows/ci.yml",
    ".github./workflows/ci.yml",
    ".github /workflows/ci.yml",
    ".github/workflows. /ci.yml",
    ".gitlab-ci.yml.",
    ".gitlab-ci.yml ",
    ".gitlab-ci.yml::$DATA",
    ".travis.yml:stream",
    ".github::$INDEX_ALLOCATION/workflows/ci.yml",
    ".github/workflows::$INDEX_ALLOCATION/ci.yml",
    ".circleci:x/config.yml",
    "sub/repo/.github/workflows/ci.yml",
]
UNRELATED = [
    "README.md",
    "docs/README.md",
    "src/app.py",
    "docs/workflows.md",
    "src/actions/index.ts",
    "src/workflows/run.py",
    "my.github/workflows.txt",
    ".github/ISSUE_TEMPLATE/bug.md",
    ".github/pull_request_template.md",
    ".github/copilot-instructions.md",
    ".github/FUNDING.yml",
    "CODEOWNERS.md",
    "docs/codeowners-guide.md",
    "transaction.yml",
    "reaction.yaml",
    "actions.yml",
    "Jenkins.md",
    "jenkinsfile_parser.py",
    "docs/Jenkinsfile-notes.txt",
    "src/JenkinsfileReader.java",
    "docs/jenkins/setup.md",
    "gitlab-ci.md",
    "renovate.md",
    "husky.js",
    "travis.yml.bak/x",
    "buildspec.md",
    "src/cloudbuild.py",
    ".pre-commit-hooks.yaml",
    "pre-commit-config.yaml",
]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {".github/workflows/ci.yml": "on: push\n", "src/app.py": "x = 1\n"})


def pattern() -> re.Pattern[str]:
    return re.compile(gatekit.gate_spec(POLICY)["params"]["forbidden_path_regex"])


def test_the_gate_asks_at_tool_use_only_and_has_no_waiver() -> None:
    manifest = scriptkit.manifest(POLICY)
    assert manifest["artifact"] == "rule"
    gate = manifest["hook"]["gate"]
    assert (gate["kind"], gate["on"], gate["action"]) == ("content_regex", ["tool_use"], "ask")
    assert gate["params"]["content_pattern"] == "(?!)"
    assert "allowlist_pragma" not in gate["params"]
    assert "propose the change" in gate["message"]


@pytest.mark.parametrize("path", PATHS)
def test_a_write_to_ci_config_asks_a_person(repo: Path, path: str) -> None:
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "new\n"}, {path: "new\n"})
    assert code == runner.EXIT_ASK
    assert "forbidden path" in err
    assert "person" in err


@pytest.mark.parametrize("path", UNRELATED)
def test_a_write_elsewhere_passes(repo: Path, path: str) -> None:
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {path: "new\n"}, {path: "new\n"}) == (0, "")


def test_the_runner_asks_on_an_empty_or_whole_file_write(repo: Path) -> None:
    # The runner asks on an empty write; the pinned adapter drops empty Write content first (a documented limit).
    for text in ("", "a\nb\n"):
        assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {".gitlab-ci.yml": text})[0] == runner.EXIT_ASK


def test_one_ci_file_among_ordinary_writes_still_asks(repo: Path) -> None:
    writes = {"src/app.py": "x = 2\n", ".circleci/config.yml": "version: 2.1\n"}
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, writes)[0] == runner.EXIT_ASK


def test_the_turns_end_warns_about_a_changed_workflow(repo: Path) -> None:
    (repo / ".github/workflows/ci.yml").write_text("on: workflow_dispatch\n", encoding="utf-8")
    code, err = gatekit.judge(POLICY, repo, gatekit.STOP, {".github/workflows/ci.yml": "on: workflow_dispatch\n"})
    assert code == runner.EXIT_WARN
    assert "forbidden path" in err


def test_the_turns_end_passes_when_no_ci_file_changed(repo: Path) -> None:
    assert gatekit.judge(POLICY, repo, gatekit.STOP, {"src/app.py": "x = 2\n"}) == (0, "")


def test_a_commit_is_never_judged_so_a_person_edits_freely(repo: Path) -> None:
    (repo / ".github/workflows/ci.yml").write_text("on: workflow_dispatch\n", encoding="utf-8")
    scriptkit.git(repo, "add", "-A")
    assert gatekit.judge(POLICY, repo, gatekit.COMMIT) == (0, "")


def test_the_gate_covers_everything_the_shell_guard_protects() -> None:
    gate = pattern()
    for part in guard.PROTECTED:
        inside = [] if part.endswith((".yml", ".yaml")) else [f"{part}/x.yml"]
        for path in [part, f"deep/{part}", part.upper(), part.replace("/", "\\"), *inside]:
            assert guard.hit(path.lower())
            assert gate.search(path), f"the gate misses {path}"


@pytest.mark.parametrize(
    "written",
    ["src/../.github/workflows/ci.yml", "./.github/workflows/ci.yml", "a/b/../../.gitlab-ci.yml", "{root}/.travis.yml"],
)
def test_the_engine_folds_a_path_before_the_gate_matches_it(repo: Path, written: str) -> None:
    names = repo_paths(written.format(root=repo), repo)
    assert any(pattern().search(name) for name in names), names


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_write_through_a_symlink_into_ci_config_is_judged_as_its_target(repo: Path) -> None:
    (repo / "ci").symlink_to(repo / ".github" / "workflows", target_is_directory=True)
    names = repo_paths("ci/new.yml", repo)
    assert "ci/new.yml" in names
    assert ".github/workflows/new.yml" in names
    assert any(pattern().search(name) for name in names)


@pytest.mark.parametrize(
    "path",
    [
        "Jenkinsfile" + ". :" * 6000 + "/x",
        "a" + ".gitlab-ci.yml:" * 5000 + "/",
        "cloudbuild" + ".yml:" * 5000 + "/",
        "buildspec" + ".gitlab-ci.yml:" * 5000 + "/",
        ".github" + " ." * 8000 + "/x",
        ".github/" + "./" * 8000 + "x",
        ".github" + ":a" * 8000 + "/x",
    ],
    ids=[
        "jenkinsfile-suffix",
        "gitlab-stream",
        "cloudbuild-stream",
        "buildspec-stream",
        "dir-spaces",
        "dot-segments",
        "dir-stream",
    ],
)
def test_a_long_hostile_path_is_matched_in_linear_time(path: str) -> None:
    gate = pattern()
    start = time.perf_counter()
    gate.search(path)
    assert time.perf_counter() - start < 0.5


def test_on_this_catalog_only_its_ci_files_match() -> None:
    listed = subprocess.run([scriptkit.GIT, "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True)
    tracked = listed.stdout.split("\0")
    hits = [path for path in tracked if path and pattern().search(path)]
    ci = re.compile(r"\.github/(workflows/[^/]+\.ya?ml|dependabot\.yml|CODEOWNERS)")
    assert hits
    assert [path for path in hits if not ci.fullmatch(path)] == []
