"""ci-github-actions-security, packs triggers, permissions and agents."""

from __future__ import annotations

import pytest
from policies.ghakit import model, of, workflow

PRT = "  pull_request_target:"
CHECKOUT = "      - uses: actions/checkout@v4\n        with:\n          ref: {ref}\n"


@pytest.mark.parametrize(
    "ref",
    [
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.head_ref }}",
        "refs/pull/${{ github.event.number }}/merge",
        "${{ steps.pr.outputs.sha }}",
        "${{ github.event.workflow_run.head_sha }}",
    ],
)
def test_prt_head_checkout(ref: str) -> None:
    assert of("gha-prt-head-checkout", workflow(PRT, CHECKOUT.format(ref=ref)))


@pytest.mark.parametrize("ref", ["${{ github.sha }}", "main", "${{ github.event.pull_request.base.sha }}"])
def test_base_checkout_is_not_head(ref: str) -> None:
    assert not of("gha-prt-head-checkout", workflow(PRT, CHECKOUT.format(ref=ref)))


def test_head_checkout_needs_a_dangerous_trigger_and_covers_scripts_and_repository() -> None:
    head = CHECKOUT.format(ref="${{ github.event.pull_request.head.sha }}")
    assert not of("gha-prt-head-checkout", workflow("  pull_request:", head))
    repo = "      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
    assert of("gha-prt-head-checkout", workflow("  workflow_run:\n    workflows: [ci]", repo))
    script = "      - run: gh pr checkout ${{ github.event.issue.number }}\n"
    assert of("gha-prt-head-checkout", workflow("  issue_comment:", script))
    fetch = "      - run: git fetch origin ${{ github.event.pull_request.head.sha }}\n"
    assert of("gha-prt-head-checkout", workflow(PRT, fetch))


def test_dangerous_trigger_each_once() -> None:
    text = "on: [pull_request_target, workflow_run, issue_comment, push]\npermissions: {}\njobs: {}\n"
    assert sorted(f["key"] for f in of("gha-dangerous-trigger", text)) == [
        "gha-dangerous-trigger|on|issue_comment",
        "gha-dangerous-trigger|on|pull_request_target",
        "gha-dangerous-trigger|on|workflow_run",
    ]
    assert model.triggers(model.Tree([])) == set()
    assert not of("gha-dangerous-trigger", "on: push\njobs: {}\n")


def test_quoted_on_key_and_scalar_trigger() -> None:
    assert of("gha-dangerous-trigger", '"on": pull_request_target\npermissions: {}\njobs: {}\n')


@pytest.mark.parametrize(
    ("uses", "extra", "hit"),
    [
        ("actions/download-artifact@v4", "run-id: ${{ github.event.workflow_run.id }}", True),
        ("actions/download-artifact@v4", "github-token: ${{ github.token }}", True),
        ("actions/download-artifact@v4", "name: x", False),
        ("actions/download-artifact@v4", "run-id: 1\n          path: ${{ runner.temp }}/a", False),
        ("dawidd6/action-download-artifact@v6", "name: x", True),
        ("dawidd6/action-download-artifact@v6", "path: ${{ runner.temp }}/a", False),
        ("actions/github-script@v7", "script: github.rest.actions.downloadArtifact({})", True),
        ("actions/github-script@v7", "script: console.log(1)", False),
    ],
)
def test_workflow_run_artifact(uses: str, extra: str, hit: bool) -> None:
    steps = f"      - uses: {uses}\n        with:\n          {extra}\n"
    assert bool(of("gha-workflow-run-artifact", workflow("  workflow_run:", steps))) is hit
    assert not of("gha-workflow-run-artifact", workflow("  push:", steps))


def test_workflow_run_gh_run_download() -> None:
    steps = "      - run: gh run download 1\n      - run: gh run download 2 -D $RUNNER_TEMP/a\n"
    assert len(of("gha-workflow-run-artifact", workflow("  workflow_run:", steps))) == 1


@pytest.mark.parametrize("runs_on", ["self-hosted", "[self-hosted, linux]", "\n      labels: [Self-Hosted]"])
def test_self_hosted_on_pull_requests(runs_on: str) -> None:
    text = f"on: pull_request\npermissions: {{}}\njobs:\n  a:\n    runs-on: {runs_on}\n    steps: []\n"
    assert of("gha-self-hosted-pr", text)
    assert not of("gha-self-hosted-pr", text.replace("pull_request", "push"))


def test_runner_registration_in_a_script() -> None:
    steps = "      - run: ./config.sh --url https://github.com/o/r --token ${{ secrets.T }}\n"
    assert of("gha-self-hosted-pr", workflow("  push:", steps))


@pytest.mark.parametrize(
    ("cond", "hit"),
    [
        ("github.actor == 'dependabot[bot]'", True),
        ("${{ github.triggering_actor == 'renovate[bot]' }}", True),
        ("github.event.pull_request.user.login == 'dependabot[bot]'", True),
        ("github.event.pull_request.user.id == 49699333", False),
        ("github.actor == 'octocat'", False),
    ],
)
def test_bot_conditions(cond: str, hit: bool) -> None:
    text = workflow("  pull_request:", f"      - run: echo\n        if: {cond}\n")
    assert bool(of("gha-bot-conditions", text)) is hit
    job = workflow("  pull_request:", "      - run: echo\n", job=f"    if: {cond}\n")
    assert bool(of("gha-bot-conditions", job)) is hit


def test_permissions_missing_write_all_and_id_token() -> None:
    bare = workflow("  push:", "      - run: echo\n", top="")
    assert [f["key"] for f in of("gha-excessive-permissions", bare)] == [
        "gha-excessive-permissions|workflow|no top-level permissions"
    ]
    assert not of(
        "gha-excessive-permissions", workflow("  push:", "      - run: echo\n", top="", job="    permissions: {}\n")
    )
    assert of("gha-excessive-permissions", workflow("  push:", "      - run: echo\n", top="permissions:\n"))
    assert of("gha-excessive-permissions", workflow("  push:", "      - run: echo\n", top="permissions: write-all\n"))
    assert of(
        "gha-excessive-permissions", workflow("  push:", "      - run: echo\n", job="    permissions: WRITE-ALL\n")
    )
    oidc = "permissions:\n  id-token: write\n"
    assert of("gha-excessive-permissions", workflow("  pull_request:", "      - run: echo\n", top=oidc))
    assert not of("gha-excessive-permissions", workflow("  push:", "      - run: echo\n", top=oidc))
    reusable = workflow("  workflow_call:", "      - run: echo\n", top="")
    assert not of("gha-excessive-permissions", reusable)
    assert not of("gha-excessive-permissions", "runs:\n  using: composite\n  steps: []\n", "action.yml")


def test_permissions_only_from_a_merge_key_do_not_count() -> None:
    text = "on: push\nx: &p\n  permissions: {}\n<<: *p\njobs:\n  a:\n    runs-on: x\n    steps: []\n"
    assert of("gha-excessive-permissions", text)


AGENT = "      - uses: {uses}\n        with:\n          prompt: review\n"


@pytest.mark.parametrize(
    "uses", ["anthropics/claude-code-action@v1", "OpenAI/codex-action@main", "actions/ai-inference@v1"]
)
def test_agent_on_untrusted_text(uses: str) -> None:
    assert of("gha-agent-step-untrusted", workflow("  issue_comment:", AGENT.format(uses=uses)))
    assert not of("gha-agent-step-untrusted", workflow("  push:", AGENT.format(uses=uses)))


def test_agent_gated_on_author_association() -> None:
    step = AGENT.format(uses="anthropics/claude-code-action@v1")
    gate = '    if: contains(fromJSON(\'["OWNER","MEMBER"]\'), github.event.comment.author_association)\n'
    assert not of("gha-agent-step-untrusted", workflow("  issue_comment:", step, job=gate))
    fake = "    if: contains(github.event.comment.body, 'author_association')\n"
    assert of("gha-agent-step-untrusted", workflow("  issue_comment:", step, job=fake))
