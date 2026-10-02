"""ci-github-actions-security: regressions from the adversarial review, one per finding."""

from __future__ import annotations

import time

import pytest
from policies.ghakit import found, gate, of, workflow

ISSUES = "  issues:"
PRT = "  pull_request_target:"


def test_a_comparison_inside_an_argument_does_not_hide_injection() -> None:
    run = "      - run: echo ${{ format('{0}{1}', github.event.issue.title, 1 == 1) }}\n"
    assert of("gha-template-injection", workflow(ISSUES, run))


def test_an_unreadable_file_is_always_new_in_the_change_run() -> None:
    text = "? permissions\n: {}\non: pull_request_target\n"
    change = gate.findings({"event": "tool_use", "writes": {".github/workflows/a.yml": text}}, gate.load_tables())
    assert change[0]["new"] is True
    base = {"event": "tool_use", "baseline": True, "writes": {".github/workflows/a.yml": text}}
    assert "new" not in gate.findings(base, gate.load_tables())[0]


def test_waiver_on_one_copy_does_not_silence_another() -> None:
    run = (
        "      - run: |\n          echo ${{ github.event.issue.title }}  # chock: allow gha-template-injection\n"
        "          echo ${{ github.event.issue.title }}\n"
    )
    hits = of("gha-template-injection", workflow(ISSUES, run))
    assert [h["line"] for h in hits] == [9, 10]
    assert len(found(workflow(ISSUES, run), event="commit")) == 1
    same_line = "      - run: echo ${{ github.event.issue.title }} ${{ github.event.issue.title }}\n"
    assert [h["line"] for h in of("gha-template-injection", workflow(ISSUES, same_line))] == [8, 8]


@pytest.mark.parametrize(
    "password",
    ["hunter2${{ env.NOTHING }}", "${{ 'hunter2' }}", "hunter2"],
)
def test_container_password_with_its_own_text(password: str) -> None:
    job = f"    container:\n      image: i\n      credentials:\n        password: {password}\n"
    assert of("gha-container-credentials", workflow("  push:", "      - run: echo\n", job=job))


def test_git_options_before_the_subcommand() -> None:
    run = "      - run: git -c advice.detachedHead=false checkout ${{ github.event.pull_request.head.sha }}\n"
    assert of("gha-prt-head-checkout", workflow(PRT, run))
    run = "      - run: git --no-pager fetch origin ${{ github.event.pull_request.head.ref }}\n"
    assert of("gha-prt-head-checkout", workflow(PRT, run))


def test_self_hosted_through_the_matrix() -> None:
    job = "    strategy:\n      matrix:\n        r: [self-hosted, ubuntu-latest]\n"
    text = workflow("  pull_request:", "      - run: echo\n", job=job).replace(
        "ubuntu-latest\n    strategy", "x\n    strategy"
    )
    text = text.replace("runs-on: x", "runs-on: ${{ matrix.r }}")
    assert of("gha-self-hosted-pr", text)


@pytest.mark.parametrize(
    "cond",
    [
        "contains(github.event.comment.body, '@bot') && github.event.comment.author_association",
        "github.event.comment.author_association != 'NONE'",
        "github.event.comment.author_association == 'OWNER' || true",
    ],
)
def test_association_conditions_that_do_not_restrict(cond: str) -> None:
    step = "      - uses: anthropics/claude-code-action@v1\n"
    assert of("gha-agent-step-untrusted", workflow("  issue_comment:", step, job=f"    if: {cond}\n"))


@pytest.mark.parametrize("value", ["~", "null", "Null"])
def test_null_permissions_are_unset(value: str) -> None:
    assert of("gha-excessive-permissions", workflow("  push:", "      - run: echo\n", top=f"permissions: {value}\n"))


def test_typed_inputs_carry_no_text() -> None:
    on = "  workflow_dispatch:\n    inputs:\n      dry:\n        type: boolean\n      n:\n        type: number\n      name:\n        type: string"
    run = "      - run: ./x --dry=${{ inputs.dry }} -n ${{ github.event.inputs.n }} ${{ inputs.name }}\n"
    hits = of("gha-template-injection", workflow(on, run))
    assert [h["key"].split("|")[2] for h in hits] == ["inputs.name"]
    call = (
        on.replace("workflow_dispatch", "workflow_call")
        + "\n  workflow_dispatch:\n    inputs:\n      dry:\n        type: string"
    )
    assert len(of("gha-template-injection", workflow(call, run))) == 2


def test_dependabot_double_star_and_publishers() -> None:
    text = "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown: {default-days: 3}\n    ignore:\n      - dependency-name: '**'\n"
    assert of("gha-dependabot-weaken", text, ".github/dependabot.yml")
    cache = "      - uses: actions/cache@v4\n"
    assert of("gha-cache-poisoning", workflow("  push:", cache + "      - run: npx semantic-release\n"))
    assert of("gha-cache-poisoning", workflow("  push:", cache + "      - uses: changesets/action@v1\n"))


def test_many_steps_stay_fast() -> None:
    steps = "".join(f"      - run: echo {i}\n" for i in range(4000))
    text = workflow("  push:", steps, job="    strategy:\n      matrix:\n        os: [a]\n")
    started = time.monotonic()
    assert found(text) == []
    assert time.monotonic() - started < 10


AGENT_STEP = "      - uses: anthropics/claude-code-action@v1\n"


@pytest.mark.parametrize(
    "cond",
    [
        "github.event.issue.author_association == 'OWNER'",
        "contains(github.event.comment.body, 'MEMBER') && github.event.comment.author_association",
        '${{ !contains(fromJSON(\'["OWNER","MEMBER"]\'), github.event.comment.author_association) }}',
        "(github.event.comment.author_association == 'OWNER') == false",
        "startsWith(github.event.comment.author_association, 'C') && 'COLLABORATOR'",
        'contains(fromJSON(\'["OWNER","NONE"]\'), github.event.comment.author_association)',
        "contains(fromJSON('[]'), github.event.comment.author_association)",
    ],
)
def test_round2_association_gates_that_do_not_restrict(cond: str) -> None:
    assert of("gha-agent-step-untrusted", workflow("  issue_comment:", AGENT_STEP, job=f"    if: {cond}\n"))


@pytest.mark.parametrize(
    ("on", "cond"),
    [
        ("  issue_comment:", "github.event.comment.author_association == 'MEMBER'"),
        (
            "  issue_comment:",
            '${{ contains(fromJSON(\'["OWNER", "MEMBER"]\'), github.event.comment.author_association) }}',
        ),
        (
            "  issues:\n  issue_comment:",
            "github.event.issue.author_association == 'OWNER' && github.event.comment.author_association == 'OWNER'",
        ),
    ],
)
def test_round2_association_gates_that_restrict(on: str, cond: str) -> None:
    assert not of("gha-agent-step-untrusted", workflow(on, AGENT_STEP, job=f"    if: {cond}\n"))


@pytest.mark.parametrize(
    ("password", "hit"),
    [
        ("${{ github.run_id && 'hunter2' }}", True),
        ("${{ format('hunter{0}', github.run_attempt) }}", True),
        ("${{ secrets.P || 'hunter2' }}", True),
        ("${{ env.PW }}", True),
        ("${{ secrets.REGISTRY_PASSWORD }}", False),
        ("${{ vars.P }}", False),
    ],
)
def test_round2_container_password_must_be_one_stored_reference(password: str, hit: bool) -> None:
    job = f'    container:\n      image: i\n      credentials:\n        password: "{password}"\n'
    assert bool(of("gha-container-credentials", workflow("  push:", "      - run: echo\n", job=job))) is hit


def _matrix_job(matrix: str, runs_on: str) -> str:
    text = workflow("  pull_request:", "      - run: echo\n", job=f"    strategy:\n      matrix:\n{matrix}")
    return text.replace("runs-on: ubuntu-latest", f"runs-on: {runs_on}")


def test_round2_matrix_runs_on_reads_only_the_named_key() -> None:
    other = "        os: [ubuntu-latest]\n        note: ['no self-hosted here']\n"
    assert not of("gha-self-hosted-pr", _matrix_job(other, "${{ matrix.os }}"))
    row = "        include:\n          - os: self-hosted\n"
    assert of("gha-self-hosted-pr", _matrix_job(row, "${{ matrix.os }}"))
    computed = "        os: [ubuntu-latest]\n        include: ${{ fromJSON(vars.ROWS) }}\n"
    assert not of("gha-self-hosted-pr", _matrix_job(computed, "${{ matrix.os }}"))
    dynamic = "        os: [self-hosted]\n"
    assert of("gha-self-hosted-pr", _matrix_job(dynamic, "${{ matrix[vars.K] }}"))
    assert not of("gha-self-hosted-pr", _matrix_job(other, "ubuntu-latest"))


def test_round2_waivers_count_only_their_own_occurrence() -> None:
    secret = (
        "      - run: |\n          echo ${{ secrets.A }}  # chock: allow gha-secret-echo\n"
        "          curl -u ${{ secrets.A }} x\n"
    )
    assert len(found(workflow("  push:", secret), event="commit")) == 1
    comment = (
        "      - run: |\n          # github.event.issue.title  chock: allow gha-template-injection\n"
        "          echo ${{ github.event.issue.title }}\n"
    )
    assert [h["line"] for h in found(workflow(ISSUES, comment), event="commit")] == [10]
    escaped = (
        '      - run: "echo ${{ \\x67ithub.event.issue.title }}"\n'
        "        name: github.event.issue.title  # chock: allow gha-template-injection\n"
    )
    assert [h["line"] for h in found(workflow(ISSUES, escaped), event="commit")] == [8]
    env_file = (
        "      - run: |\n          echo A >> $GITHUB_ENV  # chock: allow gha-github-env-injection\n"
        "          echo A >> $GITHUB_ENV\n"
    )
    assert len(found(workflow(PRT, env_file), event="commit")) == 2
