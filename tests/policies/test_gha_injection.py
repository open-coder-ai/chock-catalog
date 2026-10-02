"""ci-github-actions-security, pack injection: template injection, GITHUB_ENV writes, insecure commands."""

from __future__ import annotations

import pytest
from policies.ghakit import of, rule_ids, workflow

TI = "gha-template-injection"
ISSUE = "  issues:\n    types: [opened]"


def run_step(run: str) -> str:
    return workflow(ISSUE, f"      - run: {run}\n")


@pytest.mark.parametrize(
    "run",
    [
        'echo "${{ github.event.issue.title }}"',
        "echo ${{ github.event['issue']['body'] }}",
        "echo ${{ GITHUB.EVENT.ISSUE.TITLE }}",
        "echo ${{ github.head_ref }}",
        "echo ${{ inputs.name }}",
        "echo ${{ github.event.inputs.name }}",
        "echo ${{ toJSON(github.event) }}",
        "echo ${{ format('{0}', github.event.comment.body) }}",
        "echo ${{ github.event.commits[0].message }}",
        "echo ${{ github.event.pull_request.head.ref || 'main' }}",
        "echo ${{ github[format('{0}', 'event')] }}",
        "'echo ${{ github.event.issue.title }}'",
        '"echo ${{ github.event.issue.title }}"',
    ],
)
def test_untrusted_text_in_run_is_reported(run: str) -> None:
    assert of(TI, run_step(run))


@pytest.mark.parametrize(
    "run",
    [
        'echo "$TITLE"',
        "echo ${{ github.sha }} ${{ github.event.issue.number }}",
        "echo ${{ contains(github.event.issue.body, 'x') }}",
        "echo ${{ steps.meta.outputs.version }}",
        "echo ${{ matrix.os }} ${{ env.PLAIN }}",
    ],
)
def test_trusted_or_boolean_contexts_are_not(run: str) -> None:
    assert not of(TI, run_step(run))


def test_block_scalar_run_reports_the_line_holding_the_expression() -> None:
    text = workflow(ISSUE, "      - run: |\n          echo start\n          echo ${{ github.event.issue.body }}\n")
    hit = of(TI, text)
    assert [h["line"] for h in hit] == [11]
    assert hit[0]["key"] == "gha-template-injection|build|github.event.issue.body"


def test_flow_style_steps_and_folded_scalars_are_read() -> None:
    text = workflow(ISSUE, '      - {name: x, run: "echo ${{ github.event.issue.title }}"}\n')
    assert of(TI, text)
    folded = workflow(ISSUE, "      - run: >\n          echo\n          ${{ github.event.issue.title }}\n")
    assert of(TI, folded)


def test_env_set_from_untrusted_text_taints_env_context() -> None:
    steps = "      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo ${{ env.T }}\n"
    assert of(TI, workflow(ISSUE, steps))
    job = "    env:\n      T: ${{ github.event.issue.title }}\n"
    assert of(TI, workflow(ISSUE, "      - run: echo ${{ env.t }}\n", job=job))
    safe = '      - env:\n          T: ${{ github.sha }}\n        run: echo ${{ env.T }} "$T"\n'
    assert not of(TI, workflow(ISSUE, safe))


def test_github_script_script_is_a_sink() -> None:
    steps = "      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.title }}')\n"
    assert of(TI, workflow(ISSUE, steps))
    other = "      - uses: some/action@v1\n        with:\n          script: ${{ github.event.issue.title }}\n"
    assert not of(TI, workflow(ISSUE, other))


def test_composite_action_inputs_in_run() -> None:
    action = "runs:\n  using: composite\n  steps:\n    - run: echo ${{ inputs.ref }}\n      shell: bash\n"
    assert of(TI, action, "tools/act/action.yml")
    env = (
        "runs:\n  using: composite\n  steps:\n    - env:\n        R: ${{ inputs.ref }}\n      run: echo ${{ env.R }}\n"
    )
    assert len(of(TI, env, "action.yaml")) == 1


def test_anchor_alias_copies_the_run_into_another_job() -> None:
    text = (
        "on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - &s\n        run: echo hi\n"
        "  b:\n    runs-on: x\n    steps:\n      - *s\n      - &bad {run: 'echo ${{ github.event.issue.body }}'}\n"
        "  c:\n    runs-on: x\n    steps: [*bad]\n"
    )
    assert sorted(h["key"].split("|")[1] for h in of(TI, text)) == ["b", "c"]


def test_merge_key_value_is_judged() -> None:
    text = (
        "on: issues\npermissions: {}\nx-base: &base\n  run: echo ${{ github.event.issue.title }}\n"
        "jobs:\n  a:\n    runs-on: x\n    steps:\n      - <<: *base\n        name: n\n"
    )
    assert of(TI, text)


def test_github_env_write_under_risky_trigger() -> None:
    steps = '      - run: echo "X=$(cat x)" >> "$GITHUB_ENV"\n      - run: echo /tmp >> $env:GITHUB_PATH\n'
    hits = of("gha-github-env-injection", workflow("  pull_request_target:", steps))
    assert len(hits) == 2
    assert not of("gha-github-env-injection", workflow("  pull_request:", steps))
    assert not of("gha-github-env-injection", workflow("  push:", "      - run: echo hi\n"))


def test_insecure_commands_env_and_old_commands() -> None:
    text = workflow("  push:", "      - run: echo '::set-env name=A::b'\n      - run: echo ok\n")
    text = text.replace("jobs:", "env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\njobs:")
    assert rule_ids(text).count("gha-insecure-commands") == 2
    off = workflow(
        "  push:", "      - run: echo ok\n        env:\n          actions_allow_unsecure_commands: 'false'\n"
    )
    assert not of("gha-insecure-commands", off)
    expr = workflow(
        "  push:", "      - run: echo ok\n        env:\n          ACTIONS_ALLOW_UNSECURE_COMMANDS: ${{ 'true' }}\n"
    )
    assert of("gha-insecure-commands", expr)


def test_env_chains_and_matrix_entries_are_followed() -> None:
    chain = "    env:\n      A: ${{ github.event.issue.title }}\n      B: x-${{ env.A }}\n"
    assert of(TI, workflow(ISSUE, "      - run: echo ${{ env.B }}\n", job=chain))
    matrix = "    strategy:\n      matrix:\n        os: [linux]\n        title: ['${{ github.event.issue.title }}']\n"
    assert of(TI, workflow(ISSUE, "      - run: echo ${{ matrix.title }}\n", job=matrix))
    assert not of(TI, workflow(ISSUE, "      - run: echo ${{ matrix.os }}\n", job=matrix))
    row = "    strategy:\n      matrix:\n        include:\n          - t: ${{ github.event.issue.body }}\n"
    assert of(TI, workflow(ISSUE, "      - run: echo ${{ matrix.t }}\n", job=row))
    whole = "    strategy:\n      matrix: ${{ fromJSON(github.event.issue.body) }}\n"
    assert of(TI, workflow(ISSUE, "      - run: echo ${{ matrix.any }}\n", job=whole))
