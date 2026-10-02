"""ci-github-actions-security, packs supply and hygiene."""

from __future__ import annotations

import pytest
from policies.ghakit import of, workflow

DEPENDABOT = ".github/dependabot.yml"
RELEASE = "  release:\n    types: [published]"


@pytest.mark.parametrize(
    ("step", "hit"),
    [
        ("      - uses: actions/cache@v4\n        with: {path: x, key: k}\n", True),
        ("      - uses: actions/cache/restore@v4\n", True),
        ("      - uses: actions/cache/save@v4\n", False),
        ("      - uses: Swatinem/rust-cache@v2\n", True),
        ("      - uses: actions/setup-go@v5\n", True),
        ("      - uses: actions/setup-go@v5\n        with:\n          cache: false\n", False),
        ("      - uses: actions/setup-node@v4\n        with:\n          cache: npm\n", True),
        ("      - uses: actions/setup-node@v4\n", False),
        ("      - uses: docker/build-push-action@v6\n        with:\n          cache-from: type=gha\n", True),
        ("      - uses: docker/build-push-action@v6\n", False),
    ],
)
def test_cache_in_a_release_workflow(step: str, hit: bool) -> None:
    assert bool(of("gha-cache-poisoning", workflow(RELEASE, step))) is hit
    assert not of("gha-cache-poisoning", workflow("  pull_request:", step))


def test_cache_in_a_tag_push_or_a_publishing_job() -> None:
    cache = "      - uses: actions/cache@v4\n"
    assert of("gha-cache-poisoning", workflow("  push:\n    tags: ['v*']", cache))
    assert of("gha-cache-poisoning", workflow("  push:", cache + "      - run: npm publish\n"))
    assert of(
        "gha-cache-poisoning", workflow("  push:", cache + "      - uses: pypa/gh-action-pypi-publish@release/v1\n")
    )
    assert not of("gha-cache-poisoning", workflow("  push:", cache + "      - run: npm test\n"))


def test_dependabot() -> None:
    text = (
        "version: 2\nregistries:\n  r:\n    type: npm-registry\nupdates:\n"
        "  - package-ecosystem: npm\n    directory: /\n    insecure-external-code-execution: allow\n"
        "    ignore:\n      - dependency-name: '*'\n      - dependency-name: '*'\n        update-types: [version-update:semver-major]\n"
        "  - package-ecosystem: pip\n    directory: /\n    cooldown:\n      default-days: 7\n"
    )
    found = sorted(f["key"] for f in of("gha-dependabot-weaken", text, DEPENDABOT))
    assert found == [
        "gha-dependabot-weaken|npm /|ignore *",
        "gha-dependabot-weaken|updates|insecure-external-code-execution",
    ]
    assert [f["key"] for f in of("gha-dependabot-cooldown", text, DEPENDABOT)] == [
        "gha-dependabot-cooldown|npm /|no cooldown"
    ]
    assert not of("gha-dependabot-cooldown", "version: 2\nupdates: []\n", DEPENDABOT)


@pytest.mark.parametrize(
    ("cond", "hit"),
    [
        ("${{ github.event_name == 'push' }} && true", True),
        ("|\n          ${{ false }}", True),
        ("${{ a }} || ${{ b }}", True),
        ("${{ github.event_name == 'push' }}", False),
        ("github.event_name == 'push'", False),
        ("contains('refs/heads/main refs/heads/dev', github.ref)", True),
        ("${{ contains(fromJSON('[\"a\"]'), github.ref) }}", False),
    ],
)
def test_unsound_condition(cond: str, hit: bool) -> None:
    text = workflow("  push:", f"      - run: echo\n        if: {cond}\n")
    assert bool(of("gha-unsound-condition", text)) is hit


@pytest.mark.parametrize(
    ("step", "hit"),
    [
        ("      - run: semgrep scan\n        continue-on-error: true\n", True),
        ("      - run: semgrep scan\n        continue-on-error: false\n", False),
        ("      - uses: github/codeql-action/analyze@v3\n        if: false\n", True),
        ("      - name: Unit tests\n        run: pytest || true\n", True),
        ("      - run: npm audit || exit 0\n", True),
        ("      - run: test -f x || true\n", False),
        ("      - run: make build || true\n", False),
        ("      - run: echo hi\n        continue-on-error: true\n", False),
        ("      - run: semgrep scan\n        if: always()\n", False),
    ],
)
def test_security_step_weakened(step: str, hit: bool) -> None:
    assert bool(of("gha-security-step-weakened", workflow("  push:", step))) is hit


@pytest.mark.parametrize(
    ("step", "hit"),
    [
        ("      - uses: ${{ matrix.action }}\n", True),
        ("      - uses: ./../other/action\n", True),
        ('      - uses: "actions/checkout @v4"\n', True),
        ("      - uses: ./.github/actions/build\n", False),
        ("      - uses: docker://alpine:3\n", False),
        ("      - uses: actions/checkout@v4\n", False),
        ("      - run: dir\n        shell: CMD\n", True),
        ("      - run: echo ${{ 'literal' }}\n", True),
    ],
)
def test_obfuscation(step: str, hit: bool) -> None:
    assert bool(of("gha-obfuscation", workflow("  push:", step))) is hit


def test_auto_merge_without_update_type() -> None:
    merge = '      - run: gh pr merge --auto --squash "$PR"\n'
    assert of("gha-auto-merge-bot", workflow("  pull_request_target:", merge))
    approve = "      - uses: hmarr/auto-approve-action@v4\n"
    assert of("gha-auto-merge-bot", workflow("  pull_request_target:", approve))
    checked = (
        "      - id: m\n        uses: dependabot/fetch-metadata@v2\n"
        "      - if: steps.m.outputs.update-type == 'version-update:semver-patch'\n"
        '        run: gh pr merge --auto --squash "$PR"\n'
    )
    assert not of("gha-auto-merge-bot", workflow("  pull_request_target:", checked))
    assert not of("gha-auto-merge-bot", workflow("  push:", "      - run: gh pr merge 1\n"))
