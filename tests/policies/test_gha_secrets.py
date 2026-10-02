"""ci-github-actions-security, pack secrets."""

from __future__ import annotations

import pytest
from policies.ghakit import of, workflow

PUSH = "  push:"


def test_secrets_inherit_to_another_repository() -> None:
    call = "on: push\npermissions: {}\njobs:\n  a:\n    uses: U\n    secrets: inherit\n"
    assert of("gha-secrets-inherit", call.replace("U", "other/repo/.github/workflows/x.yml@v1"))
    assert not of("gha-secrets-inherit", call.replace("U", "./.github/workflows/x.yml"))
    named = call.replace("U", "other/repo/.github/workflows/x.yml@v1").replace("inherit", "\n      T: ${{ secrets.T }}")
    assert not of("gha-secrets-inherit", named)


@pytest.mark.parametrize(
    ("text", "hits"),
    [
        ("${{ toJSON(secrets) }}", 1),
        ("${{ secrets[format('{0}', inputs.n)] }}", 1),
        ("${{ secrets['TOKEN'] }}", 0),
        ("${{ secrets.TOKEN }}", 0),
    ],
)
def test_overprovisioned_secrets(text: str, hits: int) -> None:
    steps = f"      - run: echo\n        env:\n          ALL: {text}\n"
    assert len(of("gha-overprovisioned-secrets", workflow(PUSH, steps))) == hits


def test_secret_inline_in_run_and_debug_switches() -> None:
    steps = (
        "      - run: curl -u ${{ secrets.API_KEY }} https://e.invalid\n      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"
    )
    assert [f["key"] for f in of("gha-secret-echo", workflow(PUSH, steps))] == ["gha-secret-echo|build|secrets.api_key"]
    via_env = '      - run: curl -u "$K" https://e.invalid\n        env:\n          K: ${{ secrets.API_KEY }}\n'
    assert not of("gha-secret-echo", workflow(PUSH, via_env))
    debug = workflow(PUSH, "      - run: echo\n").replace(
        "jobs:", "env:\n  ACTIONS_STEP_DEBUG: true\n  ACTIONS_RUNNER_DEBUG: false\njobs:"
    )
    assert len(of("gha-secret-echo", debug)) == 1


@pytest.mark.parametrize(
    ("persist", "path", "hit"),
    [
        ("", ".", True),
        ("", "./**", True),
        ("", "${{ github.workspace }}", True),
        ("", "dist/", False),
        ("        with:\n          persist-credentials: false\n", ".", False),
        ("        with:\n          persist-credentials: ${{ false }}\n", ".", False),
        ("        with:\n          persist-credentials: true\n", ".", True),
    ],
)
def test_artipacked(persist: str, path: str, hit: bool) -> None:
    steps = f"      - uses: actions/checkout@v4\n{persist}      - uses: actions/upload-artifact@v4\n        with:\n          path: {path}\n"
    assert bool(of("gha-artipacked", workflow(PUSH, steps))) is hit


def test_artipacked_reads_a_multi_line_path_list_and_ignores_merged_settings() -> None:
    steps = (
        "      - uses: actions/checkout@v4\n      - uses: actions/upload-artifact@v4\n        with:\n"
        "          path: |\n            dist\n            .git\n"
    )
    assert of("gha-artipacked", workflow(PUSH, steps))
    merged = (
        "      - <<: {with: {persist-credentials: false}}\n        uses: actions/checkout@v4\n"
        "      - uses: actions/upload-artifact@v4\n        with: {path: .}\n"
    )
    assert of("gha-artipacked", workflow(PUSH, merged))
    duplicate = (
        "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n          persist-credentials: true\n"
        "      - uses: actions/upload-artifact@v4\n        with: {path: .}\n"
    )
    assert of("gha-artipacked", workflow(PUSH, duplicate))


def test_checkout_token_pat() -> None:
    step = "      - uses: actions/checkout@v4\n        with:\n          token: ${{{{ secrets.{name} }}}}\n{more}"
    assert of("gha-checkout-token-pat", workflow(PUSH, step.format(name="BOT_PAT", more="")))
    assert not of("gha-checkout-token-pat", workflow(PUSH, step.format(name="GITHUB_TOKEN", more="")))
    off = "          persist-credentials: false\n"
    assert not of("gha-checkout-token-pat", workflow(PUSH, step.format(name="BOT_PAT", more=off)))


def test_container_credentials() -> None:
    job = (
        "    container:\n      image: ghcr.io/o/i\n      credentials:\n        username: u\n        password: hunter22\n"
        "    services:\n      db:\n        image: postgres\n        credentials:\n          password: ${{ secrets.DB }}\n"
    )
    hits = of("gha-container-credentials", workflow(PUSH, "      - run: echo\n", job=job))
    assert [h["key"] for h in hits] == ["gha-container-credentials|build|container"]
    assert "hunter22" not in hits[0]["message"]


@pytest.mark.parametrize(
    ("step", "hit"),
    [
        (
            "      - uses: pypa/gh-action-pypi-publish@release/v1\n        with:\n          password: ${{ secrets.PYPI }}\n",
            True,
        ),
        ("      - uses: pypa/gh-action-pypi-publish@release/v1\n", False),
        ("      - run: twine upload dist/*\n        env:\n          TWINE_PASSWORD: ${{ secrets.PYPI }}\n", True),
        ("      - run: twine upload -p x dist/*\n", True),
        ("      - run: twine upload dist/*\n", False),
        ("      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM }}\n", True),
        ("      - run: npm publish --provenance\n", False),
        ("      - run: cargo publish --token x\n", True),
        ("      - run: gem push x.gem\n        env:\n          GEM_HOST_API_KEY: ${{ secrets.G }}\n", True),
    ],
)
def test_trusted_publishing(step: str, hit: bool) -> None:
    assert bool(of("gha-trusted-publishing", workflow(PUSH, step))) is hit


def test_trusted_publishing_in_a_composite_action() -> None:
    action = (
        "runs:\n  using: composite\n  steps:\n    - run: npm publish\n      env:\n        NPM_TOKEN: ${{ inputs.t }}\n"
    )
    assert not of("gha-trusted-publishing", action, "action.yml")
    action = action.replace("${{ inputs.t }}", "${{ secrets.NPM }}")
    assert of("gha-trusted-publishing", action, "action.yml")


@pytest.mark.parametrize(
    ("step", "hit"),
    [
        (
            "      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          aws-access-key-id: ${{ secrets.K }}\n",
            True,
        ),
        (
            "      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::1:role/r\n",
            False,
        ),
        (
            "      - uses: google-github-actions/auth@v2\n        with:\n          credentials_json: ${{ secrets.SA }}\n",
            True,
        ),
        ("      - uses: Azure/login@v2\n        with:\n          creds: ${{ secrets.AZ }}\n", True),
        ("      - run: aws s3 ls\n        env:\n          AWS_SECRET_ACCESS_KEY: ${{ secrets.S }}\n", True),
    ],
)
def test_static_cloud_keys(step: str, hit: bool) -> None:
    assert bool(of("gha-static-cloud-keys", workflow(PUSH, step))) is hit
