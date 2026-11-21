"""Every catalog eval suite, installed as `chock add` installs it, passes scan-secrets-entropy when armed.

`chock add` copies a policy folder verbatim into the adopter's policy folder, so an adopter's first
commit holds each installed suite.yaml. A suite line that trips this gate refuses that commit, so the
build fails here first. Two replays per policy: the installed file as a commit adds it, and the
fixtures of each case the policy's suite says is allowed, written out as the eval harness writes them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import select_tests
import yaml
from policies import entropykit as kit
from trees import ROOT, policy_dirs

gate = kit.load()
SUITED = [d for d in policy_dirs() if (d / "evals" / "suite.yaml").is_file()]
INSTALLED = ".agents/policies"


def refused(writes: dict[str, str]) -> list[str]:
    """The gate's findings for a commit that adds these files, as `path:line: message`."""
    rows = gate.findings({"event": "commit", "writes": writes})
    return [f"{r['path']}:{r['line']}: {r['message']}" for r in rows]


def test_every_catalog_suite_is_replayed() -> None:
    assert len(SUITED) >= 70


@pytest.mark.parametrize("policy_dir", SUITED, ids=[d.name for d in SUITED])
def test_the_installed_suite_is_not_refused(policy_dir: Path) -> None:
    path = f"{INSTALLED}/{policy_dir.name}/evals/suite.yaml"
    text = (policy_dir / "evals" / "suite.yaml").read_text(encoding="utf-8")
    assert refused({path: text}) == []


@pytest.mark.parametrize("policy_dir", SUITED, ids=[d.name for d in SUITED])
def test_no_allow_case_is_refused(policy_dir: Path) -> None:
    cases = yaml.safe_load((policy_dir / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]["cases"]
    allowed = [c for c in cases if (c.get("execute") or {}).get("files") and c["execute"].get("expect") == "allow"]
    assert [c["id"] for c in allowed if refused(c["execute"]["files"])] == []


def test_a_secret_in_an_installed_suite_is_still_asked_about() -> None:
    """The installed path is no exemption: a real value written into a suite is judged like any other."""
    path = f"{INSTALLED}/scan-secrets/evals/suite.yaml"
    quoted = f'      files:\n        app.env: "client_secret={kit.secret(41)}\\n"\n'
    assert len(refused({path: quoted})) == 1
    block = f"        app.env: |\n          client_secret={kit.secret(42)}\n"
    assert len(refused({path: block})) == 1


@pytest.mark.parametrize(
    "text",
    [
        'x: "def sign(private_key: Ed25519PrivateKey, password_min_length: int = 12):\\n    pass"',
        'x: "async def sign(self, signing_key: Optional[ed25519.Ed25519PrivateKey] = None):"',
        'x: "fn sign(access_token: &str, secret_key: HmacSha256Key)"',
        "password = models.CharField(max_length=128)",
        'password = factory.PostGenerationMethodCall("set_password", "pw")',
    ],
)
def test_a_type_annotation_and_a_call_read_through_yaml_are_code(text: str) -> None:
    assert refused({"suite.yaml": text + "\n"}) == []


@pytest.mark.parametrize(
    "text",
    [
        'x: "connect(private_key: {V})"',
        'x: "def sign(private_key: {V}):"',
        'x: "class Key:\\n  private_key: {V}"',
        'x: "def f(a) -> int:"\nprivate_key: {V}',
    ],
)
def test_a_secret_beside_those_shapes_is_still_asked_about(text: str) -> None:
    value = kit.secret(43)
    assert len(refused({"suite.yaml": text.replace("{V}", value) + "\n"})) == 1


@pytest.mark.parametrize("path", ["conf.yaml", ".env", "note.md"])
@pytest.mark.parametrize(
    "template",
    [
        'client = connect(password="{V}")',
        "token = make(api_key={V})",
        "password = f(x={V})",
        'cmd: "client = connect(password={V})"',
    ],
)
def test_a_secret_in_a_keyword_argument_is_still_asked_about(path: str, template: str) -> None:
    assert refused({path: template.replace("{V}", kit.secret(44)) + "\n"})


@pytest.mark.parametrize(
    "text", ["f(x=)", "models.CharField(max_length=128, null=True)", "make(api_key=settings.api_key)", "f(a=b.c, d=2)"]
)
def test_keyword_arguments_that_read_as_code_are_code(text: str) -> None:
    assert refused({"suite.yaml": f"password = {text}\n"}) == []


def test_a_change_to_one_policys_suite_runs_the_replay_in_every_job_it_selects() -> None:
    """Selection data: the replay walks every policy, so a PR touching only another policy's suite runs it."""
    jobs = select_tests.matrix(ROOT, ["base/block-no-verify/evals/suite.yaml"])
    assert jobs
    assert "block-no-verify" in {j["id"] for j in jobs}
    assert all("tests/policies/test_scan_secrets_entropy_replay.py" in j["tests"] for j in jobs)


def test_known_miss_a_secret_shaped_like_a_type_name_in_a_signature_is_not_reported() -> None:
    """Stated in the manifest: CamelCase words with at most two digit runs, after `name:` in a signature."""
    shaped = "Xkqmlprtvnbswdhj" + "Ab" + "Cd"
    assert refused({"suite.yaml": f'x: "def sign(private_key: {shaped}):"\n'}) == []
    assert refused({"suite.yaml": 'x: "def sign(private_key: Xk9Qm2Lp7Rt4Vn8Bs3Wd6Hj5):"\n'})


def test_known_miss_a_secret_after_another_argument_is_not_reported() -> None:
    """Stated in the manifest, and the same before the keyword-argument change."""
    assert refused({"conf.yaml": f"password = f(a=1, b={kit.secret(44)})\n"}) == []
