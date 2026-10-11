"""ask-credential-switching: the person-only allowlist, its closed schema and the guard's exit protocol.

The eval suite holds the ask and allow verdicts for each shape; it replays in a repository with no HEAD, so the
allowlist, which is read from HEAD only, is proven here against real commits.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from policies import guardkit
from policies.scriptkit import git
from trees import ROOT

POLICY = "ask-credential-switching"
IMPL = ROOT / "base" / POLICY / "implementations"
GUARD = guardkit.load_guard(POLICY)
sidecar = guardkit.load_guard(POLICY, "credential_allowlist")
ASK, ERR, OK = 3, 2, 0
LISTED = {
    "aws": ["dev", "arn:aws:iam::111122223333:role/readonly", "AKIADEVEXAMPLE00"],
    "gcloud": ["dev@example.com", "dev-config", "ci@proj.iam.gserviceaccount.com"],
    "azure": ["dev-subscription", "http://dev-app"],
    "kubernetes": ["kind-dev", "dev-user"],
}


def repo_with(tmp_path: Path, text: str | None) -> Path:
    """A repository whose HEAD holds `text` as the sidecar (none when None)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "T")
    git(repo, "config", "commit.gpgsign", "false")
    (repo / "README").write_text("x\n")
    if text is not None:
        (repo / ".chock").mkdir()
        (repo / sidecar.PATH).write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    return repo


@pytest.fixture
def listed(tmp_path: Path) -> Path:
    return repo_with(tmp_path, json.dumps(LISTED))


def verdict(command: str, root: Path) -> int:
    return ASK if GUARD.check(command, root) else OK


@pytest.mark.parametrize(
    "command",
    [
        "aws s3 ls --profile dev",
        "export AWS_PROFILE=dev",
        "AWS_DEFAULT_PROFILE=dev terraform plan",
        "aws sts assume-role --role-arn arn:aws:iam::111122223333:role/readonly --role-session-name s",
        "aws configure set aws_access_key_id AKIADEVEXAMPLE00 --profile dev",
        "export AWS_ACCESS_KEY_ID=AKIADEVEXAMPLE00 AWS_SECRET_ACCESS_KEY=x",
        "gcloud config set account dev@example.com",
        "gcloud config configurations activate dev-config",
        "gcloud auth activate-service-account ci@proj.iam.gserviceaccount.com --key-file k.json",
        "gcloud auth login dev@example.com",
        "az account set --subscription dev-subscription",
        "az login --service-principal --username=http://dev-app -p x --tenant t",
        "kubectl config use-context kind-dev",
        "kubectl config set-credentials dev-user --token=x",
        "P=dev; aws s3 ls --profile $P",
    ],
)
def test_a_switch_to_a_listed_identity_passes_silently(command: str, listed: Path) -> None:
    assert verdict(command, listed) == OK


@pytest.mark.parametrize(
    "command",
    [
        "aws s3 ls --profile prod",
        "aws sts assume-role --role-arn arn:aws:iam::111122223333:role/admin --role-session-name s",
        "gcloud config set account dev@example.com.evil",
        "kubectl config use-context kind-dev-2",
        "aws s3 ls --profile dev && kubectl config use-context prod",
        "gcloud auth login",
        "az login --identity",
        "echo x >> ~/.aws/credentials",
        "aws s3 ls --profile $UNSET",
    ],
)
def test_anything_else_still_asks_with_the_list_in_place(command: str, listed: Path) -> None:
    assert verdict(command, listed) == ASK


def test_a_name_listed_for_one_provider_does_not_pass_another(tmp_path: Path) -> None:
    root = repo_with(tmp_path, json.dumps({"kubernetes": ["prod"]}))
    assert verdict("kubectl config use-context prod", root) == OK
    assert verdict("aws s3 ls --profile prod", root) == ASK


def test_the_prompt_names_only_what_is_not_listed(listed: Path) -> None:
    prompt = GUARD.check("aws s3 ls --profile dev; kubectl config use-context prod", listed)
    assert "Kubernetes context prod" in prompt
    assert "profile dev" not in prompt
    assert "ask the person" in prompt.lower()


def test_an_uncommitted_list_never_counts(tmp_path: Path) -> None:
    """The agent cannot approve its own switch: only the list in HEAD is read."""
    root = repo_with(tmp_path, None)
    (root / ".chock").mkdir()
    (root / sidecar.PATH).write_text(json.dumps({"aws": ["prod"]}))
    assert verdict("aws s3 ls --profile prod", root) == ASK
    git(root, "add", "-A")
    assert verdict("aws s3 ls --profile prod", root) == ASK
    git(root, "commit", "-qm", "person approves prod")
    assert verdict("aws s3 ls --profile prod", root) == OK


def test_outside_a_repository_every_switch_asks(tmp_path: Path) -> None:
    assert verdict("aws s3 ls --profile dev", tmp_path) == ASK


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ('{"aws": ["prod"], "mode": "all"}', "only the keys"),
        ('{"aws": "prod"}', "not a list of names"),
        ('{"aws": ["prod", 1]}', "not a list of names"),
        ('{"aws": ["prod", " "]}', "not a list of names"),
        ('{"aws": ["dev"], "aws": ["prod"]}', "repeated key"),
        ('["prod"]', "only the keys"),
        ("{aws: [prod]}", "not honoured"),
    ],
)
def test_a_list_outside_the_closed_schema_is_not_honoured(tmp_path: Path, text: str, why: str) -> None:
    root = repo_with(tmp_path, text)
    prompt = GUARD.check("aws s3 ls --profile prod", root)
    assert prompt
    assert "not honoured" in prompt
    assert why in prompt


def test_an_empty_list_is_valid(tmp_path: Path) -> None:
    assert sidecar.parse("{}") == {}
    root = repo_with(tmp_path, '{"aws": []}')
    prompt = GUARD.check("aws s3 ls --profile prod", root)
    assert prompt
    assert "not honoured" not in prompt


def test_git_that_cannot_run_reads_as_no_list(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(sidecar.subprocess, "run", broken)
    assert sidecar.committed(tmp_path) is None


def test_more_than_three_switches_are_counted_not_listed(tmp_path: Path) -> None:
    line = "; ".join(f"kubectl config use-context c{i}" for i in range(5))
    prompt = GUARD.check(line, tmp_path)
    assert "c2" in prompt
    assert "c3" not in prompt
    assert "and 2 more" in prompt


def test_the_same_switch_is_named_once(tmp_path: Path) -> None:
    prompt = GUARD.check("export AWS_PROFILE=prod; aws s3 ls; aws ec2 describe-instances", tmp_path)
    assert prompt.count("AWS profile prod") == 1


@pytest.mark.parametrize(
    ("command", "named"),
    [
        ("aws configure set default.aws_session_token t", "AWS profile default"),
        ("aws configure set aws_access_key_id AKIA", "AWS profile default"),
        ("AWS_PROFILE=prod aws configure set aws_access_key_id AKIA --profile ops", "AWS profile ops"),
        ("export AWS_PROFILE=", "AWS profile default"),
        ("export AWS_SESSION_TOKEN=t", "access key (not named)"),
        ("aws sts assume-role --role-session-name s", "role (not named)"),
        ("gcloud config set account", "account (not named)"),
        ("gcloud config configurations activate", "configuration (not named)"),
        ("gcloud auth activate-service-account --key-file=k.json", "named in its key file"),
        ("gcloud auth application-default login", "chosen at login"),
        ("az account set", "subscription (not named)"),
        ("az login --identity --client-id 0000", "managed identity 0000"),
        ("kubectl config use-context", "context (not named)"),
        ("kubectl config set-credentials", "user (not named)"),
        ("cp creds C:\\Users\\dev\\.aws\\credentials", "credential store"),
        ("tee -a /Users/dev/.config/gcloud/configurations/config_prod", "credential store"),
    ],
)
def test_the_prompt_names_the_identity_or_says_it_is_not_named(command: str, named: str, tmp_path: Path) -> None:
    prompt = GUARD.check(command, tmp_path)
    assert prompt
    assert named in prompt


@pytest.mark.parametrize(
    "command",
    [
        "aws configure set region eu-west-1",
        "aws configure set",
        "AWS_PROFILE=prod aws configure list",
        "gcloud config set project p",
        "gcloud config get-value account",
        "az login",
        "kubectl config view",
        "kubectl --context prod get pods",
        "cat ~/.aws/credentials",
        "echo x > ~/.aws/credentials.bak",
        "echo x > ./aws/credentials",
    ],
)
def test_reads_and_unrelated_forms_pass(command: str, tmp_path: Path) -> None:
    assert verdict(command, tmp_path) == OK


@pytest.mark.parametrize(
    "command",
    [
        "./deploy.sh",
        "make deploy",
        "python -c \"import boto3; boto3.Session(profile_name='prod')\"",
        "export AWS_SHARED_CREDENTIALS_FILE=/tmp/creds",
        "export KUBECONFIG=~/prod.kubeconfig",
        "gcloud compute instances list --account ops@example.com",
        "Set-Item Env:AWS_PROFILE prod",
        "kubectl --context prod delete pod x",
        "kubectx prod",
        "export CLOUDSDK_CORE_ACCOUNT=ops@example.com",
        "cd ~ && echo x > .aws/credentials",
        "source .env.prod",
        "python3 -c \"open('/Users/dev/.config/gcloud/credentials.db','w')\"",
    ],
)
def test_the_misses_the_manifest_names_are_still_misses(command: str, tmp_path: Path) -> None:
    """A fix that closes one of these has to take it out of the manifest's Not caught list too."""
    assert verdict(command, tmp_path) == OK


def test_run_reads_the_raw_command_then_argv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "kubectl config use-context prod")
    assert GUARD.run(["ignored"]) == ASK
    assert capsys.readouterr().err.startswith("CONFIRM: ")
    monkeypatch.delenv("CHOCK_RAW_COMMAND")
    assert GUARD.run(["kubectl", "config", "use-context", "prod"]) == ASK
    assert GUARD.run(["kubectl", "get", "pods"]) == OK
    assert capsys.readouterr().err.count("CONFIRM: ") == 1


def test_an_unexpected_exception_is_a_fault_never_a_verdict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_args: object) -> None:
        raise ValueError

    monkeypatch.setattr(GUARD, "check", boom)
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "aws s3 ls --profile prod")
    assert GUARD.run([]) == ERR
    assert "internal error (ValueError)" in capsys.readouterr().err


def test_a_missing_shared_module_is_a_fault_not_a_verdict() -> None:
    """The imports sit outside run(): a broken copy must still exit 2 and say the command was not checked."""
    runner = (
        "import runpy, sys; sys.modules['credential_shapes'] = None; sys.argv = ['g', 'aws']; "
        f"runpy.run_path({str(IMPL / f'{POLICY}.py')!r}, run_name='__main__')"
    )
    done = subprocess.run([sys.executable, "-c", runner], capture_output=True, text=True, check=False, cwd=IMPL)
    assert done.returncode == ERR
    assert "internal error (" in done.stderr
    assert "command not checked" in done.stderr


@pytest.mark.parametrize(("command", "want"), [("aws s3 ls", OK), ("aws s3 ls --profile prod", ASK)])
def test_run_as_a_script_the_exit_code_is_the_verdict(command: str, want: int, tmp_path: Path) -> None:
    """The hook starts the file itself, in the project directory, with argv and the raw command."""
    env = {**os.environ, "CHOCK_RAW_COMMAND": command}
    done = subprocess.run(
        [sys.executable, str(IMPL / f"{POLICY}.py"), *command.split()],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert done.returncode == want
    assert bool(done.stderr) == (want == ASK)
