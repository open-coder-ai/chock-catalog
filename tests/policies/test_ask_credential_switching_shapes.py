"""ask-credential-switching: gcloud impersonation, PowerShell `$env:` assignments and the vendor-doc corrections."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import guardkit
from policies.test_ask_credential_switching import repo_with

GUARD = guardkit.load_guard("ask-credential-switching")
SA = "admin@proj.iam.gserviceaccount.com"


@pytest.mark.parametrize(
    ("command", "named"),
    [
        (f"gcloud compute instances list --impersonate-service-account {SA}", f"service account {SA}"),
        (f"gcloud config set auth/impersonate_service_account {SA}", f"service account {SA}"),
        ("gcloud config set auth/impersonate_service_account", "service account (not named)"),
        (f"gcloud storage ls --impersonate-service-account={SA},delegate@p.iam.gserviceaccount.com", f"{SA},delegate"),
        ("gcloud auth application-default login ops@example.com", "Google account ops@example.com"),
        ('$env:AWS_PROFILE = "Prod"', "AWS profile Prod"),
        ("$Env:AWS_DEFAULT_PROFILE='Prod'", "AWS profile Prod"),
        ("$env:AWS_PROFILE=$p", "AWS profile $p"),
        ('$env:AWS_ACCESS_KEY_ID="AKIAX"; $env:AWS_SECRET_ACCESS_KEY="s"', "access key AKIAX"),
        ('$env:AWS_SESSION_TOKEN="t"', "access key (not named)"),
        ("aws configure set --sso-session corp sso_start_url https://corp.awsapps.com/start", "AWS profile default"),
    ],
)
def test_the_new_shapes_ask_naming_the_identity(command: str, named: str, tmp_path: Path) -> None:
    prompt = GUARD.check(command, tmp_path)
    assert prompt
    assert named in prompt


@pytest.mark.parametrize(
    "command",
    [
        "gcloud auth login ops@example.com --no-activate",
        "gcloud config unset auth/impersonate_service_account",
        "gcloud config get-value auth/impersonate_service_account",
        "$env:AWS_PROFILE",
        "Write-Output $env:AWS_PROFILE",
        'echo "$env:AWS_PROFILE = prod"',
        '$env:NODE_ENV = "production"',
        "aws configure set --sso-session corp sso_region us-east-1",
    ],
)
def test_reads_and_unrelated_forms_still_pass(command: str, tmp_path: Path) -> None:
    assert GUARD.check(command, tmp_path) is None


def test_a_powershell_key_pair_is_named_once(tmp_path: Path) -> None:
    prompt = GUARD.check('$env:AWS_ACCESS_KEY_ID="AKIAX"; $env:AWS_SECRET_ACCESS_KEY="s"', tmp_path)
    assert prompt.count("AKIAX") == 1


def test_listed_identities_pass_for_the_new_shapes(tmp_path: Path) -> None:
    root = repo_with(tmp_path, json.dumps({"gcloud": [SA], "aws": ["Prod"]}))
    assert GUARD.check(f"gcloud run deploy api --impersonate-service-account={SA}", root) is None
    assert GUARD.check('$env:AWS_PROFILE = "Prod"', root) is None
    assert GUARD.check('$env:AWS_PROFILE = "prod"', root)
