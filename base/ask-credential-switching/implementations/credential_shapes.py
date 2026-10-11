"""The shell shapes that switch the cloud or cluster identity a later command acts as (stdlib only)."""

from __future__ import annotations

import posixpath
import re
from typing import NamedTuple

from chock_shellparse import Cmd, positionals, writes_files


class Switch(NamedTuple):
    """A switch to `identity` (None when the command does not name one) of `provider`, described as `what`."""

    provider: str
    identity: str | None
    what: str


AWS_VALUES = frozenset(
    (
        *("--profile", "--region", "--output", "--endpoint-url", "--query", "--ca-bundle", "--color"),
        *("--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format", "--role-arn", "--role-session-name"),
        *("--serial-number", "--token-code", "--duration-seconds", "--external-id", "--policy", "--policy-arns"),
        *("--web-identity-token", "--provider-id", "--principal-arn", "--saml-assertion", "--tags"),
        *("--sso-session", "--services"),
    )
)
#: `aws` subcommands that only show what is configured: they pass whatever profile they name.
AWS_READS = frozenset(
    (("configure", "list"), ("configure", "list-profiles"), ("configure", "get"), ("sts", "get-caller-identity"))
)
AWS_ASSUME = frozenset(("assume-role", "assume-role-with-web-identity", "assume-role-with-saml"))
AWS_CRED_KEYS = frozenset(
    (
        *("aws_access_key_id", "aws_secret_access_key", "aws_session_token", "role_arn", "source_profile"),
        *("credential_source", "credential_process", "web_identity_token_file", "sso_session", "sso_account_id"),
        *("sso_role_name", "sso_start_url"),
    )
)
AWS_PROFILE_ENV = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE")
AWS_KEY_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
GCLOUD_VALUES = frozenset(
    (
        *("--account", "--project", "--configuration", "--verbosity", "--format", "--billing-project"),
        *("--flags-file", "--flatten", "--trace-token", "--key-file", "--impersonate-service-account"),
    )
)
AZ_VALUES = frozenset(
    (
        *("--subscription", "-s", "--name", "-n", "--username", "-u", "--password", "-p", "--tenant", "-t"),
        *("--output", "-o", "--query", "--client-id", "--object-id", "--resource-id", "--scope", "--certificate"),
        *("--federated-token",),
    )
)
KUBECTL_VALUES = frozenset(("--kubeconfig", "--context", "--cluster", "--user", "-n", "--namespace", "-v"))
HOME = r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|/root|/home/[^/]+|/users/[^/]+|[a-z]:/users/[^/]+)"
STORE = re.compile(rf"{HOME}/(?:\.aws/(?:credentials|config)|\.config/gcloud(?:/.*)?|\.azure(?:/.*)?)", re.I)
VARIABLE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
PS_ENV = re.compile(r"""\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^']*)'|"([^"]*)"|([^\s;|&]*))""", re.I)


def value(args: list[str], *names: str) -> str | None:
    """The value of the first of `names` given as `--name v` or `--name=v`, else None."""
    for i, arg in enumerate(args):
        flag, eq, rest = arg.partition("=")
        if flag in names:
            return rest if eq else (args[i + 1] if i + 1 < len(args) else None)
    return None


def shown(text: str | None, env: dict[str, str]) -> str | None:
    """A value with a `$NAME` the line itself assigned replaced by what it holds."""
    if text is None:
        return None
    found = VARIABLE.fullmatch(text)
    return env.get(found.group(1), text) if found else text


def at(words: list[str], index: int) -> str | None:
    """The word at `index`, or None past the end."""
    return words[index] if index < len(words) else None


def aws_read(cmd: Cmd) -> bool:
    return cmd.name == "aws" and tuple(positionals(cmd.args, AWS_VALUES)[:2]) in AWS_READS


def aws(cmd: Cmd) -> Switch | None:
    words = positionals(cmd.args, AWS_VALUES)
    if cmd.name != "aws" or aws_read(cmd):
        return None
    profile = shown(value(cmd.args, "--profile"), cmd.env)
    if words[:1] == ["sts"] and words[1:2] and words[1] in AWS_ASSUME:
        role = shown(value(cmd.args, "--role-arn"), cmd.env)
        return Switch("aws", role, f"the AWS role {role or '(not named)'} (aws sts {words[1]})")
    key = at(words, 2) if words[:2] == ["configure", "set"] else None
    if key is not None:
        *section, name = key.split(".")
        if name.lower() in AWS_CRED_KEYS:
            who = at(section[1:] if section[:1] == ["profile"] else section, 0) or profile or "default"
            return Switch("aws", who, f"the AWS profile {who}, given new credentials (aws configure set {name})")
        return None  # a setting such as region changes no identity
    if profile is not None:
        return Switch("aws", profile, f"the AWS profile {profile} (--profile)")
    return None


def aws_env(env: dict[str, str]) -> list[Switch]:
    """`AWS_PROFILE=p`, and access keys, set for a command or exported for the rest of the line."""
    found = [
        Switch("aws", who, f"the AWS profile {who} ({name}=)")
        for name in AWS_PROFILE_ENV
        if name in env and (who := shown(env[name], env) or "default")
    ]
    keys = [n for n in AWS_KEY_ENV if n in env]
    if keys:
        key = shown(env.get("AWS_ACCESS_KEY_ID"), env) or None
        found.append(Switch("aws", key, f"the AWS access key {key or '(not named)'} ({', '.join(keys)} set)"))
    return found


def gcloud(cmd: Cmd) -> Switch | None:
    words = positionals(cmd.args, GCLOUD_VALUES)
    if cmd.name != "gcloud":
        return None
    if words[:2] == ["config", "set"] and words[2:3] in (["account"], ["core/account"]):
        who = at(words, 3)
        return Switch("gcloud", who, f"the Google Cloud account {who or '(not named)'} (gcloud config set account)")
    if words[:3] == ["config", "configurations", "activate"]:
        who = at(words, 3)
        return Switch("gcloud", who, f"the gcloud configuration {who or '(not named)'} (configurations activate)")
    if words[:2] == ["auth", "activate-service-account"]:
        who = at(words, 2)
        return Switch(
            "gcloud", who, f"the service account {who or '(named in its key file)'} (activate-service-account)"
        )
    login = words[:2] == ["auth", "login"] and "--no-activate" not in cmd.args  # stored, not made active
    if login or words[:3] == ["auth", "application-default", "login"]:
        who = at(words, 2 if words[1] == "login" else 3)
        return Switch("gcloud", who, f"the Google account {who or '(chosen at login)'} (gcloud {' '.join(words[:3])})")
    return None


def gcloud_impersonate(cmd: Cmd) -> Switch | None:
    """`--impersonate-service-account` on any gcloud command, or set as the default with `gcloud config set`."""
    words = positionals(cmd.args, GCLOUD_VALUES)
    if cmd.name != "gcloud":
        return None
    who = shown(value(cmd.args, "--impersonate-service-account"), cmd.env)
    if who is None and words[:2] == ["config", "set"] and at(words, 2) == "auth/impersonate_service_account":
        who = at(words, 3) or ""
    if who is None:
        return None
    return Switch("gcloud", who or None, f"the impersonated service account {who or '(not named)'} (gcloud)")


def az(cmd: Cmd) -> Switch | None:
    words = positionals(cmd.args, AZ_VALUES)
    if cmd.name != "az":
        return None
    if words[:2] == ["account", "set"]:
        who = shown(value(cmd.args, "--subscription", "-s", "--name", "-n"), cmd.env)
        return Switch("azure", who, f"the Azure subscription {who or '(not named)'} (az account set)")
    principal, identity = "--service-principal" in cmd.args, "--identity" in cmd.args
    if words[:1] == ["login"] and (principal or identity):
        names = (
            ("--username", "-u") if principal else ("--username", "-u", "--client-id", "--object-id", "--resource-id")
        )
        who = shown(value(cmd.args, *names), cmd.env)
        kind = "service principal" if principal else "managed identity"
        return Switch("azure", who, f"the Azure {kind} {who or '(not named)'} (az login)")
    return None


def kubectl(cmd: Cmd) -> Switch | None:
    words = positionals(cmd.args, KUBECTL_VALUES)
    verb, who = at(words, 1), at(words, 2)
    if cmd.name != "kubectl" or words[:1] != ["config"]:
        return None
    if verb in ("use-context", "use"):
        return Switch("kubernetes", who, f"the Kubernetes context {who or '(not named)'} (kubectl config {verb})")
    if verb == "set-credentials":
        return Switch(
            "kubernetes",
            who,
            f"the Kubernetes user {who or '(not named)'}, given new credentials (kubectl config set-credentials)",
        )
    return None


def store(path: str) -> bool:
    """Whether a path is a cloud CLI's credential or config store under the home directory."""
    norm = posixpath.normpath(path.replace("\\", "/"))
    return bool(STORE.fullmatch(norm))


def file_write(cmd: Cmd) -> Switch | None:
    if writes_files(cmd, store):
        return Switch(
            "files",
            None,
            "whatever a cloud CLI's credential store now holds (a shell write to ~/.aws, ~/.config/gcloud or ~/.azure)",
        )
    return None


def powershell_env(cmd: Cmd, raw: str) -> list[Switch]:
    """`$env:AWS_PROFILE = "p"`: the parser lowercases that word, so the values are read from the line it confirms."""
    name, eq, _ = cmd.name[len("$env:") :].partition("=") if cmd.name.startswith("$env:") else ("", "", "")
    name = name.upper()
    if name not in (*AWS_PROFILE_ENV, *AWS_KEY_ENV) or not (eq or cmd.args[:1] == ["="]):
        return []
    values = {m.group(1).upper(): next(g for g in m.groups()[1:] if g is not None) for m in PS_ENV.finditer(raw)}
    env = {name: values.get(name, "$" + name)}
    if "AWS_ACCESS_KEY_ID" in values:
        env.setdefault("AWS_ACCESS_KEY_ID", values["AWS_ACCESS_KEY_ID"])
    return aws_env(env) if name in AWS_PROFILE_ENV else aws_env(env)[-1:]


def switches(cmd: Cmd, raw: str = "") -> list[Switch]:
    """Every switch one simple command makes; a read-only `aws` command passes whatever its environment holds."""
    found = [hit for check in (aws, gcloud, gcloud_impersonate, az, kubectl, file_write) if (hit := check(cmd))]
    found += powershell_env(cmd, raw)
    return found if aws_read(cmd) else [*found, *aws_env(cmd.env)]
