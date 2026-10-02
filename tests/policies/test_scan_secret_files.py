"""scan-secret-files: each rule refuses the file it names, stays silent on its look-alike, and sees through a rename.

Fixture values are plainly fake (short or digitless) so no other gate mistakes them for a credential;
the cases that need a PEM private-key header arrive in a person's commit (the PR's owner step).
"""

from __future__ import annotations

import json

import pytest
from policies import sbfkit

sbf_judge = sbfkit.load("sbf_judge")

BLOCK, ASK = "block", "ask"
KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster: {{server: https://k8s.internal}}
users:
- name: deployer
  user:
    {key}: {value}
"""
SA = {"type": "service_account", "private_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"}
OVPN_BODY = "\n".join(["0123456789abcdef0123456789abcdef"] * 16)
OVPN = f"client\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n{OVPN_BODY}\n-----END OpenVPN Static key V1-----\n</tls-auth>\n"
PUTTY = (
    "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: {enc}\nComment: c\nPublic-Lines: 1\nAAAA\nPrivate-Lines: 1\nBBBB\n"
)
NOTEBOOK = {"nbformat": 4, "cells": [{"cell_type": "code", "outputs": [{"output_type": "stream", "text": ["{out}"]}]}]}


def kube(key: str, value: str) -> str:
    return KUBECONFIG.format(key=key, value=value)


def js(obj: object) -> str:
    return json.dumps(obj, indent=2)


def verdicts(path: str, text: str) -> set[tuple[str, str]]:
    return {(f.rule, f.level) for f in sbf_judge.judge(path, text)}


REFUSED = [
    # kubeconfig: a user's inline credential, by any name the file has
    ("deploy/kubeconfig", kube("token", "kubeletbootstrap"), "sbf-kubeconfig"),
    ("ops/cluster.conf", kube("client-key-data", "clientkeydatablob"), "sbf-kubeconfig"),
    ("k/admin.yaml", kube("password", "kubepass"), "sbf-kubeconfig"),
    ("k/oidc", kube("auth-provider", "{config: {refresh-token: refreshvalue}}"), "sbf-kubeconfig"),
    (
        "k/c.json",
        js({"kind": "Config", "users": [{"name": "a", "user": {"token": "jsontokenvalue"}}]}),
        "sbf-kubeconfig",
    ),
    ("k/broken", "apiVersion: v1\nkind: Config\nusers:\n\t- name: x\n", "sbf-kubeconfig"),
    ("k/merge", "kind: Config\nbase: &u {token: t}\nusers:\n- name: a\n  user:\n    <<: *u\n", "sbf-kubeconfig"),
    # Google: service account, user refresh token, OAuth client secret -- by content, any name
    ("keys/sa.json", js(SA), "sbf-gcp-sa-json"),
    ("notes.txt", js({"nested": {"source_credentials": SA}}), "sbf-gcp-sa-json"),
    ("adc.json", js({"type": "authorized_user", "refresh_token": "refreshvalue"}), "sbf-gcp-sa-json"),
    ("client.json", js({"installed": {"client_id": "c", "client_secret": "GOCSPXvalue"}}), "sbf-gcp-sa-json"),
    # registry and tool credentials
    ("home/.docker/config.json", js({"auths": {"r.example.com": {"auth": "dXNlcjpwYXNz"}}}), "sbf-rc-credentials"),
    ("old/.dockercfg", js({"r.example.com": {"auth": "dXNlcjpwYXNz", "email": "a@b"}}), "sbf-rc-credentials"),
    (
        "auth.json",
        js({"http-basic": {"repo.example.org": {"username": "u", "password": "composerpw"}}}),
        "sbf-rc-credentials",
    ),
    ("c.json", js({"config": {"github-oauth": {"github.com": "oauthvalue"}}}), "sbf-rc-credentials"),
    (".npmrc", "registry=https://r.example.com/\n//r.example.com/:_authToken=npmauthvalue\n", "sbf-rc-credentials"),
    ("ci/npmrc-copy", "//registry.npmjs.org/:_authToken=npmauthvalue\n", "sbf-rc-credentials"),
    ("web/.npmrc", "_auth=dXNlcjpwYXNz\nemail=a@b\n", "sbf-rc-credentials"),
    (
        ".pypirc",
        "[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\npassword = pypivalue\n",
        "sbf-rc-credentials",
    ),
    ("ci/pypi.cfg", "[pypi]\nusername = __token__\npassword: pypivalue\n", "sbf-rc-credentials"),
    (".netrc", "machine api.example.com login bot password netrcvalue\n", "sbf-rc-credentials"),
    ("ci/creds", "machine a.example.com\n  login bot\n  password netrcvalue\n", "sbf-rc-credentials"),
    (".git-credentials", "https://bot:pw@localhost\n", "sbf-rc-credentials"),
    ("backup/git-creds.txt", "https://bot:pw@localhost\n\nhttps://me:pw2@localhost:3000\n", "sbf-rc-credentials"),
    (".pgpass", "# local\ndb.internal:5432:app:app:pgpassvalue\n", "sbf-rc-credentials"),
    (
        "NuGet.Config",
        '<packageSourceCredentials><f><add key="ClearTextPassword" value="nugetvalue" /></f>'
        "</packageSourceCredentials>",
        "sbf-rc-credentials",
    ),
    (
        "ci/nuget.xml",
        '<packageSourceCredentials><f><add value="nugetvalue" key="ClearTextPassword"/></f></packageSourceCredentials>',
        "sbf-rc-credentials",
    ),
    (
        "m2/settings.xml",
        "<settings><servers><server><id>r</id><password>mavenvalue</password></server></servers></settings>",
        "sbf-rc-credentials",
    ),
    # AWS
    (".aws/credentials", "[default]\naws_secret_access_key = awssecretaccesskeyvalue\n", "sbf-aws-credentials"),
    ("ci/aws.ini", "[ci]\naws_session_token=awssessiontokenvaluelong\n", "sbf-aws-credentials"),
    # Terraform
    ("infra/terraform.tfstate", "{}\n", "sbf-tfstate-tfvars"),
    ("infra/prod.tfstate.backup", "x", "sbf-tfstate-tfvars"),
    ("state.json", js({"version": 4, "terraform_version": "1.6.0", "serial": 3, "lineage": "l"}), "sbf-tfstate-tfvars"),
    ("prod.tfvars", 'region = "eu-west-1"\ndb_password = "tfvarspw"\n', "sbf-tfstate-tfvars"),
    ("x.auto.tfvars.json", js({"api_token": "tfvarstokenvalue"}), "sbf-tfstate-tfvars"),
    (".terraformrc", 'credentials "app.terraform.io" {\n  token = "tfrcvalue"\n}\n', "sbf-tfstate-tfvars"),
    ("tf.json", js({"credentials": {"app.terraform.io": {"token": "tfcloudvalue"}}}), "sbf-tfstate-tfvars"),
    # dotenv, not a template
    (".env", "PORT=3000\nAPI_KEY=livevaluehere\n", "sbf-tracked-env"),
    ("svc/.env.production", "export SESSION_SECRET='sessionvalue'\n", "sbf-tracked-env"),
    (".env.example.local", "API_KEY=livevaluehere\n", "sbf-tracked-env"),
    ("deploy/prod.env", 'DB_PASSWORD="envpassword"\n', "sbf-tracked-env"),
    # framework secret files
    ("config/master.key", "0123456789abcdef0123456789abcdef\n", "sbf-framework-secrets"),
    ("config/credentials/production.key", "0123456789abcdef0123456789abcdef", "sbf-framework-secrets"),
    ("config/secrets.yml", "production:\n  secret_key_base: railssecretbase\n", "sbf-framework-secrets"),
    ("site/wp-config.php", "<?php\ndefine( 'DB_PASSWORD', 'wppassword' );\n", "sbf-framework-secrets"),
    ("old/config.inc.php", 'define("AUTH_KEY", "wpauthkeyvalue");\n', "sbf-framework-secrets"),
    ("app/local_settings.py", "SECRET_KEY = 'djangosecretvalue'\n", "sbf-framework-secrets"),
    ("app/local_settings.py", "DATABASES = {'default': {'PASSWORD': 'dbpw'}}\n", "sbf-framework-secrets"),
    ("api/appsettings.Production.json", js({"Jwt": {"SigningKey": "signingkeyvalue"}}), "sbf-framework-secrets"),
    (
        "api/AppSettings.production.json",
        js({"ConnectionStrings": {"Db": "Server=db;User Id=sa;Password=prodpw;"}}),
        "sbf-framework-secrets",
    ),
    # private keys by name, by content, and binary containers
    ("certs/client.p12", "binary", "sbf-private-key-files"),
    ("android/release.keystore", "binary", "sbf-private-key-files"),
    ("keys/AuthKey.p8", "x", "sbf-private-key-files"),
    ("deploy/id_ed25519", "x", "sbf-private-key-files"),
    ("vpn/client.ovpn", OVPN, "sbf-private-key-files"),
    ("vpn/notes.txt", OVPN, "sbf-private-key-files"),
    ("keys/me.ppk", PUTTY.format(enc="none"), "sbf-private-key-files"),
    ("keys/me.txt", PUTTY.format(enc="none"), "sbf-private-key-files"),
    (
        "nb/vpn.ipynb",
        js({**NOTEBOOK, "cells": [{"outputs": [{"data": {"text/plain": OVPN}}]}]}),
        "sbf-private-key-files",
    ),
    ("build/x.bin", "0\x82\n\x1b\x02\x01\x030\x82", "sbf-private-key-files"),
    ("build/y.bin", "0\ufffd\x02\x01\x030\ufffd", "sbf-private-key-files"),
    (
        "build/z.dat",
        "\ufffd" * 4 + "\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01" + "\x2b\x06\x01\x04\x01\x2a\x02\x11\x01\x01",
        "sbf-private-key-files",
    ),
    ("certs/server.key", "0\ufffd\x02\x01\x000\r", "sbf-private-key-files"),
    ("certs/ec.der", "0w\x02\x01\x01\x04 ", "sbf-private-key-files"),
    # browser credential stores
    ("profile/Default/Cookies", "x", "sbf-browser-credential-stores"),
    ("profile/Login Data", "x", "sbf-browser-credential-stores"),
    ("ff/key4.db", "x", "sbf-browser-credential-stores"),
    (
        "dump/a.bin",
        "SQLite format 3\x00..CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY)",
        "sbf-browser-credential-stores",
    ),
    (
        "dump/b.bin",
        "SQLite format 3\x00CREATE TABLE cookies(host_key TEXT,encrypted_value BLOB)",
        "sbf-browser-credential-stores",
    ),
    (
        "dump/c",
        "SQLite format 3\x00CREATE TABLE logins (origin_url VARCHAR, password_value BLOB)",
        "sbf-browser-credential-stores",
    ),
    (
        "ff/logins.json",
        js({"logins": [{"hostname": "h", "encryptedPassword": "MDoEEPgAAAB"}]}),
        "sbf-browser-credential-stores",
    ),
]


@pytest.mark.parametrize(("path", "text", "rule"), REFUSED, ids=[f"{r[2]}:{r[0]}" for r in REFUSED])
def test_the_file_is_refused(path: str, text: str, rule: str) -> None:
    assert (rule, BLOCK) in verdicts(path, text)


ASKED = [
    ("keys/me.ppk", PUTTY.format(enc="aes256-cbc"), "sbf-private-key-files"),
    ("nb/explore.ipynb", js(NOTEBOOK).replace("{out}", "client_secret = qXvTzLmPwRkJhGfDsAb"), "sbf-notebook-outputs"),
    ("tests/fixtures/client.p12", "binary", "sbf-private-key-files"),
    ("docs/setup.md", OVPN, "sbf-private-key-files"),
    (".agents/policies/x/evals/suite.yaml", OVPN, "sbf-private-key-files"),
]


@pytest.mark.parametrize(("path", "text", "rule"), ASKED, ids=[f"{r[2]}:{r[0]}" for r in ASKED])
def test_the_file_is_asked_about(path: str, text: str, rule: str) -> None:
    assert verdicts(path, text) == {(rule, ASK)}


ALLOWED = [
    ("deploy/kubeconfig", kube("token", '"${KUBE_TOKEN}"')),
    ("deploy/kubeconfig", kube("client-key", "/etc/k8s/client.key")),
    ("deploy/kubeconfig", kube("token", '""')),
    ("deploy/kubeconfig", kube("exec", "{command: aws, args: [eks, get-token]}")),
    ("k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\n"),
    ("k8s/odd.yaml", "apiVersion: v1\nkind: Pod\nspec:\n\t- x\n"),
    ("keys/sa.json", js({**SA, "private_key": "REDACTED"})),
    ("keys/sa.json", js({**SA, "private_key": ""})),
    ("keys/sa.json", js({**SA, "private_key": "short"})),
    ("keys/ext.json", js({"type": "external_account", "audience": "a"})),
    ("client.json", js({"web": {"client_id": "c", "client_secret": "<your-client-secret>"}})),
    ("client.json", js({"web": "not an object"})),
    ("home/.docker/config.json", js({"auths": {"r.example.com": {}}, "credsStore": "desktop"})),
    ("cfg.json", js({"r.example.com": {"email": "a@b"}})),
    ("cfg.json", js({"auths": ["x"], "http-basic": "x", "logins": "x", "credentials": "x", "kind": "Config"})),
    ("tf.json", js({"credentials": {"app.terraform.io": {"token": ""}}})),
    ("composer.json", js({"require": {"php": ">=8.1"}, "config": {"sort-packages": True}})),
    ("package-lock.json", js({"lockfileVersion": 3, "packages": {}})),
    ("data.json", "[1, 2, 3]\n"),
    ("bad.json", "{not json"),
    (".npmrc", "_authToken=${NPM_TOKEN}\nregistry=https://r.example.com/\n"),
    ("README.md", "Set `//registry.npmjs.org/:_authToken=` in your own npmrc.\n"),
    (".pypirc", "[pypi]\nusername = __token__\npassword =\n"),
    ("setup.cfg", "[metadata]\nname = x\npassword = notpypi\n"),
    (".netrc", "machine api.example.com login bot\n"),
    ("notes.txt", "machine learning needs a password reset\n"),
    (".git-credentials", "\n"),
    ("links.txt", "https://bot:pw@localhost\nsee also https://example.com\n"),
    (".pgpass", "# comment only\n*:*:*:*:\n"),
    (
        "NuGet.Config",
        '<packageSourceCredentials><f><add key="ClearTextPassword" value="%NUGET_PW%" />'
        "</f></packageSourceCredentials>",
    ),
    (
        "settings.xml",
        "<settings><servers><server><password>${env.MVN_PW}</password></server>"
        "<server><password>{COQLCEDUGtcSP=}</password></server></servers></settings>",
    ),
    (".aws/config", "[default]\nregion = eu-west-1\n"),
    ("app.py", "aws_secret_access_key = os.environ['AWS_SECRET']\n"),
    ("ci/aws.ini", "[ci]\naws_secret_access_key = awssecretvalueEXAMPLEkey\n"),
    ("variables.tf", 'variable "db_password" {}\n'),
    ("prod.tfvars", 'db_password = "changeme"\ninstance_type = "t3.micro"\n'),
    (".terraformrc", 'plugin_cache_dir = "$HOME/.terraform.d/plugin-cache"\n'),
    ("infra/terraform.tfstate", "  \n"),
    (".env.example", "API_KEY=livevaluehere\n"),
    (".env.local.example", "API_KEY=livevaluehere\n"),
    ("example.env", "API_KEY=livevaluehere\n"),
    (".env", "PORT=3000\nPASSWORD_MIN_LENGTH=12\nDEBUG=true\nAPI_KEY=\nTOKEN=${CI_TOKEN}\n# SECRET=commented\n"),
    ("config/master.key", "not a rails key\n"),
    ("config/secrets.yml", "production:\n  secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>\n"),
    (
        "site/wp-config-sample.php",
        "define( 'DB_PASSWORD', 'password_here' );\ndefine( 'AUTH_KEY', 'put your unique "
        "phrase here' );\ndefine('DB_PASSWORD', getenv('DB_PASSWORD'));\n",
    ),
    ("app/local_settings.py", "SECRET_KEY = os.environ['SECRET_KEY']\n"),
    ("api/appsettings.Production.json", js({"Logging": {"LogLevel": "Warning"}, "ApiKey": "${API_KEY}"})),
    ("api/appsettings.Development.json", js({"Jwt": {"SigningKey": "signingkeyvalue"}})),
    ("certs/server.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
    ("certs/server.key", "PK\x03\x04 keynote archive"),
    ("deploy/id_ed25519.pub", "ssh-ed25519 AAAA me@host\n"),
    ("deploy/id_ed25519", ""),
    ("vpn/short.ovpn", "-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----\n"),
    ("src/cookies", "export const cookies = []\n"),
    ("dump/d.bin", "SQLite format 3\x00CREATE TABLE users (id INTEGER)"),
    ("ff/logins.json", js({"logins": [{"user": "u"}]})),
    ("nb/clean.ipynb", js(NOTEBOOK).replace("{out}", "accuracy 0.93")),
    ("nb/odd.ipynb", js({"nbformat": 4, "cells": [{"outputs": "x"}, "y", {"outputs": [1, {"text": 2}]}]})),
]


@pytest.mark.parametrize(("path", "text"), ALLOWED, ids=[f"{i}:{r[0]}" for i, r in enumerate(ALLOWED)])
def test_the_file_is_allowed(path: str, text: str) -> None:
    assert verdicts(path, text) == set()
