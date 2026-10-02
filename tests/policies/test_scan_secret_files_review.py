"""scan-secret-files: the security review's reproductions -- each bypass now caught, each false positive silent."""

from __future__ import annotations

import base64
import json
import random
import time

import pytest
from policies import sbfkit

sbf_judge, sbf_keys = (sbfkit.load(n) for n in ("sbf_judge", "sbf_keys"))
HEX_LINE = "0123456789abcdef0123456789abcdef\n"
OVPN = "-----BEGIN OpenVPN Static key V1-----\n" + HEX_LINE * 4 + "-----END OpenVPN Static key V1-----\n"
KUBE_USERS = "users:\n- name: a\n  user:\n    token: kubeletbootstrap\n"


@pytest.mark.parametrize(
    ("path", "text", "rule"),
    [
        (".env", "\ufeffAPI_KEY=livevaluehere\n", "sbf-tracked-env"),
        ("ops/x.conf", "\ufeffkind: Config\n" + KUBE_USERS, "sbf-kubeconfig"),
        ("ops/x.conf", "kind: Config\r\n" + KUBE_USERS.replace("\n", "\r\n"), "sbf-kubeconfig"),
        ("ops/x.conf", "'kind': Config\n" + KUBE_USERS, "sbf-kubeconfig"),
        ("ops/x.conf", "kind: !!str Config\n" + KUBE_USERS, "sbf-kubeconfig"),
        ("ops/x.conf", "--- {kind: Config}\n" + KUBE_USERS, "sbf-kubeconfig"),
        ("ops/x.conf", 'apiVersion: v1\nkind: "\\u0043onfig"\n' + KUBE_USERS, "sbf-kubeconfig"),
        ("ops/x.conf", '"\\u006bind": Config\n' + KUBE_USERS, "sbf-kubeconfig"),
        (
            "s.json",
            "\ufeff" + json.dumps({"terraform_version": "1", "lineage": "l", "serial": 1}),
            "sbf-tfstate-tfvars",
        ),
        (
            "s.json",
            "// state\n/* copy */\n" + json.dumps({"terraform_version": "1", "lineage": "l", "serial": 1}),
            "sbf-tfstate-tfvars",
        ),
        (
            "d.json",
            '{"auths": {"ghcr.io": {"auth": "dXNlcjpwYXNz"}}, "pad": ' + "[" * 300 + "]" * 300 + "}",
            "sbf-rc-credentials",
        ),
        ("d.json", '{"type": "service_account", "private_key": "x"} trailing', "sbf-gcp-sa-json"),
        ("ci/aws.ini", "[ci]\r\naws_session_token=awssessiontokenvaluelong\r\n", "sbf-aws-credentials"),
        ("svc/.env-production", "API_KEY=livevaluehere\n", "sbf-tracked-env"),
        ("svc/.env_prod", "API_KEY=livevaluehere\n", "sbf-tracked-env"),
        ("build/t.jks", "\ufffd" * 4 + "\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x02", "sbf-private-key-files"),
        ("vpn/one-line.txt", OVPN.replace("\n", " "), "sbf-private-key-files"),
        (
            "src/Key.java",
            "String k = " + " +\n".join(f'"{line}"' for line in OVPN.splitlines()) + ";\n",
            "sbf-private-key-files",
        ),
        ("mail.txt", "".join(f"> {line}\n" for line in OVPN.splitlines()), "sbf-private-key-files"),
        (
            "notes.txt",
            "prod creds:\n[default]\naws_secret_access_key = awssecretaccesskeyvalue\n",
            "sbf-aws-credentials",
        ),
        ("notes.md", "```\n[default]\naws_secret_access_key = awssecretaccesskeyvalue\n```\n", "sbf-aws-credentials"),
        (".env", "AWS_SECRET_ACCESS_KEY=/wJalrXUtnFEMIKMDENGbPxRfiCYzzzKEYVALUE\n", "sbf-tracked-env"),
        (".env", "SLACK_SECRET=https://hooks.chat-relay.net/services/a/b/c\n", "sbf-tracked-env"),
        (".env", "\ufeff\ufeff\u200bAPI_KEY=livevaluehere\n", "sbf-tracked-env"),
        (
            "ci/pypi.cfg",
            "[distutils]\nindex-servers =\n    private\n[private]\npassword = pypivalue\n",
            "sbf-rc-credentials",
        ),
    ],
)
def test_review_bypasses_are_caught(path: str, text: str, rule: str) -> None:
    assert rule in {f.rule for f in sbf_judge.judge(path, text)}


def test_a_store_with_a_key_protector_refuses_whatever_its_first_entry() -> None:
    store = "\ufffd" * 4 + "\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02" + "x" * 40 + sbf_keys.KEY_PROTECTORS[0]
    assert {(f.rule, f.level) for f in sbf_judge.judge("android/release.jks", store)} == {
        ("sbf-private-key-files", "block")
    }


def test_a_truststore_asks_instead_of_refusing() -> None:
    store = "\ufffd" * 4 + "\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x02"
    assert {(f.rule, f.level) for f in sbf_judge.judge("certs/trust.jks", store)} == {("sbf-private-key-files", "ask")}


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("pkg/upload.py", '"""Reads [pypi] from .pypirc."""\npassword = cfg.get("password")\n'),
        ("pkg/upload.cfg", "[pypi]\npassword = %s\n"),
        ("src/k8s.py", 'def make():\n    return {"apiVersion": "v1", "kind": "Config", "users": [{"x": ")"}]}\n'),
        ("src/kube.ts", "export const c = {\n  kind: 'Config',\n  users: [{ name: 'a' }],\n};\n"),
        ("log.jsonl", '{"event": "login", "auths": 1}\n{"event": "x"}\n'),
        ("pyproject.toml", '[tool.x]\nkeys = ["auths", "client_secret"]\n'),
        ("cfg.ini", '[oauth]\n"client_secret" = 1\n'),
        ("guide.md", '[![badge](x)] see "client_secret" and "installed"\n'),
        ("data.js", "[1, 2, 3]\n"),
        ("pkg/upload.py", '"""\n[pypi]\n"""\nimport x\npassword = prompt()\n'),
        (
            ".env",
            "SECRET_KEY_FILE=/run/secrets/key\nGOOGLE_APPLICATION_CREDENTIALS=./sa.json\nPUBLIC_API_KEY_NAME=checkout\n",
        ),
        (".env", "AUTH_TOKEN_URL=https://auth.example.org/token\n"),
        ("app/local_settings.py", "SECRET_KEY = 'dev'\n"),
        (
            "README.txt",
            "If you see -----BEGIN OpenVPN Static key V1----- in a file, never commit it: it must be rotated.\n",
        ),
        ("notes.json", '{"note": "the auths key"'),
        ("app.py", 'CONFIG = {"type": "service_account", "private_key": key}\n'),
    ],
)
def test_review_false_positives_are_silent(path: str, text: str) -> None:
    assert sbf_judge.judge(path, text) == []


@pytest.mark.parametrize("width", [4, 8, 15])
def test_review_round_three_a_terminated_block_counts_short_lines(width: str) -> None:
    body = "".join(HEX_LINE.split()) * 4
    lines = [body[i : i + width] for i in range(0, len(body), width)]
    text = "-----BEGIN OpenVPN Static key V1-----\n" + "\n".join(lines) + "\n-----END OpenVPN Static key V1-----\n"
    assert {f.rule for f in sbf_judge.judge("vpn/k.txt", text)} == {"sbf-private-key-files"}


@pytest.mark.parametrize(
    ("path", "text", "rule"),
    [
        ("s.json", '{ /* c */ "version":4,"terraform_version":"1.5","serial":1,"lineage":"a"}', "sbf-tfstate-tfvars"),
        ("cfg.json", '{\n  // creds\n  "auths":{"ghcr.io":{"auth":"dXNlcjpwYXNz"}}}', "sbf-rc-credentials"),
        ("l.json", '[ // list\n {"type": "authorized_user", "refresh_token": "refreshvalue"}]', "sbf-gcp-sa-json"),
    ],
)
def test_review_round_three_comments_inside_the_opener(path: str, text: str, rule: str) -> None:
    assert rule in {f.rule for f in sbf_judge.judge(path, text)}


def test_review_round_three_paths_after_a_stray_begin_are_not_key_bytes() -> None:
    text = (
        'HEADER = "-----BEGIN OpenVPN Static key V1-----"\n'
        'CONFIG_DIR = "/etc/myapplication/configuration/subdirectory/x"\n'
        'LOG_DIR = "/var/log/myapplication/output/subdirectory/xy"\n'
    )
    assert sbf_judge.judge("src/detect.py", text) == []


BEGIN, END = "-----BEGIN OpenVPN Static key V1-----", "-----END OpenVPN Static key V1-----"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (".env.example", "Paste your private key contents here and keep the newlines"),
        ("config/key.template", "REPLACE THIS WITH YOUR SERVICE ACCOUNT PRIVATE KEY CONTENTS"),
        ("x.txt", "X" * 50),
        ("README.txt", "This block shows where the static key goes when you configure the tunnel"),
    ],
)
def test_review_round_four_placeholder_text_between_the_armor_is_not_a_key(path: str, body: str) -> None:
    assert sbf_judge.judge(path, f"{BEGIN}\n{body}\n{END}\n") == []


def test_review_round_four_a_forged_early_end_does_not_cut_the_body() -> None:
    text = f"{BEGIN}\n{END}\n" + HEX_LINE * 4 + f"{END}\n"
    assert {f.rule for f in sbf_judge.judge("vpn/k.txt", text)} == {"sbf-private-key-files"}


@pytest.mark.parametrize("width", [32, 39])
def test_review_round_five_zero_padding_does_not_dilute_a_rewrapped_key(width: int) -> None:
    body = base64.b64encode(random.Random(5).randbytes(48)).decode()  # noqa: S311 -- a fixed fake body
    lines = [body[i : i + width] for i in range(0, len(body), width)] + ["A" * 64] * 32
    text = f"{BEGIN}\n" + "\n".join(lines) + f"\n{END}\n"
    assert {f.rule for f in sbf_judge.judge("keys/k.pem", text)} == {"sbf-private-key-files"}


def test_review_round_five_many_begin_end_pairs_stay_linear() -> None:
    started = time.monotonic()
    sbf_judge.judge("x.txt", f"{BEGIN}\n{END}\n" * 60000)
    assert time.monotonic() - started < 10


def test_review_round_six_padding_past_the_body_limit_does_not_hide_the_end() -> None:
    body = base64.b64encode(random.Random(6).randbytes(48)).decode()  # noqa: S311 -- a fixed fake body
    lines = [body[i : i + 39] for i in range(0, len(body), 39)] + ["A" * 64] * 1000
    text = f"{BEGIN}\n" + "\n".join(lines) + f"\n{END}\n"
    assert {f.rule for f in sbf_judge.judge("keys/k.pem", text)} == {"sbf-private-key-files"}


def test_review_round_six_padding_interleaved_between_key_lines_is_measured_out() -> None:
    body = base64.b64encode(random.Random(7).randbytes(48)).decode()  # noqa: S311 -- a fixed fake body
    lines = [line for i in range(0, len(body), 8) for line in (body[i : i + 8], "A" * 64)]
    text = f"{BEGIN}\n" + "\n".join(lines) + f"\n{END}\n"
    assert {f.rule for f in sbf_judge.judge("keys/k.pem", text)} == {"sbf-private-key-files"}
