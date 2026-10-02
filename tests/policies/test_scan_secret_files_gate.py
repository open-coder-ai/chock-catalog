"""scan-secret-files: the gate's contract with the engine, the helpers' edges, and linear time on hostile input."""

from __future__ import annotations

import base64
import io
import json
import sys
import time
from pathlib import Path

import pytest
from policies import gatekit, sbfkit, scriptkit

POLICY, NAME = "scan-secret-files", sbfkit.GATE
WARN = 4  # the runner's warn: reported, never a refusal
gate, sbf_core, sbf_judge, sbf_keys = (sbfkit.load(n) for n in (NAME, "sbf_core", "sbf_judge", "sbf_keys"))
KUBE = "kind: Config\nusers:\n- name: a\n  user:\n    token: kubeletbootstrap\n"
PUTTY_ENCRYPTED = "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: aes256-cbc\nPrivate-Lines: 1\nAAAA\n"
HEX_LINE = "0123456789abcdef0123456789abcdef\n"
OVPN = "-----BEGIN OpenVPN Static key V1-----\n" + HEX_LINE * 4 + "-----END OpenVPN Static key V1-----\n"


def run(tmp_path: Path, stdin: str) -> tuple[int, dict | None, str]:
    proc = scriptkit.run_script_full(POLICY, NAME, tmp_path, stdin)
    document = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, document, proc.stderr


def test_a_clean_write_allows_with_an_empty_findings_document(tmp_path: Path) -> None:
    assert run(tmp_path, json.dumps({"writes": {"app.py": "print(1)\n"}})) == (0, {"findings": []}, "")


def test_a_secret_file_refuses_naming_the_rule_never_the_value(tmp_path: Path) -> None:
    code, document, err = run(tmp_path, json.dumps({"event": "commit", "writes": {"ops/kubeconfig": KUBE}}))
    assert code == 1
    (item,) = document["findings"]
    assert item["rule"] == "sbf-kubeconfig"
    assert item["key"].startswith("sbf-kubeconfig|")
    assert (item["path"], item["line"]) == ("ops/kubeconfig", 5)
    assert "ops/kubeconfig:5: sbf-kubeconfig: kubeconfig user token" in err
    assert ".gitignore" in err
    assert "kubeletbootstrap" not in json.dumps(document) + err


def test_only_asks_exit_three(tmp_path: Path) -> None:
    code, document, err = run(tmp_path, json.dumps({"writes": {"keys/me.ppk": PUTTY_ENCRYPTED}}))
    assert code == 3
    assert document["findings"][0]["message"].endswith("(asks)")
    assert "(asks)" in err


def test_one_refusal_among_asks_refuses(tmp_path: Path) -> None:
    writes = {"keys/me.ppk": PUTTY_ENCRYPTED, "ops/kubeconfig": KUBE}
    assert run(tmp_path, json.dumps({"writes": writes}))[0] == 1


@pytest.mark.parametrize("stdin", ["", "not json", "[]", '{"writes": []}', '{"writes": {"a": 1}}', '{"x": 1}'])
def test_input_that_is_not_the_gate_json_is_undecided(tmp_path: Path, stdin: str) -> None:
    code, document, err = run(tmp_path, stdin)
    assert (code, document) == (2, None)
    assert err.startswith("scan-secret-files:")


def test_the_key_follows_the_value_not_the_line() -> None:
    first = gate.findings({"a/kubeconfig": KUBE})[0][0]
    moved = gate.findings({"a/kubeconfig": "# moved\n" + KUBE})[0][0]
    other = gate.findings({"a/kubeconfig": KUBE.replace("kubeletbootstrap", "anothervalue")})[0][0]
    assert first["key"] == moved["key"] != other["key"]
    assert first["line"] + 1 == moved["line"]


def test_main_reads_stdin_in_process(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"writes": {".env": "API_KEY=livevaluehere\n"}})))
    assert gate.main() == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule"] == "sbf-tracked-env"


def test_the_engine_warns_in_observe_and_keeps_only_what_the_change_adds(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"ops/kubeconfig": KUBE, "README.md": "x\n"})
    scriptkit.write(repo, {"ops/kubeconfig": "# a comment\n" + KUBE, "deploy/.env": "API_KEY=livevaluehere\n"})
    scriptkit.git(repo, "add", "-A")
    code, err = gatekit.judge(POLICY, repo, gatekit.COMMIT)
    assert code == 0  # a warn at commit lets the commit through
    assert "deploy/.env:1: sbf-tracked-env" in err
    assert "ops/kubeconfig" not in err


def test_the_engine_judges_an_agent_write(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "r", {"README.md": "x\n"})
    code, err = gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {"vpn/client.ovpn": OVPN})
    assert "sbf-private-key-files" in err
    assert code == WARN  # observe until promoted


# --- helper edges ---------------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, 7, "${GCP_KEY}", "short"])
def test_key_material_needs_key_bytes(value: object) -> None:
    assert not sbf_core.key_material(value)


def test_line_of_an_offset_not_found_is_one() -> None:
    assert sbf_core.line_of("a\nb", -1) == 1


#: The first bytes of a plain PKCS#8 key (SEQUENCE, INTEGER 0, algorithm): no secret, just its shape.
PLAIN_PKCS8 = b"\x30\x82\x04\xbe\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00" + b"\x00" * 12
#: The first bytes of an EncryptedPrivateKeyInfo under PBES2, then ciphertext-like filler.
PBES2 = b"\x30\x82\x05\x00\x30\x4e\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d" + bytes(range(100, 160))
FILLER = b"\x9f\x11\x42" * 24


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def openssh(cipher: bytes, private: bytes = b"") -> str:
    raw = b"openssh-key-v1\0" + len(cipher).to_bytes(4, "big") + cipher + b"\0" * 40 + b"ssh-ed25519" + private
    return base64.b64encode(raw).decode()


@pytest.mark.parametrize(
    ("label", "body", "expected"),
    [
        ("ENCRYPTED PRIVATE KEY", b64(PBES2), True),
        ("ENCRYPTED PRIVATE KEY", b64(b"\x30\x4e\x30\x4c\x06\x09" + FILLER), False),
        ("ENCRYPTED PRIVATE KEY", b64(PLAIN_PKCS8), False),
        ("ENCRYPTED PRIVATE KEY", b64(PBES2[:17] + PLAIN_PKCS8), False),
        ("ENCRYPTED PRIVATE KEY", "", False),
        ("RSA PRIVATE KEY", "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n" + b64(FILLER), True),
        ("RSA PRIVATE KEY", "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n" + b64(PLAIN_PKCS8), False),
        ("RSA PRIVATE KEY", "Proc-Type: 4,ENCRYPTED\nDEK-Info: X,00\n" + "A" * 17 + "\n" + b64(PLAIN_PKCS8), False),
        ("RSA PRIVATE KEY", "Proc-Type: 4,ENCRYPTED\n" + b64(FILLER), False),
        ("RSA PRIVATE KEY", HEX_LINE, False),
        ("OPENSSH PRIVATE KEY", openssh(b"aes256-ctr"), True),
        ("OPENSSH PRIVATE KEY", openssh(b"none"), False),
        ("OPENSSH PRIVATE KEY", openssh(b"aes256-ctr", b"\0" * 9 + b"ssh-ed25519"), False),
        ("OPENSSH PRIVATE KEY", base64.b64encode(b"not an openssh key at all, just bytes").decode(), False),
        ("OPENSSH PRIVATE KEY", base64.b64encode(b"openssh-key-v1\0").decode(), False),
    ],
)
def test_encrypted(label: str, body: str, expected: bool) -> None:
    assert sbf_keys.encrypted(label, body) is expected


def test_an_unterminated_block_is_read_to_the_next_begin() -> None:
    begin = "-----BEGIN OpenVPN Static key V1-----\n"
    text = begin + HEX_LINE * 2 + begin + "abc\n" + OVPN
    lines = [f.line for f in sbf_keys.pem_blocks(text)]
    assert lines == [1, 6]


def test_a_block_split_by_json_escapes_is_measured_whole() -> None:
    text = json.dumps({"k": OVPN})
    assert [f.level for f in sbf_keys.pem_blocks(text)] == ["block"]


def test_findings_are_reported_once_each_in_line_order() -> None:
    text = "# note\n" + OVPN + OVPN
    assert [f.line for f in sbf_judge.judge("a/b.txt", text)] == [2, 8]


@pytest.mark.parametrize(
    "text",
    [
        json.dumps(
            {
                "kind": "Config",
                "users": [{"user": "x"}, "y", {"user": {"auth-provider": {"config": {"id-token": "idtokenvalue"}}}}],
            }
        ),
        "{apiVersion: v1, kind: Config, users: [{name: a, user: {token: flowtokenvalue}}]}\n",
    ],
)
def test_kubeconfig_shapes_beyond_the_plain_one(text: str) -> None:
    assert {f.rule for f in sbf_judge.judge("x", text)} == {"sbf-kubeconfig"}


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"http-basic": ["x"], "github-oauth": {"github.com": {"username": "u"}}, "bearer": {"h": 7}}),
        "users of this kind are welcome\n",
        "apiVersion: v1\nkind: List\nusers:\n- name: a\n  user: {token: listtokenvalue}\n",
        "DATABASES = {'default': {'PASSWORD': ''}}\n",
    ],
)
def test_look_alikes_are_silent(text: str) -> None:
    assert sbf_judge.judge("app/local_settings.py", text) == []


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN OpenVPN Static key V1-----\n" * 20000,
        "<packageSourceCredentials>" + "<add key=" * 100000,
        "SQLite format 3\x00" + "CREATE TABLE cookies(" * 50000,
        "machine password " * 60000,
        "a=b\n" * 200000,
        "kind: Config\n" + "- " * 200000,
        "{" * 300 + "}" * 300,
        "[" + "1," * 300000 + "1]",
    ],
    ids=["begin", "nuget", "sqlite", "netrc", "env", "kube", "nesting", "array"],
)
def test_hostile_input_is_judged_in_linear_time(text: str) -> None:
    started = time.monotonic()
    sbf_judge.judge(".netrc", text)
    sbf_judge.judge("deploy/kubeconfig", text)
    assert time.monotonic() - started < 10
