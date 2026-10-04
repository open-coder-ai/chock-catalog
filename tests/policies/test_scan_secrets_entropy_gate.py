"""scan-secrets-entropy gate: the findings document, waivers, input it refuses, large input and the engine's verdict."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from policies import entropykit as kit
from policies import gatekit, scriptkit

gate = kit.load()
values = gate.values
V = kit.secret(21)
PRAGMA = "# pragma: allowlist " + "secret"


def found(writes: dict[str, str], event: str = "commit") -> list[dict]:
    return gate.findings({"event": event, "writes": writes})


def run(stdin: str, cwd: Path) -> tuple[int, str, str]:
    proc = scriptkit.run_script_full(kit.POLICY, kit.NAME, cwd, stdin)
    return proc.returncode, proc.stdout, proc.stderr


def test_a_finding_is_keyed_by_rule_and_value_digest_and_never_carries_the_value() -> None:
    (row,) = found({"conf/app.ini": f"x=1\nclient_secret = {V}\n"})
    assert row["rule"] == "entropy"
    assert re.fullmatch(r"entropy\|[0-9a-f]{16}", row["key"])
    assert (row["path"], row["line"]) == ("conf/app.ini", 2)
    assert V not in json.dumps(row)
    assert "'client_secret'" in row["message"]


def test_the_same_value_moved_keeps_its_key_and_another_value_does_not() -> None:
    (first,) = found({"a.env": f"client_secret={V}\n"})
    (moved,) = found({"a.env": f"\n\nclient_secret={V}\n"})
    (other,) = found({"a.env": f"client_secret={kit.secret(22)}\n"})
    assert first["key"] == moved["key"] != other["key"]


def test_findings_come_in_line_order_across_rules_and_paths() -> None:
    text = f"cardNum: {kit.luhn_number(5)}\nclient_secret={V}\nsee {kit.crc_token(3)}\n"
    rows = found({"b.txt": text, "a.txt": text})
    assert [(r["path"], r["line"], r["rule"]) for r in rows] == [
        ("a.txt", 1, "card-number"),
        ("a.txt", 2, "entropy"),
        ("a.txt", 3, "checksum"),
        ("b.txt", 1, "card-number"),
        ("b.txt", 2, "entropy"),
        ("b.txt", 3, "checksum"),
    ]


def test_a_windows_path_is_reported_with_forward_slashes() -> None:
    assert found({"conf\\app.env": f"client_secret={V}\n"})[0]["path"] == "conf/app.env"


def test_utf16_text_and_a_stray_nul_hide_nothing_but_binary_content_is_not_judged() -> None:
    utf16 = f"client_secret={V}\n".encode("utf-16-le").decode("latin-1")
    assert [r["rule"] for r in found({"conf.reg": utf16})] == ["entropy"]
    padded = "# settings\n" * 20 + f"client_secret={V}\n\x00"
    assert [r["rule"] for r in found({"app.env": padded})] == ["entropy"]
    blob = bytes(range(256)).decode("utf-8", "replace") + f"client_secret={V}\n"
    assert found({"logo.png": blob}) == []


@pytest.mark.parametrize(("event", "kept"), [("commit", 0), ("push", 0), ("ci", 0), ("agent-commit", 1),
                                              ("tool_use", 1), ("stop", 1), (None, 1)])  # fmt: skip
def test_the_pragma_is_honoured_only_where_a_person_is_the_actor(event: str | None, kept: int) -> None:
    payload = {"writes": {"a.env": f"client_secret={V}  {PRAGMA}\n"}}
    if event:
        payload["event"] = event
    assert len(gate.findings(payload)) == kept


def test_the_pragma_waives_only_its_own_line() -> None:
    rows = found({"a.env": f"client_secret={V}  {PRAGMA}\nclient_secret={kit.secret(23)}\n"})
    assert [r["line"] for r in rows] == [2]


@pytest.mark.parametrize("payload", [{}, {"writes": []}, {"writes": {"a": 1}}, {"writes": "a"}])
def test_a_payload_that_is_not_the_gate_json_raises(payload: dict) -> None:
    with pytest.raises(ValueError, match="writes"):
        gate.findings(payload)


@pytest.mark.parametrize("stdin", ["not json", "[1, 2]", '{"writes": {"a": null}}', '{"event": "commit"}'])
def test_input_it_cannot_judge_exits_2_with_a_reason(tmp_path: Path, stdin: str) -> None:
    code, out, err = run(stdin, tmp_path)
    assert code == 2
    assert out == ""
    assert "cannot judge" in err


def test_a_clean_write_exits_0_with_an_empty_document(tmp_path: Path) -> None:
    code, out, _ = run(json.dumps({"event": "commit", "writes": {"a.txt": "hello\n"}}), tmp_path)
    assert (code, json.loads(out)) == (0, {"findings": []})


def test_a_finding_exits_ask_and_the_value_is_printed_nowhere(tmp_path: Path) -> None:
    token = kit.crc_token(4)
    writes = {"app/settings.env": f"client_secret={V}\nnote {token}\n"}
    code, out, err = run(json.dumps({"event": "tool_use", "writes": writes}), tmp_path)
    assert code == 3
    assert [f["rule"] for f in json.loads(out)["findings"]] == ["entropy", "checksum"]
    assert "app/settings.env:1: high-entropy value" in err
    assert "app/settings.env:2: github token" in err
    assert "never writes the pragma" in err
    assert V not in out + err
    assert token not in out + err


def test_text_is_fed_in_chunks_of_whole_lines_and_windows_of_long_lines() -> None:
    chunk, overlap = values.CHUNK, values.OVERLAP
    pieces = list(values.chunks(["a" * (chunk // 2), "b" * (chunk // 2), "c", "d" * (chunk + 10), "e"]))
    assert [(first, len(text), limit, offset) for first, text, limit, offset in pieces] == [
        (0, chunk // 2, None, 0),
        (1, chunk // 2 + 2, None, 0),
        (3, chunk, chunk - overlap + values.HANDOFF, 0),
        (3, overlap + 10, None, chunk - overlap),
        (4, 1, None, 0),
    ]
    assert [p[0] for p in values.chunks(["x" * chunk])] == [0]


def test_a_secret_after_the_first_mebibyte_of_lines_is_found_on_its_own_line() -> None:
    filler = ["# " + "w" * 98] * 12000
    rows = found({"big.cfg": "\n".join([*filler, f"client_secret={V}", ""])})
    assert [(r["line"], r["rule"]) for r in rows] == [(12001, "entropy")]


@pytest.mark.parametrize("delta", [-700, -600, -530, -400, -151, -20, 0, 20, 300, 600, 1000])
def test_a_secret_on_a_long_minified_line_is_found_once_wherever_a_window_cuts(delta: int) -> None:
    step = values.CHUNK - values.OVERLAP
    at = step + values.HANDOFF + delta
    line = "x" * at + f',"client_secret":"{V}",' + "y" * (values.CHUNK + 5000)
    rows = found({"bundle.min.js": "var a=1;\n" + line + "\n"})
    assert [(r["line"], r["rule"]) for r in rows] == [(2, "entropy")]


def test_a_secret_near_the_end_of_a_long_line_is_found() -> None:
    line = "z" * (values.CHUNK * 2) + f" client_secret={V}"
    assert [r["rule"] for r in found({"blob.txt": line})] == ["entropy"]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    held = f"client_secret={V}\nother=1\n"
    waived = f"client_secret={kit.secret(24)}  {PRAGMA}\n"
    return scriptkit.init_repo(tmp_path / "r", {"held.env": held, "waived.env": waived})


def engine(repo: Path, writes: dict[str, str], event: str) -> int:
    if event in (gatekit.STOP, gatekit.COMMIT):
        scriptkit.write(repo, writes)
    if event == gatekit.COMMIT:
        scriptkit.git(repo, "add", "-A")
    return gatekit.judge(kit.POLICY, repo, event, writes)[0]


@pytest.mark.parametrize(("event", "code"), [(gatekit.COMMIT, 1), (gatekit.PRE_TOOL_USE, 3), (gatekit.STOP, 4)])
def test_the_engine_asks_on_a_new_secret(repo: Path, event: str, code: int) -> None:
    writes = {"new.env": f"client_secret={kit.secret(25)}\n"}
    if event != gatekit.PRE_TOOL_USE:
        scriptkit.write(repo, writes)
        scriptkit.git(repo, "add", "-A")
    verdict, err = gatekit.judge(kit.POLICY, repo, event, writes)
    assert verdict == code
    assert "new.env:1: high-entropy value" in err


@pytest.mark.parametrize("event", [gatekit.COMMIT, gatekit.PRE_TOOL_USE, gatekit.STOP])
def test_a_secret_already_at_head_does_not_hold_up_an_unrelated_edit(repo: Path, event: str) -> None:
    assert engine(repo, {"held.env": f"other=2\nclient_secret={V}\n"}, event) == 0


def test_a_second_copy_of_a_held_secret_is_new(repo: Path) -> None:
    assert engine(repo, {"held.env": f"client_secret={V}\nclient_secret={V}\n"}, gatekit.STOP) == 4


def test_an_agent_cannot_waive_a_new_secret_with_the_pragma(repo: Path) -> None:
    text = f"client_secret={kit.secret(26)}  {PRAGMA}\n"
    assert engine(repo, {"new.env": text}, gatekit.PRE_TOOL_USE) == 3


def test_a_pragma_line_a_person_committed_stays_waived_for_the_agent(repo: Path) -> None:
    text = (repo / "waived.env").read_text(encoding="utf-8") + "debug=true\n"
    assert engine(repo, {"waived.env": text}, gatekit.PRE_TOOL_USE) == 0


def test_the_policy_asks_and_the_script_asks() -> None:
    spec = gatekit.gate_spec(kit.POLICY)
    assert (spec["kind"], spec["action"], spec["on"]) == ("script", "ask", ["commit", "tool_use"])
    assert gate.EXIT_ASK == 3
    assert scriptkit.manifest(kit.POLICY)["enforcement"] == "block"
