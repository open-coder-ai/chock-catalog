"""registry.yaml's labels are derived from agentseam's data and the manifests, and never overclaim."""

from __future__ import annotations

import json
import re

import check_registry
import pytest
import yaml
from agentseam.vendor_config import VENDOR_CONFIG
from chock import vendors
from chock.plugin import bundle_build
from label_honesty import status_label
from mechanism import NONE, classify
from trees import ROOT, policy_dirs

ROWS = {p["id"]: p for p in yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))["policies"]}
CLIENTS = (
    ("claude-code", "claude"),
    ("cursor", "cursor"),
    ("codex", "codex"),
    ("copilot", "copilot"),
    ("devin", "devin"),
)
DRAFT = re.compile(r"\bdraft\b", re.IGNORECASE)


def _manifest(pid: str) -> dict:
    return yaml.safe_load((ROOT / ROWS[pid]["path"] / "manifest.yaml").read_text(encoding="utf-8"))


@pytest.mark.parametrize(("key", "fmt"), CLIENTS)
def test_a_label_asks_only_where_the_client_can_prompt(key: str, fmt: str) -> None:
    agent = bundle_build.CLIENTS[fmt].agent
    honours = VENDOR_CONFIG[agent]["verdicts"]["gates"][vendors.pre_tool_event(agent)]["honours_escalate"]
    for pid, row in ROWS.items():
        if row["label"][key]["keyword"] == "ask":
            assert honours, f"{pid} says it asks on {key}, which cannot prompt at its pre-tool event"


def test_cursor_and_codex_refuse_what_claude_asks() -> None:
    for pid in ("protect-ci-workflows", "scan-suppression-markers", "scan-secrets-entropy"):
        label = ROWS[pid]["label"]
        assert label["claude-code"]["keyword"] == "ask"
        assert label["cursor"]["keyword"] == label["codex"]["keyword"] == "block"
        assert "asks" not in label["cursor"]["says"] + label["codex"]["says"]


def test_devin_has_a_key_that_says_it_fails_open() -> None:
    hooked = [r["label"]["devin"]["says"] for r in ROWS.values() if r["label"]["devin"]["keyword"] != "advise"]
    assert hooked
    assert all("fails open" in says for says in hooked)


def test_every_row_carries_its_manifests_lifecycle_status() -> None:
    for pid, row in ROWS.items():
        assert row["status"] == _manifest(pid)["lifecycle"]["status"]
    assert ROWS["rtk-dangerous-actions-blocker"]["label"]["status"]["says"].startswith("deprecated")


def test_only_a_deprecated_policy_carries_a_status_badge() -> None:
    for pid, row in ROWS.items():
        badge = row["label"].get("status")
        assert (badge is not None) == (row["status"] == "deprecated"), pid
        assert badge is None or badge["keyword"] == "deprecated"
    assert status_label({"lifecycle": {"status": "draft"}}) is None
    assert status_label({"lifecycle": {"status": "production"}}) is None


def test_no_generated_reader_facing_file_says_draft() -> None:
    files = [ROOT / "README.md", ROOT / "llms.txt", *ROOT.glob("docs/*/README.md")]
    for policy_dir in policy_dirs():
        files += [policy_dir / "plugin.json", *policy_dir.glob("skills/*/SKILL.md")]
    said = [
        f.relative_to(ROOT).as_posix() for f in files if f.is_file() and DRAFT.search(f.read_text(encoding="utf-8"))
    ]
    said += [f"registry.yaml label of {pid}" for pid, row in ROWS.items() if DRAFT.search(json.dumps(row["label"]))]
    assert said == []


def test_a_policy_whose_enforcement_no_plugin_carries_is_text_only() -> None:
    text_only = {
        pid for pid, row in ROWS.items() if row["label"]["claude-code"]["says"].startswith("text only in a plugin")
    }
    declared = {
        d.name for d in policy_dirs() if classify(d, yaml.safe_load((d / "manifest.yaml").read_text()))[0] != NONE
    }
    assert text_only == {"protect-main-branch", "limit-diff-size", "firecrawl-fallback-only", "token-efficiency"}
    assert text_only <= declared
    for pid in text_only:
        assert all(v["keyword"] == "advise" for k, v in ROWS[pid]["label"].items() if k not in {"misses", "status"})


def test_dated_data_states_its_date_and_that_reinstalling_updates_it() -> None:
    for pid in ("compromised-package-ioc", "verify-mcp-allowlist"):
        data = ROWS[pid]["label"]["data"]
        assert data["as_of"] in data["says"]
        assert "re-running the install is the update" in data["says"]
    assert sum("data" in r["label"] for r in ROWS.values()) == 2


def test_a_catalog_policy_cannot_take_the_user_prefix(monkeypatch, capsys) -> None:
    assert check_registry.reserved_ids(["my-policy", "mystery", "scan-secrets", "my-"]) == ["my-", "my-policy"]
    real = check_registry.entries_on_disk
    monkeypatch.setattr(check_registry, "entries_on_disk", lambda: {**real(), "my-extra": "base/my-extra"})
    assert check_registry.main() == 1
    assert "reserved for user policies: my-extra" in capsys.readouterr().out


def test_no_published_policy_uses_the_user_prefix() -> None:
    assert check_registry.reserved_ids(list(ROWS)) == []
