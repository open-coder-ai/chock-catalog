"""tools/check_promotion.py: a policy is production only with a measurement on record that meets the bar."""

from __future__ import annotations

import copy
import json
import runpy
import sys
from pathlib import Path

import check_promotion as cp
import pytest
from build_tools.selkit import write
from trees import ROOT

SCHEMA = json.loads((ROOT / cp.FOLDER / "record.schema.json").read_text(encoding="utf-8"))
SHA = "a" * 40
#: The 25 policies production on 2026-11-28 (R13-4): pending.json may lose names from it, never gain one.
GRANDFATHERED = {
    "agent-permissions-scan", "ask-credential-switching", "block-curl-pipe-sh", "block-destructive-commands",
    "block-hook-bypass-in-files", "block-invisible-unicode", "block-no-verify", "block-persistence-shapes",
    "block-secret-store-reads", "block-unapproved-egress", "block-unguarded-agent-spawn",
    "block-unpinned-agent-components", "block-wildcard-agent-permissions", "dockerfile-compose-security",
    "iam-policy-scan", "pin-github-actions", "protect-agent-config", "protect-ci-workflows",
    "protect-commit-privacy", "protect-main-branch", "scan-secret-files", "scan-secrets",
    "scan-secrets-entropy", "verify-dependency-exists", "verify-mcp-allowlist",
}  # fmt: skip


def entry(verdict: str = "correct_work", reason: str = "a fixture") -> dict:
    return {"repo": "r/a", "commit": SHA, "path": "t.py", "rule": "", "verdict": verdict, "reason": reason}


def record(**over: object) -> dict:
    """A record that meets the bar: 40 commits judged, two fires judged correct work, every case right."""
    base = {
        "policy": "demo",
        "version": "1.0.0",
        "engine": SHA,
        "catalog": SHA,
        "date": "2026-11-28",
        "corpora": [{"repo": "r/a", "commits": 50, "judged": 40, "fires": 2}],
        "triage": [entry(), entry("true_catch")],
        "eval": {"block": {"caught": 3, "total": 3}, "allow": {"allowed": 2, "total": 2}},
        "misses": {"read": True, "listed": 4},
        "correct_work_rate": None,
        "bar_met": False,
    }
    return cp.settle(base | over)


def defects(rec: dict, version: str = "1.0.0") -> list[str]:
    return cp.defects(rec, "demo", version, SCHEMA)


def test_a_record_inside_the_bar_holds() -> None:
    rec = record()
    assert (rec["correct_work_rate"], rec["bar_met"]) == (0.025, True)
    assert defects(rec) == []


def test_five_percent_exactly_is_inside_the_bar_and_a_hair_over_is_not() -> None:
    corpora = [{"repo": "r/a", "commits": 50, "judged": 40, "fires": 2}]
    two = [entry(), entry()]
    assert record(triage=two)["bar_met"] is True
    assert record(triage=two, corpora=[{**corpora[0], "judged": 39}])["bar_met"] is False


def test_a_missed_bar_is_reported_with_its_rate() -> None:
    rec = record(triage=[entry()] * 4, corpora=[{"repo": "r/a", "commits": 50, "judged": 40, "fires": 4}])
    assert rec["correct_work_rate"] == 0.1
    assert defects(rec) == ["does not meet the bar"]


@pytest.mark.parametrize(
    "over",
    [
        {"eval": {"block": {"caught": 2, "total": 3}, "allow": {"allowed": 2, "total": 2}}},
        {"eval": {"block": {"caught": 3, "total": 3}, "allow": {"allowed": 1, "total": 2}}},
        {"eval": {"block": {"caught": 0, "total": 0}, "allow": {"allowed": 2, "total": 2}}},
        {"eval": {"block": {"caught": 3, "total": 3}, "allow": {"allowed": 0, "total": 0}}},
        {"misses": {"read": False, "listed": 4}},
    ],
)
def test_an_authored_case_wrong_or_missing_or_an_unread_misses_sentence_fails_the_bar(over: dict) -> None:
    assert record(**over)["bar_met"] is False
    assert defects(record(**over)) == ["does not meet the bar"]


def test_nothing_judged_has_no_rate_and_no_bar() -> None:
    rec = record(triage=[], corpora=[{"repo": "r/a", "commits": 0, "judged": 0, "fires": 0}])
    assert (rec["correct_work_rate"], rec["bar_met"]) == (None, False)


def test_an_unjudged_fire_has_no_rate_and_is_named() -> None:
    rec = record(triage=[entry(), entry("", "")])
    assert (rec["correct_work_rate"], rec["bar_met"]) == (None, False)
    assert "has 1 fire(s) without a verdict" in defects(rec)


def test_a_verdict_without_a_reason_is_refused() -> None:
    assert "has a verdict without a reason" in defects(record(triage=[entry(reason=" "), entry("true_catch")]))


def test_a_rate_or_bar_the_numbers_do_not_give_is_refused() -> None:
    assert "states a rate or bar_met that its numbers do not give" in defects(record() | {"bar_met": False})
    assert "states a rate or bar_met that its numbers do not give" in defects(record() | {"correct_work_rate": 0.0})


def test_a_record_for_another_version_or_policy_is_refused() -> None:
    assert defects(record(), version="1.0.1") == ["is for version 1.0.0, the manifest is 1.0.1"]
    assert defects(record(policy="other")) == ["names policy 'other'"]


@pytest.mark.parametrize(
    ("over", "said"),
    [
        ({"triage": [entry()]}, "differs from the fires"),
        ({"triage": [{**entry(), "repo": "r/zz"}, entry()]}, "did not replay"),
        ({"corpora": [{"repo": "r/a", "commits": 30, "judged": 40, "fires": 2}]}, "judged more commits"),
        ({"eval": {"block": {"caught": 4, "total": 3}, "allow": {"allowed": 2, "total": 2}}}, "more eval cases"),
    ],
)
def test_counts_that_do_not_add_up_are_named(over: dict, said: str) -> None:
    assert any(said in d for d in defects(record(**over)))


def test_a_corpus_listed_twice_is_refused() -> None:
    twice = [{"repo": "r/a", "commits": 50, "judged": 20, "fires": 1}] * 2
    assert any("lists a corpus twice" in d for d in defects(record(corpora=twice)))


def test_a_record_that_does_not_fit_the_schema_is_refused_without_a_traceback() -> None:
    broken = copy.deepcopy(record())
    del broken["engine"]
    broken["triage"][0]["verdict"] = "fine"
    (only,) = defects(broken)
    assert only.startswith("does not validate: ")
    assert "'engine' is a required property" in only


def test_the_empty_verdict_a_fresh_record_carries_validates() -> None:
    fresh = record(triage=[entry("", "")])
    assert not [d for d in defects(fresh) if d.startswith("does not validate")]


def catalog(tmp_path: Path, status: str = "production", pending: tuple[str, ...] = ()) -> Path:
    write(tmp_path, "base/demo/manifest.yaml", f'id: demo\nversion: "1.0.0"\nlifecycle:\n  status: {status}\n')
    write(tmp_path, "base/drafty/manifest.yaml", 'id: drafty\nversion: "0.1.0"\nlifecycle:\n  status: draft\n')
    write(tmp_path, "base/bare/manifest.yaml", 'id: bare\nversion: "0.1.0"\n')
    folder = tmp_path / cp.FOLDER
    write(tmp_path, f"{cp.FOLDER}/record.schema.json", json.dumps(SCHEMA))
    write(tmp_path, f"{cp.FOLDER}/pending.json", json.dumps({"pending": list(pending)}))
    assert folder.is_dir()
    return tmp_path


def put(root: Path, rec: dict, name: str = "demo") -> None:
    write(root, f"{cp.FOLDER}/{name}.json", json.dumps(rec))


def test_only_production_policies_are_listed_with_their_versions(tmp_path: Path) -> None:
    assert cp.production(catalog(tmp_path)) == {"demo": "1.0.0"}
    assert cp.production(catalog(tmp_path / "x", status="draft")) == {}


def test_a_production_policy_with_a_record_that_holds_passes(tmp_path: Path) -> None:
    root = catalog(tmp_path)
    put(root, record())
    assert cp.check(root) == []
    assert cp.main(["--root", str(root)]) == 0


def test_a_production_policy_with_no_record_and_not_pending_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    root = catalog(tmp_path)
    assert cp.check(root) == ["demo is production with no record: run measure_false_positives.py --record demo"]
    assert cp.main(["--root", str(root)]) == 1
    assert "no record" in capsys.readouterr().out


def test_a_pending_policy_needs_no_record_but_may_not_have_one(tmp_path: Path) -> None:
    root = catalog(tmp_path, pending=("demo",))
    assert cp.check(root) == []
    put(root, record())
    assert cp.check(root) == ["demo has a record: remove it from pending.json"]


def test_pending_may_name_only_production_policies(tmp_path: Path) -> None:
    root = catalog(tmp_path, pending=("demo", "drafty", "ghost"))
    assert cp.check(root) == [
        "pending.json lists drafty, which is not a production policy",
        "pending.json lists ghost, which is not a production policy",
    ]


def test_a_stale_record_fails_with_the_policy_named(tmp_path: Path) -> None:
    root = catalog(tmp_path)
    put(root, record(version="0.9.0"))
    assert cp.check(root) == ["demo: record is for version 0.9.0, the manifest is 1.0.0"]


def test_settle_rewrites_the_rate_and_the_bar_from_the_verdicts(tmp_path: Path) -> None:
    root = catalog(tmp_path)
    put(root, record() | {"correct_work_rate": None, "bar_met": False})
    assert cp.main(["--settle", "demo", "--root", str(root)]) == 0
    saved = json.loads((root / cp.FOLDER / "demo.json").read_text(encoding="utf-8"))
    assert (saved["correct_work_rate"], saved["bar_met"]) == (0.025, True)


def test_this_repos_records_hold(capsys: pytest.CaptureFixture) -> None:
    assert cp.main([]) == 0
    assert "production policies: records hold" in capsys.readouterr().out


def test_the_pending_list_only_shrinks() -> None:
    pending = json.loads((ROOT / cp.FOLDER / "pending.json").read_text(encoding="utf-8"))["pending"]
    assert pending == sorted(pending)
    assert set(pending) <= GRANDFATHERED, (
        f"a new production policy ships with a record: {sorted(set(pending) - GRANDFATHERED)}"
    )


def test_every_record_here_names_the_policy_it_is_filed_under() -> None:
    files = [p for p in (ROOT / cp.FOLDER).glob("*.json") if p.name not in {"pending.json", "record.schema.json"}]
    assert files
    assert all(json.loads(p.read_text(encoding="utf-8"))["policy"] == p.stem for p in files)


def test_running_the_file_as_a_script_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["check_promotion.py"])
    with pytest.raises(SystemExit) as stop:
        runpy.run_path(cp.__file__, run_name="__main__")
    assert stop.value.code == 0
