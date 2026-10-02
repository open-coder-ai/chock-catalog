"""The shipped gate, per tier: silence refuses a security finding and lets a quality finding through (D2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from chock_security.decision import ALLOW, ASK, DENY
from java_security.conftest import GateRun

EMPTY_CATCH = "void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n  }\n}\n"
UNESCAPED = '<p th:utext="${bio}"></p>\n'
REFUSE, PASS = 1, 0


@pytest.fixture(autouse=True)
def _no_user_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A home with no ~/.chock/security.json, so only what each test writes governs."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def test_a_quality_finding_with_no_selection_passes(gate: GateRun) -> None:
    assert gate({"E.java": EMPTY_CATCH}) == (PASS, "")


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_a_security_finding_with_no_selection_is_still_refused(gate: GateRun, event: str) -> None:
    code, err = gate({"p.html": UNESCAPED, "E.java": EMPTY_CATCH}, event=event)
    assert code == REFUSE
    assert "java-xss-unescaped-template" in err
    assert "exceptions-empty-catch" not in err


def test_a_security_finding_under_a_selection_silent_on_its_pack_is_refused(gate: GateRun) -> None:
    code, _ = gate({"p.html": UNESCAPED}, {"version": 2, "packs": {"bugs": {"verdict": ALLOW}}})
    assert code == REFUSE


@pytest.mark.parametrize(
    "selection",
    [
        {"version": 2, "packs": {"exceptions": {"verdict": DENY}}},
        {"version": 2, "packs": {"exceptions": {"rules": {"exceptions-empty-catch": DENY}}}},
        {"version": 2, "packs": {"exceptions": {"verdict": ASK}}},
    ],
    ids=["pack-deny", "rule-deny", "pack-ask"],
)
def test_a_selection_that_spells_a_quality_verdict_keeps_it(gate: GateRun, selection: dict) -> None:
    code, err = gate({"E.java": EMPTY_CATCH}, selection)
    assert code == REFUSE
    assert "exceptions-empty-catch" in err


def test_a_user_level_selection_still_spells_quality_verdicts(gate: GateRun, tmp_path: Path) -> None:
    home = tmp_path / "home" / ".chock"
    home.mkdir(parents=True)
    (home / "security.json").write_text('{"version": 2, "packs": {"exceptions": {"verdict": "deny"}}}')
    assert gate({"E.java": EMPTY_CATCH})[0] == REFUSE


SWALLOWED_TRUST_CHECK = (
    "public class T implements X509TrustManager {\n"
    "  public void checkServerTrusted(X509Certificate[] c, String a) {\n"
    "    try {\n      d.checkServerTrusted(c, a);\n    } catch (CertificateException e) {\n    }\n"
    "  }\n}\n"
)


def test_known_limit_a_swallowed_security_check_needs_the_exceptions_pack_spelled(gate: GateRun) -> None:
    """Documented in the 0.7.0 changelog: only the quality rule exceptions-empty-catch sees this."""
    assert gate({"T.java": SWALLOWED_TRUST_CHECK})[0] == PASS
    code, err = gate({"T.java": SWALLOWED_TRUST_CHECK}, {"version": 2, "packs": {"exceptions": {"verdict": DENY}}})
    assert code == REFUSE
    assert "exceptions-empty-catch" in err
