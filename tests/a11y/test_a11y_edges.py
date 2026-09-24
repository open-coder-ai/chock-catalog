"""The a11y guard's paths its two checkers do not reach: undecidable components, git failing,
and a file the parser cannot read at commit time."""

from __future__ import annotations

import check_a11y_rules as rules
import pytest

GUARD = rules.load_guard()
WIDGET = '<Widget data-testid="w" aria-label="Close" />'


def _keys(before: str, after: str) -> list[tuple[tuple[str, str], str]]:
    return [(row["key"], row["action"]) for row in GUARD.evaluate(before, after)]


@pytest.mark.parametrize("source", [None, "", "div", "plain text"])
def test_is_component_is_false_without_a_component_tag(source: str | None) -> None:
    assert GUARD.is_component(source) is False


def test_a_spread_component_is_undecidable_so_the_guard_stays_silent() -> None:
    assert _keys(WIDGET, '<Widget data-testid="w" {...props} />') == [
        ((GUARD.SATISFIED, GUARD.UNEVALUATED), GUARD.SILENT)
    ]


def test_hiding_a_named_component_is_refused() -> None:
    assert _keys(WIDGET, '<Widget data-testid="w" aria-hidden="true" />') == [
        ((GUARD.SATISFIED, GUARD.SUPPRESSED), GUARD.DENY)
    ]


def test_git_failing_reads_as_no_content() -> None:
    assert GUARD._git("show", "HEAD:no/such/path.html") == ""


def test_a_file_the_parser_cannot_read_is_skipped_not_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def unreadable(before: str, after: str) -> list[dict]:
        raise ValueError(before + after)

    monkeypatch.setattr(GUARD, "staged_markup", lambda: ["page.html"])
    monkeypatch.setattr(GUARD, "_git", lambda *_args: "<p>")
    monkeypatch.setattr(GUARD, "evaluate", unreadable)
    assert GUARD.main() == 0
    assert "skipped page.html: ValueError" in capsys.readouterr().err
