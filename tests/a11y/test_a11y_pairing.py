"""How the guard pairs two revisions: through insertions, a changed `src`, duplicate keys, a rename, and size."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import check_a11y_rules as rules
import pytest

GUARD = rules.load_guard()
NAMED = '<img src="/img/a.png" alt="Team at the summit">\n'
BARE = '<img src="/img/a.png">\n'
LEGACY = '<button type="button" class="legacy"></button>\n'
#: The review's timing table: N rows, each a named image and a text cell; 2000, 10000 and 40000 rows.
ROW = '<tr><td><img src="/img/{n}.png" alt="Revenue chart for {n}"></td><td>Region {n} revenue (USD)</td></tr>\n'


def _actions(before: str, after: str) -> list[tuple[str, str]]:
    return [(row["ref"], row["action"]) for row in GUARD.evaluate(before, after) if row["action"] != GUARD.SILENT]


def _table(rows: int) -> str:
    return "<table>\n" + "".join(ROW.format(n=n) for n in range(rows)) + "</table>\n"


def test_an_inserted_element_shifts_no_later_one() -> None:
    before = f'<button class="a" aria-label="A"></button>\n{LEGACY}'
    after = f'<button class="b" aria-label="B"></button>\n{before}'
    assert _actions(before, after) == []


def test_a_deleted_element_shifts_no_later_one() -> None:
    before = f'<button class="a" aria-label="A"></button>\n{LEGACY}'
    assert _actions(before, LEGACY) == []


def test_a_deleted_named_element_does_not_hide_the_next_one_losing_its_name() -> None:
    before = '<button class="legacy-dot"></button>\n<button class="next" aria-label="Next"></button>\n'
    assert _actions(before, '<button class="next"></button>\n') == [("button:1", "deny"), ("button:1", "deny")]


def test_a_changed_src_is_the_same_element() -> None:
    assert _actions(NAMED, '<img src="/img/a.webp" alt="">\n') == [("img[src=/img/a.webp]", "deny")]
    assert _actions(BARE, '<img src="/img/b.png">\n') == []


def test_a_changed_href_is_the_same_element() -> None:
    assert _actions('<a href="/a" aria-label="Home">x</a>', '<a href="/b" aria-label="Home">x</a>') == []
    assert _actions('<a href="/a"><img src="/i.png" alt="Home"></a>', '<a href="/b"><img src="/i.png"></a>') == [
        ("a[href=/b]", "deny"),
        ("img[src=/i.png]", "deny"),
    ]


def test_two_elements_with_one_key_are_both_kept() -> None:
    other = '<img src="/img/a.png" alt="Second view">\n'
    assert _actions(NAMED + other, BARE + other) == [("img[src=/img/a.png]", "deny")]
    assert _actions(NAMED + other, NAMED + BARE) == [("img[src=/img/a.png]", "deny")]


def test_a_stretch_replaced_in_full_pairs_by_tag_order() -> None:
    before = NAMED + '<button aria-label="Close"></button>\n'
    after = '<img src="/b.png">\n<button class="x"></button>\n'
    assert _actions(before, after) == [("img[src=/b.png]", "deny"), ("button:1", "deny")]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for args in (("init", "--quiet", "."), ("config", "user.email", "t@chock.invalid"), ("config", "user.name", "t")):
        subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, check=True)  # noqa: S607 -- fixed argv
    return tmp_path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)  # noqa: S607 -- fixed argv


def _commit(repo: Path, name: str, text: str) -> None:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "--quiet", "--no-verify", "-m", f"add {name}")


def _judge(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(rules.GUARD)], cwd=repo, capture_output=True, text=True, check=False)


PAGE = '<!doctype html>\n<html lang="en">\n<head><title>Acme</title></head>\n<body>\n{body}</body>\n</html>\n'


def test_a_renamed_compliant_file_is_silent_at_commit(repo: Path) -> None:
    """N27."""
    page = PAGE.format(body='<h1>Pricing</h1>\n<img src="/img/plans.png" alt="Comparison of the three plans">\n')
    _commit(repo, "pricing.html", page)
    (repo / "plans").mkdir()
    _git(repo, "mv", "pricing.html", "plans/index.html")
    done = _judge(repo)
    assert (done.returncode, done.stderr) == (0, "")


def test_a_renamed_file_with_a_legacy_unnamed_image_is_silent_at_commit(repo: Path) -> None:
    """N28: the unnamed image nobody touched is not a new element, so it does not even warn."""
    page = PAGE.format(body='<div><img src="/img/logo.png" alt="Acme"><img src="/img/old-banner.png"></div>\n')
    _commit(repo, "legacy.html", page)
    (repo / "archive").mkdir()
    _git(repo, "mv", "legacy.html", "archive/legacy.html")
    done = _judge(repo)
    assert (done.returncode, done.stderr) == (0, "")


def test_a_rename_that_also_loses_a_name_is_refused(repo: Path) -> None:
    _commit(repo, "pricing.html", PAGE.format(body=NAMED))
    _git(repo, "mv", "pricing.html", "plans.html")
    (repo / "plans.html").write_text(PAGE.format(body='<img src="/img/a.png" alt="">\n'), encoding="utf-8")
    _git(repo, "add", "plans.html")
    done = _judge(repo)
    assert done.returncode == 1
    assert "plans.html: img[src=/img/a.png]" in done.stderr


def test_a_file_renamed_into_markup_from_another_suffix_has_no_old_revision(repo: Path) -> None:
    _commit(repo, "page.txt", NAMED)
    _git(repo, "mv", "page.txt", "page.html")
    (repo / "page.html").write_text(BARE, encoding="utf-8")
    _git(repo, "add", "page.html")
    done = _judge(repo)
    assert (done.returncode, "warning: page.html" in done.stderr) == (0, True)


def test_a_path_with_spaces_and_a_tab_pairs_with_its_old_path(repo: Path) -> None:
    old, new = "my page.html", "new\tpage.html"
    _commit(repo, old, PAGE.format(body=NAMED))
    _git(repo, "mv", old, new)
    (repo / new).write_text(PAGE.format(body=BARE), encoding="utf-8")
    _git(repo, "add", new)
    assert _judge(repo).returncode == 1


@pytest.mark.parametrize("rows", [2000, 10000, 40000])
def test_a_file_of_the_review_timing_sizes_gets_its_verdict_inside_the_budget(rows: int) -> None:
    before = _table(rows)
    started = time.monotonic()
    found = GUARD.evaluate(before, before + "<!-- end -->\n")
    assert time.monotonic() - started < 30
    assert [r for r in found if r["action"] != GUARD.SILENT] == []


def test_a_lost_name_in_a_large_file_is_still_found() -> None:
    before = _table(10000)
    after = before.replace('alt="Revenue chart for 5000"', "")
    found = GUARD.evaluate(before, after)
    assert [r["ref"] for r in found if r["action"] == GUARD.DENY] == ["img[src=/img/5000.png]"]


def test_a_stretch_too_long_to_align_is_paired_by_tag_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(GUARD, "ALIGN_LIMIT", 4)
    before = "".join(f'<img src="/{n}.png" alt="Picture {n}">\n' for n in range(6))
    after = "".join(f'<img src="/{n}.webp" alt="Picture {n}">\n' for n in range(6)).replace(' alt="Picture 3"', "")
    assert _actions(before, after) == [("img[src=/3.webp]", "deny")]


def test_a_long_file_is_trimmed_at_both_ends_and_the_middle_edit_is_judged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(GUARD, "ALIGN_LIMIT", 4)
    before = "".join(f'<img src="/{n}.png" alt="Picture {n}">\n' for n in range(6))
    after = before.replace('src="/3.png" alt="Picture 3"', 'src="/3.webp"')
    assert _actions(before, after) == [("img[src=/3.webp]", "deny")]
