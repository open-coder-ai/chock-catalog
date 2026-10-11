"""tools/regen_run.py: steps run without a shell, and output any console can print."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import regen_run
from regen_run import Result


def test_run_takes_an_argv_a_function_or_a_shell_string(tmp_path: Path) -> None:
    assert regen_run.run("argv", [sys.executable, "-c", "print('hi')"]).out == "hi"
    assert regen_run.run("function", lambda: (4, "said"))[1:2] == (4,)
    failed = regen_run.run("shell", "echo out; echo err >&2; exit 3", cwd=tmp_path)
    assert (failed.rc, failed.out) == (3, "out\nerr")


def test_a_failure_prints_the_tail_of_its_output(capsys) -> None:
    assert regen_run.report(Result("good", 0, 1.0, "hidden")) == 0
    assert regen_run.report(Result("bad", 2, 1.0, "shown")) == 2
    out = capsys.readouterr().out
    assert "hidden" not in out
    assert "FAIL" in out
    assert "        shown" in out


def test_child_output_the_console_cannot_encode_is_replaced_not_raised(monkeypatch) -> None:
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    child = regen_run.run("child", [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'bad \\xff byte')"])
    assert "\ufffd" in child.out
    assert regen_run.report(Result("transcript", 1, 0.0, child.out)) == 1
    sys.stdout.flush()
    assert b"bad ? byte" in raw.getvalue()


def test_children_print_utf8_whatever_the_console_encoding() -> None:
    assert regen_run.CHILD_ENV["PYTHONIOENCODING"] == "utf-8"
    assert regen_run.run("child", [sys.executable, "-c", "print('\u2192 \u00e9')"]).out == "\u2192 \u00e9"


def test_figures_run_without_a_shell_and_stop_at_a_failure(tmp_path: Path) -> None:
    (tmp_path / "make_a.py").write_text("open('a.svg', 'w').write('a'); print('wrote a')", encoding="utf-8")
    (tmp_path / "make_b.py").write_text("raise SystemExit('b broke')", encoding="utf-8")
    (tmp_path / "make_c.py").write_text("open('c.svg', 'w').write('c')", encoding="utf-8")
    rc, out = regen_run.render_figures(tmp_path)
    assert (rc, out) == (1, "wrote a\nb broke")
    assert (tmp_path / "a.svg").is_file()
    assert not (tmp_path / "c.svg").exists()


def test_check_only_mode_diffs_the_figures_in_a_copy(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    figures = root / "docs" / "figures"
    figures.mkdir(parents=True)
    (root / "registry.yaml").write_text("n: 2\n", encoding="utf-8")
    script = "from pathlib import Path; n = (Path(__file__).parents[2] / 'registry.yaml').read_text()[3]; "
    (figures / "make_n.py").write_text(script + "Path('n.svg').write_text(n)", encoding="utf-8")
    (figures / "n.svg").write_text("2", encoding="utf-8")
    assert regen_run.run("figures", regen_run.figures_check(tmp_path / "ok", root)).rc == 0
    (root / "registry.yaml").write_text("n: 3\n", encoding="utf-8")
    stale = regen_run.run("figures", regen_run.figures_check(tmp_path / "stale", root))
    assert (stale.rc, stale.out) == (1, f"stale: {figures / 'n.svg'}")
    assert (figures / "n.svg").read_text(encoding="utf-8") == "2"
    (figures / "make_n.py").write_text("raise SystemExit('broke')", encoding="utf-8")
    assert regen_run.run("figures", regen_run.figures_check(tmp_path / "broke", root)).out == "broke"


def test_differing_walks_subtrees_and_ignores_pycache(tmp_path: Path) -> None:
    for side, text in (("l", "x"), ("r", "y")):
        (tmp_path / side / "sub" / "__pycache__").mkdir(parents=True)
        (tmp_path / side / "sub" / "f.svg").write_text(text, encoding="utf-8")
        (tmp_path / side / "sub" / "__pycache__" / "m.pyc").write_text(text, encoding="utf-8")
    (tmp_path / "r" / "new.svg").write_text("", encoding="utf-8")
    left = tmp_path / "l"
    assert regen_run.differing(left, tmp_path / "r") == [str(left / "new.svg"), str(left / "sub" / "f.svg")]
