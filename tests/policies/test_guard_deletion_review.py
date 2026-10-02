"""guard-deletion: bypasses and fail-open paths found by review, each pinned."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from policies import guard_deletion_kit, scriptkit

NAME = "guard-deletion-gate.py"
with guard_deletion_kit.shipped():
    mod = scriptkit.load("guard-deletion", NAME)

API = "def handle(req):\n    if len(req.body) > MAX_BODY:\n        raise TooLarge()\n    return work(req)\n"
API_GONE = "def handle(req):\n    return work(req)\n"
MAKE = "CFLAGS += -fstack-protector-strong -O2\n"
MAKE_GONE = "CFLAGS += -O2\n"
MIDDLEWARE = "app.use(csrfProtection)\napp.use(cors())\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    files = {"src/api.py": API, "Makefile": MAKE, "src/mw.js": MIDDLEWARE, "src/keep.py": "x = 1\n"}
    return scriptkit.init_repo(tmp_path / "r", files)


def stage(repo: Path, files: dict[str, str]) -> None:
    scriptkit.write(repo, files)
    scriptkit.git(repo, "add", "-A")


def run(repo: Path, event: str, writes: dict[str, str] | None = None, env: dict[str, str] | None = None):
    payload = json.dumps({"event": event, "repo_root": str(repo), "writes": writes or {}})
    proc = scriptkit.run_script_full("guard-deletion", NAME, repo, payload, env)
    return proc.returncode, proc.stderr


def test_a_file_marked_binary_or_holding_a_nul_byte_is_still_read(repo: Path) -> None:
    scriptkit.write(repo, {".gitattributes": "*.mk -diff\n", "a.mk": MAKE})
    stage(repo, {})
    scriptkit.git(repo, "commit", "-qm", "mk")
    stage(repo, {"a.mk": MAKE_GONE})
    assert run(repo, "commit")[0] == 1
    assert run(repo, "tool_use", {"Makefile": MAKE_GONE + "\0"})[0] == 1


def test_a_pragma_an_agent_adds_is_a_finding_even_beside_a_kept_mitigation(repo: Path) -> None:
    kept = MAKE.rstrip("\n") + "  # pragma: allowlist mitigation-removal\n"
    for event, writes in (("tool_use", {"Makefile": kept}), ("agent-commit", None)):
        if writes is None:
            stage(repo, {"Makefile": kept})
        code, err = run(repo, event, writes)
        assert code == 3 and "waiver pragma" in err, event
    assert run(repo, "commit") == (0, "")  # a person's commit may add it


def test_a_guard_removed_while_moving_the_file_out_of_scope_is_still_read(repo: Path) -> None:
    scriptkit.git(repo, "mv", "src/api.py", "vendor_api.py")
    (repo / "vendor").mkdir()
    scriptkit.git(repo, "mv", "vendor_api.py", "vendor/api.py")
    stage(repo, {"vendor/api.py": API_GONE})
    code, err = run(repo, "commit")
    assert code == 3 and "src/api.py" in err


def test_an_absolute_write_path_is_judged_and_one_outside_the_repo_is_refused(repo: Path) -> None:
    scriptkit.write(repo, {"Makefile": MAKE_GONE})  # a post-write hook: disk already holds the text
    assert run(repo, "tool_use", {str(repo / "Makefile"): MAKE_GONE})[0] == 1
    code, err = run(repo, "tool_use", {"../elsewhere/x.py": "x\n"})
    assert code == 2 and "outside the repository" in err


@pytest.mark.parametrize("event", ["", "pre-commit", "Commit", "push", "agent_commit"])
def test_an_event_the_gate_does_not_judge_is_refused(repo: Path, event: str) -> None:
    code, err = run(repo, event, {"Makefile": MAKE_GONE})
    assert code == 2 and "not one this gate judges" in err


def test_a_lone_carriage_return_does_not_hide_a_change(tmp_path: Path) -> None:
    line = "s = 'a\rb'; r = get(u, verify=%s)\n"
    root = scriptkit.init_repo(tmp_path / "cr", {})
    (root / "a.py").write_bytes((line % "True").encode())
    scriptkit.git(root, "add", "-A")
    scriptkit.git(root, "commit", "-qm", "cr")
    (root / "a.py").write_bytes((line % "False").encode())
    scriptkit.git(root, "add", "-A")
    assert run(root, "commit")[0] == 1


def test_ci_reads_a_push_from_the_event_files_before_commit(repo: Path, tmp_path: Path) -> None:
    before = scriptkit.git_out(repo, "rev-parse", "HEAD")
    stage(repo, {"Makefile": MAKE_GONE})
    scriptkit.git(repo, "commit", "-qm", "one")
    stage(repo, {"src/keep.py": "x = 3\n"})
    scriptkit.git(repo, "commit", "-qm", "two")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": before}))
    env = {"GITHUB_EVENT_PATH": str(event), "PATH": scriptkit.os_path()}
    assert run(repo, "ci", env=env)[0] == 1
    assert run(repo, "ci", env={"PATH": scriptkit.os_path()})[0] == 0  # without it, only the tip commit is read


def test_running_out_of_time_asks(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mod, "BUDGET", -1.0)
    stage(repo, {"src/api.py": API_GONE})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"event": "commit", "repo_root": str(repo)})))
    assert mod.main() == 3
    assert "out of time" in capsys.readouterr().err


def test_a_shallow_checkout_cannot_be_compared_so_ci_refuses(repo: Path, tmp_path: Path) -> None:
    stage(repo, {"src/api.py": API_GONE})
    scriptkit.git(repo, "commit", "-qm", "drop")
    shallow = tmp_path / "shallow"
    scriptkit.git(tmp_path, "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow))
    code, err = run(shallow, "ci", env={"PATH": scriptkit.os_path()})
    assert code == 2 and "shallow" in err


def test_a_push_event_that_starts_at_head_falls_back_to_the_tip_commit(repo: Path, tmp_path: Path) -> None:
    stage(repo, {"src/api.py": API_GONE})
    scriptkit.git(repo, "commit", "-qm", "drop")
    event = tmp_path / "e.json"
    event.write_text(json.dumps({"before": scriptkit.git_out(repo, "rev-parse", "HEAD")}))
    env = {"GITHUB_EVENT_PATH": str(event), "PATH": scriptkit.os_path()}
    assert run(repo, "ci", env=env)[0] == 3


@pytest.mark.parametrize(
    "line",
    [
        "from x import y; assert len(a) < 3",
        "import x from 'y'; if (a.length > 3) throw new Error();",
        "using (var c = Open()) { if (c.Count > 3) return; }",
        "use AuthMiddleware",
        "if x == ' # ' and len(a) > 3: raise X",
        "/* c */ if (n > max_len) return -1;",
    ],
)
def test_a_guard_sharing_a_line_with_an_import_a_string_or_a_comment_is_still_read(repo: Path, line: str) -> None:
    root = scriptkit.init_repo(repo.parent / "g", {"src/a.src": line + "\n"})
    stage(root, {"src/a.src": "pass\n"})
    assert run(root, "commit")[0] == 3


def test_vendor_below_the_root_is_judged_and_the_root_one_is_not(tmp_path: Path) -> None:
    root = scriptkit.init_repo(
        tmp_path / "v", {"app/vendor/o.rb": "before_action :authenticate_user!\n", "vendor/x.rb": "before_action :a\n"}
    )
    stage(root, {"app/vendor/o.rb": "x = 1\n", "vendor/x.rb": "x = 1\n"})
    code, err = run(root, "commit")
    assert code == 3 and "app/vendor/o.rb" in err and "vendor/x.rb" not in err.replace("app/vendor/x.rb", "")


def test_a_pure_rename_out_of_scope_asks(repo: Path) -> None:
    (repo / "docs").mkdir()
    scriptkit.git(repo, "mv", "src/api.py", "docs/api.py")
    code, err = run(repo, "commit")
    assert code == 3 and "moved here from src/api.py" in err
    scriptkit.git(repo, "mv", "src/mw.js", "src/mw2.js")
    assert "src/mw2.js" not in run(repo, "commit")[1]


def test_a_pragma_in_a_string_or_a_moved_line_is_not_a_new_waiver(repo: Path) -> None:
    waived = "s = html.escape(x)  # pragma: allowlist guard-removal"
    root = scriptkit.init_repo(repo.parent / "p", {"a.py": waived + "\n", "b.py": "x = 1\n"})
    stage(root, {"a.py": "if 1:\n    " + waived + "\n"})
    assert run(root, "agent-commit") == (0, "")
    stage(root, {"b.py": "msg = 'pragma: allowlist guard-removal'\nx = 2\n"})
    assert "waiver pragma" not in run(root, "agent-commit")[1]


def test_a_repository_git_cannot_read_is_refused_at_tool_use(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.py").write_text("x = 1\n")
    assert run(plain, "tool_use", {"a.py": "x = 1\n"})[0] == 2


def test_a_change_with_too_many_characters_asks(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mod, "MAX_CHANGED_CHARS", 10)
    stage(repo, {"src/api.py": API_GONE})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"event": "commit", "repo_root": str(repo)})))
    assert mod.main() == 3


@pytest.mark.parametrize(
    ("removed", "added"),
    [
        ("SECURE_HSTS_SECONDS = 31536000", "SECURE_HSTS_SECONDS = 0"),
        ("SECURE_CONTENT_TYPE_NOSNIFF = True", "SECURE_CONTENT_TYPE_NOSNIFF = False"),
        ("ctx.verify_mode = ssl.CERT_REQUIRED", "ctx.verify_mode = ssl.CERT_NONE"),
        ("Content-Security-Policy: default-src 'self'", "Content-Security-Policy-Report-Only: default-src 'self'"),
    ],
)
def test_more_weakened_forms_are_refused(repo: Path, removed: str, added: str) -> None:
    root = scriptkit.init_repo(repo.parent / "w", {"settings.py": removed + "\n"})
    stage(root, {"settings.py": added + "\n"})
    assert run(root, "commit")[0] == 1
