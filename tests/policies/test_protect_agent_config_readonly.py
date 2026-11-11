"""protect-agent-config 0.7.7: a Python here-document that provably only reads may name a protected path; any write is still refused."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

GUARD = guardkit.load_guard("protect-agent-config")
PY = guardkit.load_guard("protect-agent-config", "pathpy")

RESULT = "/root/.claude/projects/-home-user-repo/tool-results/r1.json"
SETTINGS = "/root/.claude/settings.json"


def doc(body: str, head: str = "python3 -I -") -> str:
    return f"{head} <<'EOF'\n{body}\nEOF"


OPEN = [
    doc(f"import json; print(json.load(open('{RESULT}'))['k'])"),
    doc(f"import json\nwith open('{RESULT}') as f:\n    print(json.load(f)['k'])"),
    doc(f"from json import loads\nprint(loads(open('{RESULT}', 'rb').read()))"),
    doc(f"print(open('{SETTINGS}', 'r', encoding='utf-8').read())"),
    doc("print(open('.claude/settings.json', mode='rt').read()[:100])"),
    doc(f"import json; print(json.dumps(json.load(open('{RESULT}')), indent=2))", "python3 -IP -"),
    doc(f"import json; print(json.load(open('{RESULT}')))", "python3 -IB"),
]
READ = f"print(open('{SETTINGS}').read())"
# Not read-only without -I, or when the environment or the line around it can change what Python runs.
ENVIRONED = [
    doc(f"print(open('{RESULT}').read())", "python3 -"),  # PYTHON* variables, a sitecustomize on sys.path
    doc(f"import json; print(json.load(open('{RESULT}')))", "python3 -P -"),  # -P still reads PYTHON* variables
    doc(READ, "PYTHONPATH=/work/x python3 -"),
    doc(READ, "PYTHONPATH=/work/x python3 -I -"),
    doc(READ, "LD_PRELOAD=/work/x.so python3 -I -"),
    doc(READ, "env PYTHONPATH=/work/x python3 -I -"),
    doc(READ, "env LD_PRELOAD=/work/x.so python3 -I -"),
    "export LD_PRELOAD=/work/x.so; " + doc(READ),
    "cd /work && " + doc(READ),
    f"python3 -I - <<'EOF' | head\n{READ}\nEOF",  # not the whole line
]
# A read-only script never launders a shell-level write.
LAUNDERED = [
    doc(READ, f"python3 -I - > {SETTINGS}"),
    f"python3 -I - <<'EOF' > {SETTINGS}\n{READ}\nEOF",
    f"python3 -I - <<'EOF' | tee {SETTINGS}\n{READ}\nEOF",
    f"python3 -I - <<'EOF' >> {SETTINGS}\n{READ}\nEOF",
]
REFUSED = [
    f"cat > {SETTINGS}",
    f"echo '{{}}' | tee {SETTINGS}",
    f"echo '{{}}' >> {SETTINGS}",
    f"sed -i s/deny/allow/ {SETTINGS}",
    f"python3 -c \"open('{SETTINGS}', 'w').write('x')\"",
    f"cat > {SETTINGS} <<'EOF'\n{{}}\nEOF",
    doc(f"open('{SETTINGS}', 'w').write('x')"),
    doc(f"open('{SETTINGS}', 'a').write('x')"),
    doc(f"open('{SETTINGS}', 'r+').write('x')"),
    doc(f"open('{SETTINGS}', 'x')"),
    doc(f"open('{SETTINGS}', mode='w').write('x')"),
    doc(f"m = 'w'\nopen('{SETTINGS}', m).write('x')"),
    doc(f"open('{SETTINGS}', **{{'mode': 'w'}})"),
    doc(f"open('{SETTINGS}', 'r', 1, None, None, None, True, print)"),
    doc(f"o = open\no('{SETTINGS}', 'w').write('x')"),
    doc(f"import os; os.remove('{SETTINGS}')"),
    doc(f"import json; json.dump({{}}, open('{SETTINGS}', 'w'))"),
    doc(f"import json; json.codecs.open('{SETTINGS}', 'w').write('x')"),
    doc(f"import json as j\nj = None\nprint(open('{SETTINGS}').read())"),
    doc(f"from pathlib import Path; Path('{SETTINGS}').write_text('x')"),
    doc(f"import shutil; shutil.copy('x', '{SETTINGS}')"),
    doc(f"__import__('os').remove('{SETTINGS}')"),
    doc(f"exec(\"open('{SETTINGS}', 'w')\")"),
    doc(f"getattr(__builtins__, 'open')('{SETTINGS}', 'w')"),
    doc(f"print(().__class__, '{SETTINGS}')"),
    doc(f"print(open('{RESULT}').read())") + f" > {SETTINGS}",
    doc(f"print(open('{RESULT}').read())", "python3 -I x.py"),
    doc("print(1)", f"python3 -I - {SETTINGS}"),
    doc(f"print(open('{RESULT}').read())", "python3 -i -"),
    doc(f"console.log(require('fs').readFileSync('{RESULT}'))", "node -"),
    doc(f"echo x > {SETTINGS}", "bash"),
    doc(f"print(open('{RESULT}').read(')"),  # does not parse
    doc(f"print('{SETTINGS}')"),  # read-only, but names a protected path it does not open: judged as before (0.7.5)
    doc(f"print(open('{RESULT}').read(), '.mcp.json')"),
]


@pytest.fixture(autouse=True)
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", OPEN)
def test_a_read_only_python_here_document_passes(raw: str) -> None:
    assert GUARD.check(raw) is None, raw


@pytest.mark.parametrize("raw", ENVIRONED)
def test_a_read_without_i_or_with_a_changed_environment_is_refused(raw: str) -> None:
    assert GUARD.check(raw) is not None, raw


@pytest.mark.parametrize("raw", LAUNDERED)
def test_a_read_only_script_does_not_launder_a_shell_write(raw: str) -> None:
    assert GUARD.check(raw) == GUARD.REASON, raw


@pytest.mark.parametrize("raw", REFUSED)
def test_a_write_or_a_script_not_provably_read_only_is_still_refused(raw: str) -> None:
    assert GUARD.check(raw) is not None, raw


@pytest.mark.parametrize(
    ("name", "args", "script", "expected"),
    [
        ("python3", ["-I", "-"], "import json; print(json.loads('1'))", True),
        ("/usr/bin/python3.12", ["-I"], "print(open('a').read())", True),
        ("python3", ["-I", "-"], "import sys; print(sys.argv)", False),
        ("python3", ["-"], "print(open('a').read())", False),
        ("python3", ["-P", "-"], "print(open('a').read())", False),
        ("python3", ["-EsP", "-"], "print(open('a').read())", False),
        ("python3", ["-c", "x"], "print(1)", False),
        ("python3", ["-X", "dev", "-"], "print(1)", False),
        ("ruby", ["-"], "print 1", False),
        ("python3", ["-I", "-"], "", True),
    ],
)
def test_the_read_only_subset(name: str, args: list[str], script: str, expected: bool) -> None:
    assert PY.read_only(name, args, [script]) is expected


def test_no_script_is_not_read_only() -> None:
    assert PY.read_only("python3", ["-I", "-"], []) is False


def test_only_the_paths_a_read_only_script_opens_leave_the_judged_text() -> None:
    script = f"print(open('{RESULT}').read(), '{SETTINGS}')"
    assert PY.judged("python3", ["-I", "-"], [script]) == [f"print(open('').read(), '{SETTINGS}')"]
    writes = f"open('{SETTINGS}', 'w')"
    assert PY.judged("python3", ["-I", "-"], [writes]) == [writes]


# IR-F64 (0.7.8): the same read as `python3 -I -c CODE` passes under the same conditions; every write is still refused.
CODE = f"import json; print(json.load(open('{RESULT}'))['k'])"
ONE_LINERS = [
    f'python3 -I -c "{CODE}"',
    f'python3 -Ic "{CODE}"',
    f'python3 -IB -c "{CODE}"',
    f"python3 -I -c 'print(open(\"{SETTINGS}\").read())'",
]
ONE_LINERS_REFUSED = [
    f"python3 -I -c \"open('{SETTINGS}','w').write('x')\"",
    f"python3 -I -c \"open('{SETTINGS}', 'a')\"",
    f"python3 -I -c \"m = 'w'; open('{SETTINGS}', m)\"",
    f"python3 -I -c \"import os; os.remove('{SETTINGS}')\"",
    f"python3 -I -c \"print('{SETTINGS}')\"",  # names a path it does not open
    f'python3 -c "{CODE}"',
    f'python3 -P -c "{CODE}"',
    f'python3 -I -X dev -c "{CODE}"',
    f'PYTHONPATH=x python3 -I -c "{CODE}"',
    f'LD_PRELOAD=x.so python3 -I -c "{CODE}"',
    f'env python3 -I -c "{CODE}"',
    f'env PYTHONPATH=x python3 -I -c "{CODE}"',
    f'sudo python3 -I -c "{CODE}"',
    f'export X=1; python3 -I -c "{CODE}"',
    f'cd /work && python3 -I -c "{CODE}"',
    f'python3 -I -c "{CODE}" | head',
    f'python3 -I -c "{CODE}" x',  # CODE is not the last argument
    f"python3 -I -c \"print(open('{SETTINGS}').read(), '$(rm AGENTS.md)')\"",
]
ONE_LINERS_LAUNDERED = [
    f'python3 -I -c "{CODE}" > {SETTINGS}',
    f'python3 -I -c "{CODE}" >> {SETTINGS}',
    f'python3 -I -c "{CODE}" | tee {SETTINGS}',
]


@pytest.mark.parametrize("raw", ONE_LINERS)
def test_a_read_only_python_one_liner_passes(raw: str) -> None:
    assert GUARD.check(raw) is None, raw


@pytest.mark.parametrize("raw", ONE_LINERS_REFUSED)
def test_a_one_liner_not_provably_read_only_or_not_the_whole_line_is_refused(raw: str) -> None:
    assert GUARD.check(raw) is not None, raw


@pytest.mark.parametrize("raw", ONE_LINERS_LAUNDERED)
def test_a_read_only_one_liner_does_not_launder_a_shell_write(raw: str) -> None:
    assert GUARD.check(raw) == GUARD.REASON, raw


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["-I", "-c", "print(open('a').read())"], ["-I", "-c", "print(open('').read())"]),
        (["-Ic", "print(1)"], ["-Ic", "print(1)"]),
        (["-c", "print(1)"], None),
        (["-I", "-c"], None),
        (["-I", "-c", "print(1)", "x"], None),
        (["-I", "-c", "import sys"], None),
        (["-I", "-c", "print('$HOME')"], None),
        (["-I", "-m", "json"], None),
    ],
)
def test_the_one_liner_subset(args: list[str], expected: list[str] | None) -> None:
    assert PY.inline("python3", args) == expected
    assert PY.inline("ruby", args) is None
