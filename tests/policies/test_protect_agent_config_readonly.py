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
    doc(f"print(open('{RESULT}').read())", "python3 -"),  # no import: the working directory cannot shadow one
    doc(f"import json; print(json.dumps(json.load(open('{RESULT}')), indent=2))", "python3 -P -"),
    doc(f"import json; print(json.load(open('{RESULT}')))", "python3 -IB"),
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
    doc(f"import json; print(json.load(open('{RESULT}')))", "python3 -"),  # a json.py in the working directory
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


@pytest.mark.parametrize("raw", REFUSED)
def test_a_write_or_a_script_not_provably_read_only_is_still_refused(raw: str) -> None:
    assert GUARD.check(raw) is not None, raw


@pytest.mark.parametrize(
    ("name", "args", "script", "expected"),
    [
        ("python3", ["-I", "-"], "import json; print(json.loads('1'))", True),
        ("/usr/bin/python3.12", ["-I"], "print(open('a').read())", True),
        ("python3", ["-I", "-"], "import sys; print(sys.argv)", False),
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
