"""protect-agent-config: seventh review round, the shared command reader -- `--` and options before a script, arrays, `+=`,
and a line of unbalanced quotes read in linear time."""

from __future__ import annotations

import itertools
import json
import os
import random
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from policies import guardkit
from trees import ROOT

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
POLICIES = guardkit.policies_with_shellparse()


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".claude", ".cursor", ".chock", "src", "docs"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.fixture(params=POLICIES, ids=POLICIES)
def sp(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CHOCK_TOOL", raising=False)
    module = guardkit.load_shellparse(request.param)
    yield module
    for name in [n for n in sys.modules if n == module.__name__ or n.startswith(f"{module.__name__}.")]:
        del sys.modules[name]  # a later load of the same package must import its modules afresh, not reuse these


@pytest.mark.parametrize(
    ("raw", "name", "args"),
    [
        ("eval -- 'rm a'", "rm", ["a"]),
        ("eval 'rm a'", "rm", ["a"]),
        ("eval rm -- a", "rm", ["--", "a"]),
        ("builtin eval -- 'rm a'", "rm", ["a"]),
        ("bash -c -- 'rm a'", "rm", ["a"]),
        ("sh -c 'rm a'", "rm", ["a"]),
        ("bash -ec -- 'rm a'", "rm", ["a"]),
        ("bash -c -- -- 'rm a'", "--", ["rm", "a"]),
        ("pwsh -Command -- rm a", "rm", ["a"]),
        ("bash -c -x 'rm a'", "rm", ["a"]),
        ("bash -c +e -- 'rm a'", "rm", ["a"]),
        ("bash -c -O extglob 'rm a'", "rm", ["a"]),
        ("bash -c +O extglob 'rm a'", "rm", ["a"]),
        ("bash -c -xo pipefail 'rm a'", "rm", ["a"]),
        ("bash -c -o pipefail -x -- 'rm a'", "rm", ["a"]),
        ("bash -c 'rm a' arg0 -x", "rm", ["a", "arg0", "-x"]),
        ("bash -c -", "-", []),
        ("pwsh -Command -x rm a", "-x", ["rm", "a"]),
    ],
)
def test_a_double_dash_before_the_script_of_eval_or_dash_c_is_not_part_of_the_script(
    sp, raw: str, name: str, args: list[str]
) -> None:
    found = sp.commands(raw)
    assert (found[0].name, found[0].args) == (name, args)


@pytest.mark.parametrize(
    ("raw", "env"),
    [
        ("x=.mc; x+=p.json; true", {"x": ".mcp.json"}),
        ("x=.mc; x+=p; x+=.json; true", {"x": ".mcp.json"}),
        ("x+=p.json; true", {"x": "$__subst__"}),
        ("x=safe; x[0]=.mcp.json; true", {"x": "$__subst__"}),
        ("x[1]+=.mcp.json; true", {"x": "$__subst__"}),
        ("x=(.mcp.json); true", {"x": "$__subst__"}),
        ("x=(a b c); true", {"x": "$__subst__"}),
        ("x=(a 'b c' \"d\"); true", {"x": "$__subst__"}),
        ("x=(a\nb # note\n c); true", {"x": "$__subst__"}),
        ("x=(); true", {"x": "$__subst__"}),
        ("x=a; x+=(b); true", {"x": "$__subst__"}),
        ("x=([0]=.mcp.json); true", {"x": "$__subst__"}),
        ('x="(a)"; true', {"x": "$__subst__"}),
        ("x=a; true", {"x": "a"}),
        ("{ x=a; }; true", {"x": "a"}),
        ("f(){ x=a; }; true", {"x": "a"}),
    ],
)
def test_the_reader_keeps_appended_text_and_makes_an_array_or_an_element_unknown(sp, raw: str, env: dict) -> None:
    assert sp.commands(raw)[-1].env == env


@pytest.mark.parametrize(
    "raw",
    [
        "(a)",
        "echo (a)",
        "echo foo=bar=(x)",
        "> x=(a)",
        "x=(a; b)",
        "x=(a | b)",
        "x=('b",
        "x=(a b",
        "x=(a $(b))",
    ],
)
def test_a_parenthesis_that_does_not_open_an_array_still_ends_the_clause(sp, raw: str) -> None:
    assert all(not c.env.get("x", "").startswith("$") for c in sp.commands(raw))


def test_an_array_does_not_swallow_the_commands_after_it(sp) -> None:
    found = sp.commands("x=(a b); rm c")
    assert [(c.name, c.args) for c in found] == [("rm", ["c"])]


def _words_before_the_rewrite(part: str) -> list[str]:
    """The segment reader as it was: it re-split the text at every quote, which is cubic on unbalanced quotes."""
    positions = [m.start() for m in re.finditer(r"['\"]", part)]
    for at in [len(part), *reversed(positions)]:
        try:
            return [*shlex.split(part[:at]), *([part[at + 1 :]] if at < len(part) else [])]
        except ValueError:
            continue
    return part.split()


def test_the_segment_reader_gives_what_it_gave_for_every_short_text_and_a_sample_of_long_ones(sp) -> None:
    alphabet = ["a", " ", "'", '"', "\\", "\n"]
    texts = ["".join(chars) for size in range(6) for chars in itertools.product(alphabet, repeat=size)]
    rng = random.Random(7)  # noqa: S311 -- a fixed seed gives a reproducible sample, nothing secret
    texts += ["".join(rng.choice([*alphabet, "b", "$"]) for _ in range(rng.randint(6, 40))) for _ in range(1500)]
    for text in texts:
        assert list(sp.quoting.split_words(text)) == _words_before_the_rewrite(text), repr(text)


def _unbalanced(shape: str, size: int) -> str:
    return {
        "escaped": lambda: 'echo "' + '\\"' * (size // 2),
        "opened": lambda: 'echo "' + "'x' " * (size // 4),
        "alternating": lambda: "echo " + "a'b'c\"d" * (size // 7),
        "backslash": lambda: "echo 'a' " * (size // 9) + "\\",
        "clauses": lambda: 'echo "a; ' * (size // 8),
        "declares": lambda: "declare " * (size // 8),
    }[shape]()


_TIMER = """
import json, sys, time
from policies import guardkit
from policies.test_protect_agent_config_seventh_reader import _unbalanced
policy, shape = sys.argv[1:3]
sp, guard = guardkit.load_shellparse(policy), guardkit.load_guard("protect-agent-config")
def seconds(call, size):
    raw = _unbalanced(shape, size)
    start = time.process_time()
    call(raw)
    return time.process_time() - start
print(json.dumps([[seconds(call, 4096), seconds(call, 65536)] for call in (sp.commands, guard.check)]))
"""


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("shape", ["escaped", "opened", "alternating", "backslash", "clauses", "declares"])
def test_a_line_of_unbalanced_quotes_is_read_in_linear_time(shape: str, policy: str) -> None:
    """CPU time, not wall time: a guard that outruns the engine's 30 s is escalated by the engine, but a client that stops the hook first may allow.

    Timed in a child process, as a hook runs, outside the coverage tracer, which slows a python loop several times over.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith(("COV", "COVERAGE"))}
    env["PYTHONPATH"] = os.pathsep.join(str(ROOT / d) for d in ("tests", "tools"))
    done = subprocess.run(
        [sys.executable, "-c", _TIMER, policy, shape],
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    for small, large in json.loads(done.stdout):
        assert large < 3, (shape, large)
        assert large < 60 * max(small, 0.005), (shape, small, large)  # 16 times the text is about 16 times the time
