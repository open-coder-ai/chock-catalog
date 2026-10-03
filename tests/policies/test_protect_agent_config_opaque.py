"""protect-agent-config: the backstop for a line that runs script text the guard cannot read and names a protected path."""

from __future__ import annotations

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
opaque = guardkit.load_guard(POLICY, "pathopaque")


@pytest.mark.parametrize(
    ("text", "runs"),
    [
        ('eval "$x"', True),
        ("eval echo hi", False),
        ("eval eval eval eval eval eval $x", True),
        ('echo $(eval "$x")', True),
        ("echo $(echo $(echo $(echo $(echo $(echo hi)))))", False),
        ("echo $(echo $(echo $(echo $(echo $(eval $x)))))", False),
        ("sh", True),
        ("sh -s", True),
        ("sh run.sh", False),
        ("sh /dev/stdin", True),
        ("sh -c", True),
        ("sh -c 'echo hi'", False),
        ('sh -c "$x"', True),
        ("bash -lc 'echo hi'", False),
        ("bash -c 'python3 -c 1'", True),
        ("xargs sh -c 'echo hi' _", True),
        ("find . -exec sh -c 'echo hi' {} ;", True),
        ("sudo env sh", True),
        ("env -S 'echo hi'", True),
        ("env A=1 echo hi", False),
        ("A=1 B=2 $SH", True),
        ("$HOME/bin/tool", False),
        ("${SH:-sh} -c true", True),
        ("source x.sh", False),
        ("source", True),
        ('source "$x"', True),
        (". /dev/fd/3", True),
        ("trap 'echo hi' EXIT", True),
        ("trap -- 'echo hi' EXIT", True),
        ("trap - EXIT", False),
        ("trap -p", False),
        ("python3 -c 1", True),
        ("python3 -Sc 1", True),
        ("python3", True),
        ("python3 -m pytest", False),
        ("python3 script.py", False),
        ("node --eval 1", True),
        ("deno eval 1", True),
        ("perl -ne 1", True),
        ("echo sh", False),
        ("ls /bin/sh", False),
        ("Invoke-Expression $x", True),
        ("", False),
    ],
)
def test_a_construct_that_runs_script_text_the_guard_cannot_read_is_found(text: str, runs: bool) -> None:
    look = opaque._Look()
    look.run(text)
    assert look.found is runs, text


def test_the_backstop_needs_both_the_construct_and_a_protected_path() -> None:
    protected = guard.hit
    assert opaque.refuses('eval "$x" # .mcp.json', protected)
    assert opaque.refuses("e''val \"$x\" .mc''p.json", protected)
    assert opaque.refuses("sh <<< \"$x\"; cat '.m'cp.json", protected)
    assert opaque.refuses("printf '%b' '.\\0155cp.json' | sh", protected)
    assert not opaque.refuses('eval "$x"', protected)
    assert not opaque.refuses("cat .mcp.json", protected)
    assert not opaque.refuses("cat .mcp.json | jq .", protected)
    assert not opaque.refuses("sh run.sh .mcp.json", protected)


def test_the_reason_says_what_was_refused() -> None:
    assert "script text the guard cannot read" in guard.BLIND
    assert "names a protected path" in guard.BLIND
    assert guard.check('eval "$x" # .mcp.json') == guard.BLIND
