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


HEREDOC = "python3 -I - <<'E'\nprint(1)\nE\n"


@pytest.mark.parametrize(
    "line",
    [
        HEREDOC + "grep -n x AGENTS.md",
        HEREDOC + "cat AGENTS.md\nls .claude",
        HEREDOC + "grep -n x AGENTS.md; head .claude/settings.json | wc -l",
        'python3 -I - <<< "print(1)"; grep -n x AGENTS.md',
        "sudo python3 - <<'E'\nprint(1)\nE\ngrep -n x AGENTS.md",
    ],
)
def test_an_interpreter_fed_a_here_document_that_names_nothing_is_not_blind_beside_a_read(line: str) -> None:
    assert not opaque.refuses(line, guard.hit), line


@pytest.mark.parametrize(
    "line",
    [
        "python3 -I - <<'E'\nopen('AGENTS.md','w')\nE\ngrep -n x registry.yaml",
        HEREDOC + "cat x > AGENTS.md",
        HEREDOC + "touch .claude/settings.json",
        HEREDOC + "AGENTS.md=1 cat AGENTS.md",
        HEREDOC + "rm AGENTS.md",
        HEREDOC + "grep x AGENTS.md > .claude/settings.json",
        "python3 -I - <<E\nprint('$(rm AGENTS.md)')\nE",
        "python3 -I - <<E\nprint(`rm AGENTS.md`)\nE",
        "cat run.py | python3 -I -\ngrep -n x AGENTS.md",
        "python3 -I - < run.py\ngrep -n x AGENTS.md",
        "xargs python3 -I - <<'E'\nprint(1)\nE\ngrep -n x AGENTS.md",
        "python3 -I - <<'E'\nprint(1)\nE\npython3 -c 1\ngrep -n x AGENTS.md",
        "bash -c \"python3 -I - <<'E'\nopen('AGENTS.md','w')\nE\"",
    ],
)
def test_the_other_blind_forms_and_a_write_beside_a_here_document_stay_refused(line: str) -> None:
    assert opaque.refuses(line, guard.hit), line


def test_a_here_document_is_judged_by_what_it_names_and_what_surrounds_it() -> None:
    look = opaque._Look()
    look.run(HEREDOC + "grep -n x AGENTS.md")
    assert not look.found
    assert len(look.fed) == 1
    assert look.rest == []


# IR-F10: a script that only reads registry.yaml, then greps instruction files by name, was refused as BLIND.
PARSE_REGISTRY = (
    "cd repo && python3 -I - <<'E'\nimport yaml,re\nr=yaml.safe_load(open('registry.yaml'))\n"
    "rows=r if isinstance(r,list) else r.get('policies',r)\nprint(type(rows),len(rows))\nfor p in rows:\n"
    "    d=' '.join(p.get('description','').split())\n    if re.search(r'enforc|block|refus|stops?\\b',d,re.I):\n"
    "        print(p['id'],'|',d[:170])\nE\n"
    'grep -rn "protect-main-branch" tests tools --include=*.py -l | head; grep -n -i "version" AGENTS.md CONTRIBUTING.md | head'
)


def test_the_script_that_only_reads_a_registry_is_allowed_beside_greps_of_instruction_files() -> None:
    assert guard.check(PARSE_REGISTRY) is None


@pytest.mark.parametrize("name", ["AGENTS.md", ".claude/settings.json"])
def test_the_same_script_writing_a_protected_file_is_refused(name: str) -> None:
    script = PARSE_REGISTRY.replace("open('registry.yaml')", f"open('{name}','w')")
    assert guard.check(script) == guard.REASON
