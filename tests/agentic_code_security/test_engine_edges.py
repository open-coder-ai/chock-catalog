"""The corners the rule cases do not reach: unparseable files, lexer edges, file kinds, BOMs."""

from __future__ import annotations

import pytest
from agentic_code_security.conftest import ALL_DENY
from agentic_gate import jsscan
from agentic_gate.engine import evaluate
from agentic_gate.model import FileText, Finding
from agentic_gate.textscan import uncommented


def judged(path: str, text: str) -> list[str]:
    return [f.rule_id for f in evaluate({path: text}, ALL_DENY, lambda _p: None, human=True)]


@pytest.mark.parametrize("body", ["def broken(:\n    eval(x)\n", "x = (\n", "\x00"])
def test_python_that_does_not_parse_has_nothing_for_the_ast_rules_to_judge(body: str) -> None:
    assert judged("a.py", body) == []


def test_a_byte_order_mark_does_not_hide_the_first_line() -> None:
    assert judged("a.py", "﻿eval(x)\n") == ["code-dynamic-eval-exec"]
    assert judged("net.env", "﻿x=1\n") == []
    assert judged(".env", "﻿NODE_TLS_REJECT_UNAUTHORIZED=0\n") == ["comms-node-tls-disabled"]


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("a.py", "python"),
        ("dir/a.TSX", "js"),
        ("a.mjs", "js"),
        ("a.json", "json"),
        ("a.yml", "yaml"),
        ("a.toml", "toml"),
        ("run.sh", "shell"),
        ("Dockerfile", "dockerfile"),
        ("Dockerfile.dev", "dockerfile"),
        (".env", "env"),
        (".env.local", "env"),
        ("README.md", "other"),
        ("Makefile", "other"),
    ],
)
def test_a_path_belongs_to_one_kind(path: str, kind: str) -> None:
    assert FileText(path, "").kind == kind


@pytest.mark.parametrize(
    ("path", "is_test"),
    [
        ("tests/a.py", True),
        ("pkg/test/a.py", True),
        ("src/__tests__/a.ts", True),
        ("src/test_a.py", True),
        ("src/a_test.py", True),
        ("src/a.test.ts", True),
        ("src/a.spec.tsx", True),
        ("src/agent.py", False),
        ("src/contest.py", False),
        ("src/latest/a.py", False),
    ],
)
def test_test_paths_are_told_from_product_paths(path: str, is_test: bool) -> None:
    assert FileText(path, "").is_test is is_test


def test_holds_ignores_case() -> None:
    assert FileText("a.py", "Import MEM0").holds("mem0")
    assert not FileText("a.py", "x").holds("mem0")


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        ("a: 1  # note", "a: 1  "),
        ("# whole", ""),
        ('url: "http://x/#frag"', 'url: "http://x/#frag"'),
        ("run: echo a#b", "run: echo a#b"),
        ("x: 'it''s' # c", "x: 'it''s' "),
    ],
)
def test_a_hash_comment_ends_a_line_only_outside_quotes(line: str, kept: str) -> None:
    assert uncommented(line) == kept


def test_the_js_lexer_blanks_comments_and_keeps_columns() -> None:
    text = "a // one\nb /* two\nthree */ c\n"
    out = jsscan.strip_comments(text)
    assert out.splitlines() == ["a       ", "b       ", "         c"]
    assert len(out) == len(text)


def test_the_js_lexer_blanks_string_contents_only_in_shape() -> None:
    text = 'const a = \'x // y\'; const b = `t${1}\nu`; const c = "q\\"r";\n'
    assert jsscan.strip_comments(text) == text
    shaped = jsscan.shape(text)
    assert "// y" not in shaped
    assert shaped.count("\n") == text.count("\n")
    assert "const a = '      ';" in shaped


def test_the_js_lexer_survives_unterminated_input() -> None:
    assert jsscan.strip_comments("a /* never closed") == "a " + " " * len("/* never closed")
    assert jsscan.strip_comments("a // no newline") == "a " + " " * len("// no newline")
    assert jsscan.shape("x = 'open\ny = 1\n") == "x = '    \ny = 1\n"
    assert jsscan.shape("x = 'a\\") == "x = ' " + " "
    assert jsscan.shape("`open template") == "`" + " " * len("open template")


def test_a_js_pattern_in_a_comment_or_string_is_not_code() -> None:
    assert judged("a.js", "// new ShellTool()\nconst s = 'env: process.env';\n") == []
    assert judged("a.js", "const t = new ShellTool();\n") == ["tools-shell-tool-instantiation"]


def test_a_finding_on_a_line_past_the_end_still_renders() -> None:
    found = evaluate({"a.py": "eval(x)"}, ALL_DENY, lambda _p: None, human=True)
    assert found[0].line == "eval(x)"
    assert found[0].render().startswith("a.py:1: [deny: code-dynamic-eval-exec CWE-95] ")


def test_a_rule_with_no_cwe_or_asi_renders_without_tags() -> None:
    assert Finding("r", "a.py", 1, "", "m").render() == "a.py:1: [deny: r] m"
