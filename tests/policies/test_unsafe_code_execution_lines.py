"""block-unsafe-code-execution 0.1.3: a definition, a comment-only line and a config array are not calls (REVIEW-deps.md, section 9)."""

from __future__ import annotations

import re

import pytest
from policies import gatekit

PATTERN = re.compile(gatekit.gate_spec("block-unsafe-code-execution")["params"]["content_pattern"])

# Lines the 0.0.4 pattern refused and that are not code, so the rules test's "v2 only adds refusals" does not apply.
SPARED = {
    "definitions named eval or exec": [
        "def eval(self, loader):",
        "  async exec(conn: Conn): Promise<Row[]> {",
        "function eval(x) {",
        "func exec(cmd string) error {",
        "fn eval(x: i32) -> i32 {",
    ],
    "comment-only lines": [
        "# never call eval() on user input; use ast.literal_eval",
        "    # os.system() is banned here",
        "#",
        "// exec(cmd) is banned",
    ],
    "shell vector in a config array": [
        'CMD ["sh", "-c", "nginx -g \'daemon off;\'"]',
        'HEALTHCHECK --interval=30s CMD ["sh", "-c", "curl -f http://localhost/"]',
        'command: ["/bin/sh", "-c", "alembic upgrade head"]',
        'test: ["CMD", "sh", "-c", "wget -qO- http://localhost:3000/health"]',
    ],
}

# What stays refused next to them: a call, a vector in a call or an assignment, code after or beside a comment.
REFUSED = {
    "a hash that is not a comment": [
        "# define RUN(c) eval(c)",
        "#  define RUN(c) os.system(c)",
        "#\tdefine RUN(c) eval(c)",
        "#define RUN(c) eval(c)",
        "# include <eval(x)>",
        "#!/usr/bin/env python -c eval(x)",
        '#!/bin/sh eval "$CMD"',
        "# error eval(x)",
    ],
    "eval-exec-call": [
        "return eval(user_input)",
        "x = 1  # then eval(y)",
        "/* ok */ eval(x)",
        "#eval(x)",
        "await exec(cmd)",
        "async_exec(cmd); eval(x)",
        "x = def_eval(y); eval(z)",
    ],
    "shell vector in a call or an assignment": [
        'new ProcessBuilder("sh", "-c", cmd)',
        'exec.Command("sh", "-c", cmd)',
        "subprocess.run(['env', 'A=1', 'sh', '-c', cmd])",
        'argv = ["sh", "-c", cmd]',
        'argv: list[str] = ["bash", "-c", cmd]',
    ],
}


def _cases(table: dict[str, list[str]]) -> list:
    return [pytest.param(line, id=f"{rule}: {line}") for rule, lines in table.items() for line in lines]


@pytest.mark.parametrize("line", _cases(SPARED))
def test_the_line_is_not_a_call(line: str) -> None:
    assert not PATTERN.search(line)


@pytest.mark.parametrize("line", _cases(REFUSED))
def test_the_call_is_still_refused(line: str) -> None:
    assert PATTERN.search(line)
