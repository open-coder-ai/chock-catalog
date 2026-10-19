"""block-secret-store-reads: which words of an interpreter command are read for a credential-store name.

The verdicts are in guard_cases_secret_more.py and the eval suite; this holds the reader on its own: the code
flag's value, the script operand, or nothing, never the program's later arguments.
"""

from __future__ import annotations

import pytest
from policies import guardkit

POLICY = "block-secret-store-reads"
readers = guardkit.load_guard(POLICY, "secret_readers")


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("python -c code arg", "code"),
        ("python -Bc code", "code"),
        ("python -m pytest -k .env", ""),
        ("python -Bm pytest -k .env", ""),
        ("python -W ignore -c code", "code"),
        ("python -Wd x.py", "x.py"),
        ("python -V", ""),
        ("python -- x.py", "x.py"),
        ("python - arg", ""),
        ("python3.11 app.py --env-file .env", "app.py"),
        ("perl -ne code file", "code"),
        ("perl -Mstrict -e code", "code"),
        ("perl -eprint", "print"),
        ("ruby -I lib -e code", "code"),
        ("node --eval=code", "code"),
        ("node -r dotenv/config app.js --config .npmrc", "app.js"),
        ("node --inspect app.js", "app.js"),
        ("nodejs -p code", "code"),
        ("deno run -A app.ts .env", "app.ts"),
        ("deno eval code", "code"),
        ("bun run test.ts --config .npmrc", "test.ts"),
        ("php -f x.php .env", "x.php"),
        ("lua -l mod x.lua", "x.lua"),
    ],
)
def test_an_interpreters_program_is_its_code_or_script_operand_never_its_later_arguments(
    command: str, want: str
) -> None:
    name, *args = command.split()
    assert readers.program_text(readers.Cmd(name, args, {}, [], [], "")) == want
