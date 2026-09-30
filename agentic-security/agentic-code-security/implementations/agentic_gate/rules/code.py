"""The code pack (code safety): dynamic code and SQL built from strings, in the code agents write."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agentic_gate import jsscan
from agentic_gate.model import FileText, Hit, Pack, Rule
from agentic_gate.pyast import builds_string, calls, string_of, terminal, tree
from agentic_gate.textscan import find

PACK = Pack(
    id="code",
    title="Code safety",
    covers="Python eval and exec of non-literal text, and SQL assembled from strings in Python and JavaScript.",
)

_SQL_METHODS = frozenset({"execute", "executemany", "query", "raw"})
_SQL_WORDS = re.compile(r"\b(?:select|insert|update|delete|from|where|drop|create|alter|join)\b", re.IGNORECASE)
_JS_SQL = re.compile(r"\b(?:query|execute)\s*\(\s*`[^`]*\$\{")
_WHOLE_STATEMENT_METHODS = frozenset({"execute", "executemany"})


def _literal_text(node: ast.AST) -> str:
    """The constant parts of a string expression, joined: what its author wrote around the holes."""
    return " ".join(str(n.value) for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _built_values(parsed: ast.Module) -> dict[str, ast.expr]:
    """Names assigned an assembled string anywhere in the file, so `q = f"..."; execute(q)` is seen."""
    return {
        target.id: node.value
        for node in ast.walk(parsed)
        if isinstance(node, ast.Assign) and builds_string(node.value, set())
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def _eval_exec(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        bare = isinstance(call.func, ast.Name) and call.func.id in {"eval", "exec"}
        if bare and call.args and string_of(call.args[0]) is None:
            yield Hit(call.lineno, f"{terminal(call)}() runs text that is not a literal in this file.")


def _sql(text: FileText) -> Iterator[Hit]:
    parsed = tree(text)
    if parsed is not None:
        values = _built_values(parsed)
        for call in calls(text):
            method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
            if method not in _SQL_METHODS or not call.args or not builds_string(call.args[0], set(values)):
                continue
            arg = call.args[0]
            origin = values[arg.id] if isinstance(arg, ast.Name) else arg
            if method in _WHOLE_STATEMENT_METHODS or _SQL_WORDS.search(_literal_text(origin)):
                yield Hit(
                    call.lineno,
                    f"{method}() receives SQL assembled from a string, so values become syntax.",
                    (origin.lineno,),
                )
    if text.kind == "js":
        yield from find(jsscan.strip_comments(text.text), _JS_SQL, "a template literal with ${} is passed as SQL.")


RULES: tuple[Rule, ...] = (
    Rule(
        id="code-dynamic-eval-exec",
        pack="code",
        title="eval or exec of text that is not a literal",
        why="eval and exec of a variable run whatever the text says, and in agent code that text often comes from a model.",
        kinds=("python",),
        scan=_eval_exec,
        fix="parse with ast.literal_eval or json.loads, or dispatch through a table of named functions.",
        refuses="eval(x) or exec(x) where x is not a string literal (bare eval( is also block-unsafe-code-execution's)",
        silent_on="ast.literal_eval, model.eval(), eval of a string literal",
        cwe=("CWE-95",),
        references=(
            "https://docs.python.org/3/library/functions.html#eval",
            "https://cwe.mitre.org/data/definitions/95.html",
        ),
    ),
    Rule(
        id="code-sql-string-built",
        pack="code",
        title="SQL assembled from strings",
        why="Values spliced into SQL become syntax, and model output is untrusted input.",
        kinds=("python", "js"),
        scan=_sql,
        fix="bind values as parameters: cursor.execute('... WHERE id = %s', (value,)); in JS pass a values array.",
        refuses=".execute(, .executemany(, .query(, .raw( whose statement is an f-string, %-format, .format() or + concatenation; JS query( or execute( over a template literal with ${}",
        silent_on="parameterised queries, constant SQL, session.query(Model), .query( on a non-SQL string",
        cwe=("CWE-89",),
        references=("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",),
    ),
)
