"""The tools pack (ASI02): a tool the model can call that hands the model's string to the shell."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agentic_gate import jsscan
from agentic_gate.model import FileText, Hit, Pack, Rule
from agentic_gate.pyast import callee, calls, dotted, keyword, terminal, tree
from agentic_gate.textscan import find

PACK = Pack(
    id="tools",
    title="Agent tool misuse",
    covers="Python functions registered as agent tools that pass their string parameters to a subprocess, and shell tools.",
    asi=("ASI02",),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_DECORATORS = frozenset({"tool", "function_tool"})
_OS_SINKS = frozenset({"os.system", "os.popen"})
_QUOTERS = frozenset({"shlex.quote", "pipes.quote"})
_SHELL_TOOLS = frozenset({"ShellTool", "TerminalTool", "BashTool"})
_JS_SHELL_TOOL = re.compile(r"\bnew\s+(?:ShellTool|TerminalTool|BashTool)\s*\(")
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _registered(parsed: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Functions that are agent tools: decorated as one, or handed to `Tool(func=...)`."""
    functions = [n for n in ast.walk(parsed) if isinstance(n, _FUNCTIONS)]
    named = {
        value.id
        for call in (n for n in ast.walk(parsed) if isinstance(n, ast.Call))
        if terminal(call) in {"Tool", "from_function"} and isinstance(value := keyword(call, "func"), ast.Name)
    }
    return [
        fn
        for fn in functions
        if fn.name in named
        or any(
            dotted(d.func if isinstance(d, ast.Call) else d).rsplit(".", 1)[-1] in _DECORATORS
            for d in fn.decorator_list
        )
    ]


def _annotated_str(arg: ast.arg) -> bool:
    if arg.annotation is None:
        return False
    return any(isinstance(n, ast.Name) and n.id == "str" for n in ast.walk(arg.annotation))


def _validated(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters the body tests for membership in a fixed collection: an allowlist check."""
    return {
        node.left.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and all(isinstance(op, ast.In | ast.NotIn) for op in node.ops)
    }


def _flows(node: ast.AST, tainted: set[str]) -> str | None:
    """The tainted name whose value reaches this expression, else None.

    A shlex.quote(...) call, a subscript's key and a comparison do not carry the value on: the
    key picks from a fixed table, and the comparison yields a bool.
    """
    if isinstance(node, ast.Name):
        return node.id if node.id in tainted else None
    if (isinstance(node, ast.Call) and callee(node) in _QUOTERS) or isinstance(node, ast.Compare):
        return None
    children = [node.value] if isinstance(node, ast.Subscript) else list(ast.iter_child_nodes(node))
    return next((found for child in children if (found := _flows(child, tainted))), None)


def _spread(fn: ast.FunctionDef | ast.AsyncFunctionDef, seeds: set[str]) -> set[str]:
    """`seeds` plus every local assigned from them, followed to a fixed point."""
    tainted = set(seeds)
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign | ast.AnnAssign | ast.AugAssign) and n.value]
    while True:
        before = len(tainted)
        for node in assigns:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if _flows(node.value, tainted):
                tainted |= {t.id for target in targets for t in ast.walk(target) if isinstance(t, ast.Name)}
        if len(tainted) == before:
            return tainted


def _sinks(parsed: ast.Module) -> frozenset[str]:
    """Bare names that are subprocess functions in this file, from `from subprocess import ...`."""
    return frozenset(
        alias.asname or alias.name
        for node in ast.walk(parsed)
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for alias in node.names
    )


def _is_sink(call: ast.Call, bare: frozenset[str]) -> bool:
    name = callee(call)
    return name.startswith("subprocess.") or name in _OS_SINKS or name in bare


def _shell_flow(text: FileText) -> Iterator[Hit]:
    parsed = tree(text)
    if parsed is None:
        return
    bare = _sinks(parsed)
    for fn in _registered(parsed):
        params = {a.arg for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs) if _annotated_str(a)}
        tainted = _spread(fn, params - _validated(fn))
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call) and _is_sink(n, bare)):
            values = [*call.args, *(kw.value for kw in call.keywords)]
            if name := next((found for v in values if (found := _flows(v, tainted))), None):
                yield Hit(call.lineno, f"tool {fn.name!r} passes the model's string {name!r} to {callee(call)}.")


def _shell_tool(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        if terminal(call) in _SHELL_TOOLS:
            yield Hit(call.lineno, f"{terminal(call)}() gives the model a shell.")
    if text.kind == "js":
        yield from find(jsscan.shape(text.text), _JS_SHELL_TOOL, "a shell tool gives the model a shell.")


RULES: tuple[Rule, ...] = (
    Rule(
        id="tools-shell-injection-via-tool-param",
        pack="tools",
        title="Agent tool passes a string parameter to a subprocess",
        why="The model writes tool arguments and prompt injection steers what it writes; a string that reaches a subprocess is a command the attacker chose.",
        kinds=("python",),
        scan=_shell_flow,
        fix="map the parameter to a fixed command through a table (COMMANDS[action]) or check it against an allowlist first; never build argv from the model's string.",
        refuses="@tool, @function_tool, @mcp.tool, server.tool(...) or Tool(func=...) functions whose str parameter reaches subprocess.*, os.system or os.popen",
        silent_on="a fixed argv, a table lookup keyed by the parameter, an allowlist membership check, shlex.quote",
        cwe=("CWE-78",),
        asi=("ASI02",),
        references=(*_OWASP, "https://cwe.mitre.org/data/definitions/78.html"),
    ),
    Rule(
        id="tools-shell-tool-instantiation",
        pack="tools",
        title="Generic shell tool handed to an agent",
        why="A generic shell tool gives the model every command its user can run, with no per-action check.",
        kinds=("python", "js"),
        scan=_shell_tool,
        fix="expose the specific operations the task needs as typed tools instead of a shell.",
        refuses="ShellTool(...), TerminalTool(...), BashTool(...) instantiated",
        silent_on="typed single-purpose tools",
        cwe=("CWE-78",),
        asi=("ASI02",),
        references=(*_OWASP, "https://python.langchain.com/docs/security/"),
    ),
)
