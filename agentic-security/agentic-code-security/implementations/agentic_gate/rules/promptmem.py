"""The prompt-memory pack (ASI01, ASI06): untrusted text in the instruction channel, memory with no owner."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agentic_gate.model import ALLOW, FileText, Hit, Pack, Rule
from agentic_gate.pyast import (
    builds_string,
    calls,
    dict_items,
    identifiers,
    keyword,
    spreads,
    string_of,
    terminal,
    tree,
)

PACK = Pack(
    id="prompt-memory",
    title="Prompt and memory hygiene",
    covers="System messages assembled from retrieved or user text, and mem0 calls with no user, agent or run scope.",
    asi=("ASI01", "ASI06"),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_UNTRUSTED = re.compile(r"doc|chunk|context|retrieved|email|page|html|tool_output|user_input", re.IGNORECASE)
_SYSTEM_KEYWORDS = ("system", "system_prompt", "system_message", "instructions")
_MEM_CLASSES = frozenset({"Memory", "MemoryClient", "AsyncMemory", "AsyncMemoryClient", "from_config"})
_MEM_METHODS = frozenset({"add", "search"})
_PAIR = 2
_SCOPES = frozenset({"user_id", "agent_id", "run_id"})


def _tainted(expr: ast.expr | None) -> bool:
    """An assembled string that mentions a variable named for untrusted content."""
    return expr is not None and builds_string(expr, set()) and any(_UNTRUSTED.search(n) for n in identifiers(expr))


def _system_expressions(parsed: ast.Module) -> Iterator[ast.expr | None]:
    """The text every system message in the file is built from."""
    for node in ast.walk(parsed):
        if isinstance(node, ast.Dict):
            fields = dict(dict_items(node))
            if string_of(fields.get("role")) == "system":
                yield fields.get("content")
        elif isinstance(node, ast.Tuple) and len(node.elts) == _PAIR and string_of(node.elts[0]) == "system":
            yield node.elts[1]
        elif isinstance(node, ast.Call):
            if terminal(node) == "SystemMessage":
                yield keyword(node, "content") or (node.args[0] if node.args else None)
            yield from (keyword(node, name) for name in _SYSTEM_KEYWORDS)


def _system_message(text: FileText) -> Iterator[Hit]:
    parsed = tree(text)
    for expr in _system_expressions(parsed) if parsed else ():
        if _tainted(expr):
            yield Hit(expr.lineno, "the system message is assembled from text named like retrieved or user content.")


def _receivers(parsed: ast.Module) -> dict[str, set[int]]:
    """Names bound to a mem0 client in this file, and the lines that bind them."""
    found: dict[str, set[int]] = {}
    for node in ast.walk(parsed):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and terminal(node.value) in _MEM_CLASSES:
            for target in (t for t in node.targets if isinstance(t, ast.Name | ast.Attribute)):
                found.setdefault(_owner(target), set()).add(node.lineno)
    return found


def _scoped(call: ast.Call) -> bool:
    filters = keyword(call, "filters")
    keys = {key for key, _ in dict_items(filters)} if isinstance(filters, ast.Dict) else set()
    return bool(_SCOPES & ({kw.arg for kw in call.keywords} | keys)) or spreads(call)


def _mem0(text: FileText) -> Iterator[Hit]:
    parsed = tree(text)
    if parsed is None or not text.holds("mem0"):
        return
    receivers = _receivers(parsed)
    for call in calls(text):
        func = call.func
        on_client = isinstance(func, ast.Attribute) and func.attr in _MEM_METHODS and _owner(func.value) in receivers
        if on_client and not _scoped(call):
            yield Hit(
                call.lineno,
                f"memory.{terminal(call)}() with no user_id, agent_id or run_id shares one memory pool.",
                tuple(sorted(receivers[_owner(func.value)])),
            )


def _owner(node: ast.expr) -> str:
    return node.id if isinstance(node, ast.Name) else getattr(node, "attr", "")


RULES: tuple[Rule, ...] = (
    Rule(
        id="prompt-untrusted-in-system-message",
        pack="prompt-memory",
        title="Retrieved or user text spliced into a system message",
        why="The system channel is read as instructions; retrieved or user text placed there is prompt injection with the highest authority.",
        kinds=("python",),
        scan=_system_message,
        fix="keep the system message constant; pass retrieved text as a user or tool message, delimited and labelled as data.",
        refuses="a system message built with an f-string, .format(), % or + from variables named doc, chunk, context, retrieved, email, page, html, tool_output or user_input",
        silent_on="a constant system message, the same variables in a user message",
        cwe=("CWE-1427",),
        asi=("ASI01",),
        references=(*_OWASP, "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
        default=ALLOW,
    ),
    Rule(
        id="memory-mem0-unscoped",
        pack="prompt-memory",
        title="mem0 memory call with no owner",
        why="Memory with no owner pools every user's facts, so one user's session can read or poison another's.",
        kinds=("python",),
        scan=_mem0,
        fix="pass user_id, agent_id or run_id on every add() and search() so one user's memory is never another's context.",
        refuses="a mem0 client's .add( or .search( with none of user_id, agent_id, run_id (or a filters dict naming one)",
        silent_on="calls passing a scope, add/search on other objects",
        cwe=("CWE-639",),
        asi=("ASI06",),
        references=(*_OWASP, "https://docs.mem0.ai/core-concepts/memory-operations/add"),
        default=ALLOW,
    ),
)
