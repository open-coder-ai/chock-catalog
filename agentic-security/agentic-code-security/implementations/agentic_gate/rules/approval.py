"""The approval pack (ASI02, ASI09): the human checkpoint switched off where the action is consequential."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from agentic_gate import jsscan, mcp
from agentic_gate.model import FileText, Hit, Pack, Rule
from agentic_gate.pyast import calls, is_const, is_false, keyword, settings
from agentic_gate.textscan import find

PACK = Pack(
    id="approval",
    title="Human approval",
    covers="Hosted-tool, AutoGen, Claude Agent SDK and MCP client settings that remove the human's approval step.",
    asi=("ASI02", "ASI09"),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_JS_NEVER = re.compile(r"\b(?:require_approval|requireApproval)\s*:\s*[\"']never[\"']")
_JS_BYPASS = re.compile(r"\bpermissionMode\s*:\s*[\"']bypassPermissions[\"']")
_WRITE_TOKENS = ("write", "delete", "exec", "run", "shell", "deploy", "push", "send")
_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_APPROVE_KEYS = ("autoApprove", "alwaysAllow")


def _hosted_mcp(text: FileText) -> Iterator[Hit]:
    detail = 'require_approval "never" lets a hosted MCP tool act without asking the user.'
    for line_no, value in settings(text, "require_approval"):
        if is_const(value, "never"):
            yield Hit(line_no, detail)
    if text.kind == "js":
        yield from find(jsscan.strip_comments(text.text), _JS_NEVER, detail)


def _has_execution(call: ast.Call) -> bool:
    config = keyword(call, "code_execution_config")
    return (config is not None and not (is_false(config) or is_const(config, None))) or bool(
        keyword(call, "code_executor")
    )


def _autogen(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        if is_const(keyword(call, "human_input_mode"), "NEVER") and _has_execution(call):
            yield Hit(call.lineno, 'human_input_mode="NEVER" on an agent that also executes code.')


def _bypass(text: FileText) -> Iterator[Hit]:
    if text.is_test:
        return
    detail = 'permission_mode "bypassPermissions" runs every tool without asking.'
    for line_no, value in settings(text, "permission_mode"):
        if is_const(value, "bypassPermissions"):
            yield Hit(line_no, detail)
    if text.kind == "js":
        yield from find(jsscan.strip_comments(text.text), _JS_BYPASS, detail)


def _write_type(name: str) -> bool:
    return any(word.lower().startswith(_WRITE_TOKENS) for word in _WORDS.findall(name))


def _approved_writes(server: mcp.Server) -> Iterator[tuple[str, str]]:
    for key in _APPROVE_KEYS:
        listed = server.body.get(key)
        if isinstance(listed, list):
            yield from ((key, tool) for tool in listed if isinstance(tool, str) and _write_type(tool))


def _autoapprove(text: FileText) -> Iterator[Hit]:
    for server in mcp.servers(text):
        for key, tool in _approved_writes(server):
            yield Hit(
                mcp.line_for(text, server, f'"{tool}"'),
                f"server {server.name!r} {key} includes {tool!r}, which changes state.",
                mcp.block(text, server),
            )


RULES: tuple[Rule, ...] = (
    Rule(
        id="approval-hosted-mcp-never",
        pack="approval",
        title="Hosted MCP tool that never asks for approval",
        why="The approval step is the one human check between a tool call and its effect; never removes it for every tool the server exposes.",
        kinds=("python", "js"),
        scan=_hosted_mcp,
        fix='use require_approval="always", or a per-tool map that names only read-only tools under "never".',
        refuses='require_approval="never" (requireApproval: "never" in TypeScript) on a hosted MCP tool',
        silent_on='require_approval="always", a per-tool {"never": {"tool_names": [...]}} map, an approval callback',
        cwe=("CWE-862",),
        asi=("ASI02", "ASI09"),
        references=(
            *_OWASP,
            "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations",
        ),
    ),
    Rule(
        id="approval-autogen-no-human-input",
        pack="approval",
        title="AutoGen agent that executes code with no human input",
        why="An agent that executes code and never asks a human has nobody to stop a bad step.",
        kinds=("python",),
        scan=_autogen,
        fix='set human_input_mode="ALWAYS" (or "TERMINATE") on the agent that executes code, or remove its code_execution_config.',
        refuses='human_input_mode="NEVER" in a call that also sets code_execution_config or code_executor',
        silent_on='human_input_mode="NEVER" with code_execution_config False, "ALWAYS" or "TERMINATE"',
        cwe=("CWE-862",),
        asi=("ASI09", "ASI02"),
        references=(*_OWASP, "https://microsoft.github.io/autogen/0.2/docs/tutorial/human-in-the-loop/"),
    ),
    Rule(
        id="approval-claude-sdk-bypass-permissions",
        pack="approval",
        title="Claude Agent SDK bypassPermissions in product code",
        why="bypassPermissions runs every tool, Bash and file writes included, without a prompt.",
        kinds=("python", "js"),
        scan=_bypass,
        fix='use permission_mode "default" or "acceptEdits" with an allowed_tools list, and a can_use_tool callback for the rest.',
        refuses='permission_mode="bypassPermissions" (permissionMode in TypeScript) outside test files',
        silent_on="the same setting in a test file, any other permission mode",
        cwe=("CWE-862",),
        asi=("ASI02", "ASI09"),
        references=(*_OWASP, "https://docs.claude.com/en/api/agent-sdk/permissions"),
    ),
    Rule(
        id="approval-mcp-autoapprove-write-tools",
        pack="approval",
        title="MCP client config auto-approves a state-changing tool",
        why="Auto-approving a state-changing tool means the client never asks before it writes, deletes, runs or sends.",
        kinds=("json", "toml"),
        scan=_autoapprove,
        fix="keep write, delete, exec, run, shell, deploy, push and send tools out of autoApprove and alwaysAllow so each call asks.",
        refuses="an autoApprove or alwaysAllow list holding a tool named write|delete|exec|run|shell|deploy|push|send*",
        silent_on="autoApprove lists of read-only tools (read_file, list_directory, search)",
        cwe=("CWE-862",),
        asi=("ASI02", "ASI09"),
        references=(
            *_OWASP,
            "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations",
        ),
    ),
)
