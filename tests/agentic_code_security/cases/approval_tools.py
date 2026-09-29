"""approval and tools packs: the human checkpoint, and tools that hand the model's string to a shell."""

from __future__ import annotations

from agentic_code_security.cases.case import Case

AUTO_WRITE = """{
  "mcpServers": {
    "fs": {
      "command": "node",
      "args": ["./server.js"],
      "autoApprove": [
        "read_file",
        "write_file"
      ]
    },
    "ops": {
      "command": "node",
      "args": ["./ops.js"],
      "alwaysAllow": ["list_pods", "runQuery", "deploy_prod"]
    }
  }
}
"""
AUTO_READ = """{
  "mcpServers": {
    "fs": {
      "command": "node",
      "args": ["./server.js"],
      "autoApprove": ["read_file", "list_directory", "search", "truncate_log"],
      "alwaysAllow": "read_file"
    }
  }
}
"""
TOOL_RUN = """import subprocess
from langchain_core.tools import tool


@tool
def run_command(command: str) -> str:
    \"\"\"Run a command.\"\"\"
    return subprocess.run(command.split(), capture_output=True, text=True).stdout
"""
TOOL_FLOW = """import os
from subprocess import check_output
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
async def search_logs(pattern: str, limit: int) -> str:
    cmd = ["grep", pattern, "app.log"]
    return check_output(cmd, text=True)


def cleanup(path: str) -> None:
    os.system(f"rm -rf {path}")


registered = Tool(name="cleanup", func=cleanup)
"""
TOOL_SAFE = """import os
import shlex
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")
COMMANDS = {"status": ["git", "status"], "log": ["git", "log", "-5"]}
ALLOWED = {"status", "log"}


@mcp.tool()
def git(action: str) -> str:
    if action not in ALLOWED:
        raise ValueError(action)
    return subprocess.run(COMMANDS[action], capture_output=True, text=True).stdout


@mcp.tool()
def tail(path: str) -> str:
    return os.popen("tail -5 " + shlex.quote(path)).read()


@mcp.tool()
def fixed() -> str:
    return subprocess.run(["git", "status"], capture_output=True, text=True).stdout


@mcp.tool()
def count(n: int) -> str:
    return subprocess.run(["head", f"-{n}", "log"], capture_output=True, text=True).stdout


def helper(command: str) -> str:
    return subprocess.run(command, capture_output=True, text=True).stdout


@mcp.tool()
def untyped(command):
    label = "static"
    return subprocess.run(command, capture_output=True, text=True).stdout + label


@mcp.tool()
def broken(command: str) -> str:
    out = helper(command)
    return out
"""

REFUSED = [
    Case(
        "approval-hosted-mcp-never",
        "agent/hosted.py",
        'tool = HostedMCPTool(tool_config={"type": "mcp", "server_label": "docs", "server_url": "https://x.example", "require_approval": "never"})\n',
        'sets require_approval "never" on a hosted MCP tool',
    ),
    Case(
        "approval-hosted-mcp-never",
        "agent/hosted.ts",
        'const tool = hostedMcpTool({ serverLabel: "docs", serverUrl: "https://x.example", requireApproval: "never" });\n',
        'sets requireApproval "never" in TypeScript',
    ),
    Case(
        "approval-autogen-no-human-input",
        "agents/proxy.py",
        'proxy = UserProxyAgent("u", human_input_mode="NEVER", code_execution_config={"work_dir": "w", "use_docker": True})\n',
        'runs an AutoGen agent that executes code with human_input_mode "NEVER"',
    ),
    Case(
        "approval-claude-sdk-bypass-permissions",
        "src/agent.py",
        'options = ClaudeAgentOptions(permission_mode="bypassPermissions")\n',
        'sets permission_mode "bypassPermissions" in product code',
    ),
    Case(
        "approval-claude-sdk-bypass-permissions",
        "src/agent.ts",
        'for await (const m of query({ prompt, options: { permissionMode: "bypassPermissions" } })) {}\n',
        'sets permissionMode "bypassPermissions" in TypeScript product code',
    ),
    Case("approval-mcp-autoapprove-write-tools", ".mcp.json", AUTO_WRITE, "auto-approves write, run and deploy tools"),
    Case(
        "approval-mcp-autoapprove-write-tools",
        ".codex/config.toml",
        '[mcp_servers.ops]\ncommand = "node"\nautoApprove = ["send_email"]\n',
        "auto-approves a send tool in TOML",
    ),
    Case(
        "tools-shell-injection-via-tool-param",
        "tools/run.py",
        TOOL_RUN,
        "passes a tool's str parameter to subprocess.run",
    ),
    Case(
        "tools-shell-injection-via-tool-param",
        "tools/ops.py",
        TOOL_FLOW,
        "passes tool parameters to check_output and os.system",
    ),
    Case(
        "tools-shell-tool-instantiation",
        "agent/tools.py",
        "tools = [ShellTool(), TerminalTool(), BashTool()]\n",
        "gives the agent a shell tool",
    ),
    Case(
        "tools-shell-tool-instantiation",
        "agent/tools.ts",
        "const shell = new ShellTool();\n",
        "instantiates a shell tool in TypeScript",
    ),
]

SILENT = [
    Case(
        "approval-hosted-mcp-never",
        "agent/hosted.py",
        'a = HostedMCPTool(tool_config={"require_approval": "always"})\n'
        'b = HostedMCPTool(tool_config={"require_approval": {"never": {"tool_names": ["search"]}}})\n',
        "asks for approval, or excuses only named read-only tools",
    ),
    Case(
        "approval-hosted-mcp-never",
        "agent/hosted.ts",
        '// requireApproval: "never" was the demo setting\nconst tool = hostedMcpTool({ requireApproval: "always" });\n',
        "asks for approval, the demo setting only in a comment",
    ),
    Case(
        "approval-autogen-no-human-input",
        "agents/proxy.py",
        'a = UserProxyAgent("u", human_input_mode="NEVER", code_execution_config=False)\n'
        'b = UserProxyAgent("v", human_input_mode="ALWAYS", code_execution_config={"work_dir": "w"})\n'
        'c = AssistantAgent("w", human_input_mode="NEVER")\n',
        "keeps a human in the loop wherever code runs",
    ),
    Case(
        "approval-claude-sdk-bypass-permissions",
        "tests/test_agent.py",
        'options = ClaudeAgentOptions(permission_mode="bypassPermissions")\n',
        "bypasses permissions only in a test",
    ),
    Case(
        "approval-claude-sdk-bypass-permissions",
        "src/agent.py",
        'options = ClaudeAgentOptions(permission_mode="acceptEdits", allowed_tools=["Read"])\n',
        "uses acceptEdits with an allowed_tools list",
    ),
    Case("approval-mcp-autoapprove-write-tools", ".mcp.json", AUTO_READ, "auto-approves only read-only tools"),
    Case(
        "tools-shell-injection-via-tool-param",
        "tools/git.py",
        TOOL_SAFE,
        "uses a fixed argv, a lookup table, an allowlist or shlex.quote",
    ),
    Case(
        "tools-shell-tool-instantiation",
        "agent/tools.py",
        "tools = [ReadFileTool(), ListDirectoryTool()]\n",
        "uses typed single-purpose tools",
    ),
    Case(
        "tools-shell-tool-instantiation",
        "agent/tools.ts",
        '// new ShellTool() was removed\nconst read = new ReadFileTool();\nconst note = "new BashTool()";\n',
        "mentions a shell tool only in a comment and a string",
    ),
]
