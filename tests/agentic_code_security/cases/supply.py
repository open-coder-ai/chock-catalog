"""supply pack: MCP launch commands and URLs, remote code, hub downloads."""

from __future__ import annotations

from agentic_code_security.cases.case import Case

NPX_UNPINNED = """{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/work"
      ]
    }
  }
}
"""
UVX_UNPINNED = """{
  "mcpServers": {
    "git": {
      "command": "uvx",
      "args": [
        "mcp-server-git"
      ]
    }
  }
}
"""
NPX_PINNED = """{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem@2025.1.14",
        "/work"
      ]
    },
    "git": {"command": "uvx", "args": ["mcp-server-git==0.6.2"]},
    "latest": {"command": "npx", "args": ["-y", "some-server@latest"]},
    "local": {"command": "node", "args": ["./server.js"]},
    "box": {"command": "docker", "args": ["run", "-i", "acme/mcp:1.0.0"]}
  }
}
"""
UVX_GIT = """{
  "mcpServers": {
    "tool": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/acme/tool",
        "tool"
      ]
    }
  }
}
"""
SHA = "0123456789abcdef0123456789abcdef01234567"
UVX_GIT_PINNED = (
    '{"mcpServers": {"tool": {"command": "uvx", "args": ["--from", '
    f'"git+https://github.com/acme/tool@{SHA}#subdirectory=mcp", "tool"]}}}}}}\n'
)
HTTP_URL = """{
  "mcpServers": {
    "remote": {
      "url": "http://mcp.example.com/sse"
    }
  }
}
"""
HTTPS_URL = """{
  "servers": {
    "remote": {"type": "http", "url": "https://mcp.example.com/mcp"},
    "dev": {"url": "http://localhost:3000/mcp"},
    "loop": {"serverUrl": "http://127.0.0.1:8080/sse"},
    "v6": {"url": "http://[::1]:9000/mcp"}
  }
}
"""

REFUSED = [
    Case(
        "supply-mcp-unpinned-package", ".mcp.json", NPX_UNPINNED, "launches an npm MCP server with npx and no version"
    ),
    Case(
        "supply-mcp-unpinned-package",
        ".cursor/mcp.json",
        UVX_UNPINNED,
        "launches a Python MCP server with uvx and no version",
    ),
    Case(
        "supply-mcp-unpinned-package",
        ".codex/config.toml",
        '[mcp_servers.git]\ncommand = "uvx"\nargs = ["mcp-server-git"]\n',
        "launches a uvx server from a Codex TOML config",
    ),
    Case(
        "supply-mcp-unpinned-package",
        ".vscode/mcp.json",
        '{"servers": {"gh": {"command": "pipx", "args": ["run", "mcp-github"]}, "b": {"command": "bunx", "args": ["mcp-b"]}}}\n',
        "launches servers with pipx run and bunx and no version",
    ),
    Case("supply-uvx-git-unpinned", "claude_desktop_config.json", UVX_GIT, "runs uvx --from a git URL with no commit"),
    Case(
        "supply-uvx-git-unpinned",
        "scripts/serve.sh",
        "uvx --from git+https://github.com/acme/tool tool --stdio\n",
        "runs uvx --from a git URL in a script",
    ),
    Case("supply-mcp-remote-http", ".gemini/settings.json", HTTP_URL, "points an MCP server at a remote http:// URL"),
    Case(
        "supply-mcp-remote-http",
        ".codex/config.toml",
        '[mcp_servers.remote]\nurl = "http://mcp.example.com/mcp"\n',
        "points a TOML MCP server at a remote http:// URL",
    ),
    Case(
        "supply-mcp-remote-http",
        "app/servers.py",
        'server = MCPServerSse(params={"url": "http://tools.example.com/sse"})\n',
        "builds an MCP client for a remote http:// URL",
    ),
    Case(
        "supply-mcp-remote-http",
        "deploy/mcp.yaml",
        "mcp:\n  servers:\n    - name: remote\n      url: http://mcp.example.com/sse\n",
        "lists a remote http:// MCP server in YAML",
    ),
    Case(
        "supply-trust-remote-code",
        "models/load.py",
        'model = AutoModel.from_pretrained("acme/m", revision="abc1234", trust_remote_code=True)\n',
        "loads a model with trust_remote_code=True",
    ),
    Case(
        "supply-hf-unpinned-revision",
        "models/load.py",
        'model = AutoModel.from_pretrained("acme/m")\npath = hf_hub_download("acme/m", "weights.bin")\n',
        "downloads from the hub with no revision",
    ),
    Case(
        "supply-langchain-hub-unpinned",
        "prompts/load.py",
        'prompt = hub.pull("acme/rag-prompt")\n',
        "pulls a hub prompt with no commit",
    ),
]

SILENT = [
    Case(
        "supply-mcp-unpinned-package",
        ".mcp.json",
        NPX_PINNED,
        "pins every package, or launches something that is not a package",
    ),
    Case(
        "supply-mcp-unpinned-package",
        ".codex/config.toml",
        '[mcp_servers.git]\ncommand = "uvx"\nargs = ["mcp-server-git==0.6.2"]\n[mcp_servers.other]\ncommand = "npx"\nargs = ["-y", "other@1.2.3"]\n',
        "pins TOML-configured servers",
    ),
    Case("supply-mcp-unpinned-package", "package.json", NPX_UNPINNED, "is not an MCP client config file"),
    Case("supply-uvx-git-unpinned", ".mcp.json", UVX_GIT_PINNED, "pins the git spec to a 40-hex commit"),
    Case(
        "supply-uvx-git-unpinned",
        "scripts/serve.sh",
        f"uvx --from git+https://github.com/acme/tool@{SHA} tool --stdio\nuvx ruff check\n",
        "pins the git spec in a script",
    ),
    Case("supply-mcp-remote-http", ".vscode/mcp.json", HTTPS_URL, "uses https, or http to localhost"),
    Case(
        "supply-mcp-remote-http",
        "app/servers.py",
        'server = MCPServerSse(params={"url": "https://tools.example.com/sse"})\nlocal = MCPServerSse(params={"url": "http://localhost:8000/sse"})\n',
        "connects to an MCP server over https, or to localhost over http",
    ),
    Case(
        "supply-mcp-remote-http",
        "deploy/health.yaml",
        "check:\n  url: http://example.com/health\n",
        "has a plain URL in a YAML file that is not about MCP",
    ),
    Case(
        "supply-trust-remote-code",
        "models/load.py",
        'model = AutoModel.from_pretrained("acme/m", revision="abc1234", trust_remote_code=False)\n',
        "loads with trust_remote_code=False",
    ),
    Case(
        "supply-hf-unpinned-revision",
        "models/load.py",
        'model = AutoModel.from_pretrained("acme/m", revision="0123abc")\nlocal = AutoModel.from_pretrained("./models/m")\n'
        'more = AutoModel.from_pretrained(name, **kwargs)\npath = hf_hub_download("acme/m", "w.bin", revision="0123abc")\n',
        "pins the revision, or loads a local directory",
    ),
    Case(
        "supply-langchain-hub-unpinned",
        "prompts/load.py",
        'prompt = hub.pull("acme/rag-prompt:9a8b7c6d")\nother = client.pull("acme/x")\nname = hub.pull(prompt_name)\n',
        "pulls a hub prompt at a commit",
    ),
]
