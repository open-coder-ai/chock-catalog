"""Which surface a path is, matched by path segment and case-insensitively (macOS and Windows ignore case)."""

from __future__ import annotations

import re
from collections.abc import Callable

from devenv import agents, agents_more, devcontainer, gitfiles, hooklaunch, toolchain, vscode
from devenv.core import Collector

Handler = Callable[[Collector], None]

#: (regex over the lower-cased, slash-separated path, handler). First match wins; `(?:^|/)` anchors a segment.
_TABLE: list[tuple[str, Handler]] = [
    (r"\.claude/settings[^/]*\.json", agents.claude_settings),
    (r"\.claude/(?:commands|agents)/.+\.md|\.claude/skills/.+/skill\.md", agents.claude_markdown),
    (
        r"\.(?:cursor|codex|windsurf|agents)/hooks\.json|\.devin/hooks\.v1\.json|\.github/hooks/[^/]+\.json",
        agents.hooks_file,
    ),
    (r"\.grok/hooks/[^/]+\.json|\.kiro/hooks/[^/]+", agents.hooks_file),
    (r"\.cursor/environment\.json", agents.cursor_environment),
    (r"\.cursor/cli\.json", agents.cursor_cli),
    (r"\.gemini/settings\.json", agents_more.gemini_settings),
    (r"\.gemini/\.env", agents_more.agent_dotenv),
    (r"\.codex/config\.toml", agents_more.codex_config),
    (
        r"\.mcp\.json|\.(?:cursor|vscode|roo|kilocode|amazonq)/mcp\.json|\.windsurf/mcp_config\.json|\.gemini/mcp\.json",
        agents_more.mcp_client,
    ),
    (r"\.aider\.conf\.ya?ml", agents_more.aider_config),
    (r"opencode\.jsonc?|\.opencode/opencode\.jsonc?", agents_more.opencode_config),
    (r"\.vscode/tasks\.json", vscode.tasks_file),
    (r"\.vscode/settings\.json", vscode.settings_file),
    (r"\.vscode/launch\.json", vscode.launch_file),
    (r"\.vscode/extensions\.json", vscode.extensions_file),
    (r"[^/]+\.code-workspace", vscode.workspace_file),
    (r"\.devcontainer/(?:[^/]+/)?devcontainer\.json|\.devcontainer\.json", devcontainer.devcontainer),
    (r"\.idea/.+\.xml|\.run/[^/]+\.run\.xml", toolchain.jetbrains),
    (r"\.envrc(?:\.local)?", toolchain.envrc),
    (
        r"\.?mise(?:\.local)?\.toml|\.mise/config\.toml|\.config/mise(?:/config)?\.toml|mise/config\.toml",
        toolchain.mise,
    ),
    (r"\.tool-versions|\.nvmrc|\.node-version|\.python-version|\.ruby-version", toolchain.versions),
    (r"(?:gnu)?makefile|[^/]+\.mk", toolchain.makefile),
    (r"\.?justfile|[^/]+\.just", toolchain.justfile),
    (r"taskfile(?:\.dist)?\.ya?ml", toolchain.taskfile),
    (r"procfile", toolchain.procfile),
    (r"vagrantfile|brewfile", toolchain.ruby_file),
    (r"\.gitpod\.ya?ml", toolchain.gitpod),
    (r"\.replit", toolchain.replit),
    (r"\.husky/(?!_/)[^/]+|\.githooks/[^/]+", hooklaunch.hook_script),
    (r"\.?lefthook(?:-local)?\.ya?ml", hooklaunch.lefthook),
    (r"\.pre-commit-config\.ya?ml", hooklaunch.pre_commit),
    (r"package\.json", hooklaunch.package_json),
    (r"\.gitmodules", gitfiles.gitmodules),
    (r"\.gitattributes", gitfiles.gitattributes),
    (r"[^/]*\.gitconfig|\.git/config", gitfiles.gitconfig),
]
_COMPILED = [(re.compile(rf"(?:^|/)(?:{pattern})$"), handler) for pattern, handler in _TABLE]

#: Files scanned only for agent CLIs launched with their safety checks off.
SPAWN_ONLY = re.compile(r"(?:^|/)(?:[^/]+\.(?:sh|bash|zsh|ps1|psm1|cmd|bat)|\.github/workflows/[^/]+\.ya?ml)$")


def normalized(path: str) -> str:
    """Lower case, forward slashes, `./` and repeated separators collapsed."""
    parts = [p for p in path.replace("\\", "/").lower().split("/") if p not in ("", ".")]
    return "/".join(parts)


def handler_for(path: str) -> Handler | None:
    low = normalized(path)
    return next((handler for pattern, handler in _COMPILED if pattern.search(low)), None)
