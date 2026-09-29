"""The supply pack (ASI04): agent components fetched at a version nobody reviewed."""

from __future__ import annotations

import re
from collections.abc import Iterator

from agentic_gate import mcp
from agentic_gate.model import FileText, Hit, Pack, Rule
from agentic_gate.pyast import callee, calls, is_true, keyword, settings, spreads, string_of, terminal
from agentic_gate.textscan import code_lines

PACK = Pack(
    id="supply",
    title="Agentic supply chain",
    covers="MCP server launch commands and URLs, remote model code, model hub downloads and prompt hub pulls.",
    asi=("ASI04",),
)

_OWASP = ("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",)
_GIT_SHA = re.compile(r"@[0-9a-f]{40}(?:#.*)?$")
_GIT_SPEC = re.compile(r"(?:uvx|--from)[^\n]*?(git\+[^\s\"',\])]+)")
_COMMIT = re.compile(r":[0-9a-f]{7,40}$")
_URL_KEYS = ("url", "serverUrl", "httpUrl")
_HTTP_HOST = re.compile(r"http://(?:\[([^\]]+)\]|([^/:?#\s]+))", re.IGNORECASE)
_LOCAL_HOSTS = frozenset({"localhost", "::1"})
_YAML_URL = re.compile(r"\b(?:url|serverUrl|httpUrl)\s*:\s*[\"']?(http://\S+?)[\"']?\s*$")
_LOCAL_PREFIXES = (".", "/", "~")


def _unpinned(text: FileText) -> Iterator[Hit]:
    for server in mcp.servers(text):
        found = mcp.launch(mcp.argv(server))
        if found and mcp.is_fetched_by_name(found) and not found.spec.endswith("@latest") and not mcp.is_pinned(found):
            yield Hit(
                mcp.line_for(text, server, found.spec),
                f"server {server.name!r} runs {found.tool} {found.spec!r} with no exact version.",
            )


def _git_unpinned(spec: str) -> bool:
    return spec.startswith("git+") and not _GIT_SHA.search(spec)


def _uvx_git(text: FileText) -> Iterator[Hit]:
    for server in mcp.servers(text):
        found = mcp.launch(mcp.argv(server))
        if found and found.tool == "uvx" and _git_unpinned(found.spec):
            yield Hit(mcp.line_for(text, server, found.spec), f"server {server.name!r} runs uvx from {found.spec!r}.")
    if not text.is_mcp_config:
        for line_no, line in code_lines(text):
            found_spec = _GIT_SPEC.search(line)
            if found_spec and _git_unpinned(found_spec.group(1)):
                yield Hit(line_no, f"uvx runs {found_spec.group(1)!r} with no commit SHA.")


def _is_remote_http(url: str) -> bool:
    found = _HTTP_HOST.match(url)
    host = (found.group(1) or found.group(2)).lower() if found else ""
    return bool(host) and host not in _LOCAL_HOSTS and not host.startswith("127.")


def _remote_http(text: FileText) -> Iterator[Hit]:
    for server in mcp.servers(text):
        for key in _URL_KEYS:
            url = server.body.get(key)
            if isinstance(url, str) and _is_remote_http(url):
                yield Hit(
                    mcp.line_for(text, server, url), f"server {server.name!r} connects to {url!r} over plain HTTP."
                )
    if text.kind == "python" and text.holds("mcp"):
        for line_no, value in settings(text, "url"):
            if _is_remote_http(string_of(value) or ""):
                yield Hit(line_no, "an MCP server URL uses plain HTTP to a remote host.")
    if text.kind == "yaml" and text.holds("mcp"):
        for line_no, line in code_lines(text):
            found = _YAML_URL.search(line)
            if found and _is_remote_http(found.group(1)):
                yield Hit(line_no, "an MCP server URL uses plain HTTP to a remote host.")


def _remote_code(text: FileText) -> Iterator[Hit]:
    for line_no, value in settings(text, "trust_remote_code"):
        if is_true(value):
            yield Hit(line_no, "trust_remote_code=True runs Python from the model repository on load.")


def _hf_unpinned(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        target = (string_of(call.args[0]) or "") if call.args else ""
        local = target.startswith(_LOCAL_PREFIXES)
        if terminal(call) in {"from_pretrained", "hf_hub_download"} and not (
            keyword(call, "revision") or spreads(call) or local
        ):
            yield Hit(call.lineno, f"{terminal(call)}(...) follows the hub's moving default branch.")


def _hub_pull(text: FileText) -> Iterator[Hit]:
    for call in calls(text):
        ref = string_of(call.args[0]) if call.args else None
        if callee(call).split(".")[-2:] == ["hub", "pull"] and ref and not _COMMIT.search(ref):
            yield Hit(call.lineno, f"hub.pull({ref!r}) fetches whatever the prompt's latest commit says.")


RULES: tuple[Rule, ...] = (
    Rule(
        id="supply-mcp-unpinned-package",
        pack="supply",
        title="MCP server launched from an unpinned package",
        why="An unpinned launcher fetches whatever the registry serves today and runs it with the user's privileges; a hijacked release runs on the next start.",
        kinds=("json", "toml"),
        scan=_unpinned,
        fix="pin the package to an exact version: npx -y pkg@1.2.3, uvx pkg==1.2.3 (name@latest stays with block-unpinned-agent-components).",
        refuses="an MCP server whose command is npx, uvx, bunx or pipx run with a package argument lacking an exact version",
        silent_on="npx -y pkg@1.2.3, uvx pkg==1.2.3, a local script path, a docker or python command",
        cwe=("CWE-829",),
        asi=("ASI04",),
        references=(*_OWASP, "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices"),
    ),
    Rule(
        id="supply-uvx-git-unpinned",
        pack="supply",
        title="uvx installs from git without a commit SHA",
        why="A branch or tag in a git URL moves; only a commit SHA names one reviewed tree.",
        kinds=("json", "toml", "python", "js", "yaml", "shell"),
        scan=_uvx_git,
        fix="append the full 40-hex commit: uvx --from git+https://host/org/repo@<sha> tool.",
        refuses="uvx --from git+... (or an MCP server doing so) with no @<40-hex sha> on the spec",
        silent_on="git+https://host/org/repo@<40-hex sha>, a tag-only reference is refused too",
        cwe=("CWE-829", "CWE-494"),
        asi=("ASI04",),
        references=(*_OWASP, "https://docs.astral.sh/uv/guides/tools/"),
    ),
    Rule(
        id="supply-mcp-remote-http",
        pack="supply",
        title="MCP server reached over plain HTTP",
        why="Plain HTTP lets anyone on the path read tool calls and results, or answer as the server.",
        kinds=("json", "toml", "python", "yaml"),
        scan=_remote_http,
        fix="use https:// for a remote MCP server; plain http is for localhost only.",
        refuses='an MCP server "url" starting http:// whose host is not localhost, 127.x or ::1',
        silent_on="https:// URLs, http://localhost and http://127.0.0.1",
        cwe=("CWE-319",),
        asi=("ASI04",),
        references=(*_OWASP, "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports"),
    ),
    Rule(
        id="supply-trust-remote-code",
        pack="supply",
        title="Model loaded with trust_remote_code=True",
        why="The flag executes Python from the model repository at load time, so a change in that repository is code execution on your host.",
        kinds=("python",),
        scan=_remote_code,
        fix="load with trust_remote_code=False and a natively supported architecture, or vendor and review the code at a pinned revision.",
        refuses="trust_remote_code=True in a call or config dict",
        silent_on="trust_remote_code=False or absent",
        cwe=("CWE-829", "CWE-94"),
        asi=("ASI04",),
        references=(*_OWASP, "https://huggingface.co/docs/transformers/en/models#trust-remote-code"),
    ),
    Rule(
        id="supply-hf-unpinned-revision",
        pack="supply",
        title="Hub download without a pinned revision",
        why="A hub name follows the default branch, so the weights or code you tested can change under you.",
        kinds=("python",),
        scan=_hf_unpinned,
        fix="pass revision=<commit sha> so the artifact cannot change under you.",
        refuses="from_pretrained(...) or hf_hub_download(...) with no revision= (a local path is exempt)",
        silent_on="calls passing revision=, from_pretrained on a local directory",
        cwe=("CWE-494",),
        asi=("ASI04",),
        references=(*_OWASP, "https://huggingface.co/docs/huggingface_hub/en/guides/download"),
        default="allow",
    ),
    Rule(
        id="supply-langchain-hub-unpinned",
        pack="supply",
        title="LangChain hub prompt pulled without a commit",
        why="A prompt pulled by name can be edited by its owner at any time and becomes your agent's instructions.",
        kinds=("python",),
        scan=_hub_pull,
        fix='pin the commit: hub.pull("owner/name:<commit hash>").',
        refuses='hub.pull("owner/name") with no :<commit> suffix',
        silent_on='hub.pull("owner/name:<commit hash>")',
        cwe=("CWE-494",),
        asi=("ASI04",),
        references=(
            *_OWASP,
            "https://docs.smith.langchain.com/prompt_engineering/how_to_guides/manage_prompts_programatically",
        ),
    ),
)
