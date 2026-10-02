"""A command a config makes a tool run, the environment names that redirect one, and chock's own wiring."""

from __future__ import annotations

import re

from devenv.core import BLOCK, Collector, norm, risky

#: The launcher `chock sync` writes into agent hook configs, running only files protect-agent-config
#: guards (.chock/bin, .chock/compiled, policy implementations). Matched whole, so anything added fails it.
_LAUNCH = (
    r'git -c "alias\.chock-hook=!test -f \.chock/bin/launch\.sh \|\| \{ echo chock: no \.chock/bin/launch\.sh here,'
    r' run chock sync --repo \. >&2; exit 2; \}; sh \.chock/bin/launch\.sh" chock-hook \.chock/bin/[a-z_]+\.py'
)
_FILE = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_TARGET = (
    rf' --(?:guard|gate|tool-call|record) "(?:\.agents/policies/[a-z0-9-]+/implementations/{_FILE}'
    rf'|\.chock/compiled/[a-z0-9-]+/[a-z-]+/{_FILE}\.json)"'
)
_WINDOWS = r"; if \(\$null -eq \$LASTEXITCODE\) \{ exit 2 \}; exit \$LASTEXITCODE"
CHOCK_WIRING = re.compile(rf"{_LAUNCH}(?:{_TARGET})?|& {_LAUNCH}(?:{_TARGET})?{_WINDOWS}")


def run(  # noqa: PLR0913 -- the finding's parts, named at every call
    c: Collector,
    rule: str,
    where: str,
    command: str,
    label: str,
    *,
    severity: str | None = BLOCK,
    line: int | None = None,
) -> None:
    """Report a command a tool runs on its own; one that fetches and runs code, or is encoded, always blocks.

    `severity=None` reports the command only when it is such a payload (it still counts for cross-references).

    The message names where it is and why, never the command, which may carry a token.
    """
    text = command.strip()
    if not text or CHOCK_WIRING.fullmatch(text):
        return
    reason = risky(text)
    line = line or c.line_of(re.sub(r"(?:\.\d+)+$", "", where).rsplit(".", 1)[-1], text[:40])
    c.commands.append((where, text, line))
    if severity is None and not reason:
        return
    shown = f"{label} at {where}" + (f", and it {reason}" if reason else "")
    c.add(rule, f"{where}={norm(text)}", shown, severity=BLOCK if reason or severity is None else severity, line=line)


_DANGEROUS_ENV = re.compile(
    r"[A-Z0-9_]*_(?:BASE_URL|BASEURL|ENDPOINT|API_URL|API_BASE)|DOCKER_HOST|DOCKER_CONTEXT"
    r"|(?:HTTPS?|ALL|NO|FTP|GRPC)_PROXY|NODE_OPTIONS|NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS"
    r"|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_[A-Z_]+|PATH|PYTHONPATH|PYTHONSTARTUP|PYTHONHTTPSVERIFY"
    r"|PYTHONWARNINGS|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS"
    r"|CLAUDE_CODE_SHELL|CLAUDE_CODE_SHELL_PREFIX|CLAUDE_ENV_FILE|CLAUDE_CONFIG_DIR"
    r"|[A-Z0-9_]*_(?:SHELL_PREFIX|ENV_FILE|COMMAND|HELPER|EXECUTABLE|BINARY|BIN_PATH|PLUGIN_DIR)"
    r"|BASH_ENV|ENV|PROMPT_COMMAND|ZDOTDIR|SHELL|EDITOR|VISUAL|PAGER|BROWSER"
    r"|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|GIT_SSL_NO_VERIFY|GIT_SSL_CAINFO"
    r"|GIT_CONFIG[A-Z_0-9]*|GIT_EXEC_PATH|GIT_SSH|GIT_SSH_COMMAND|GIT_ASKPASS|GIT_PROXY_COMMAND|GIT_EDITOR"
    r"|SSH_ASKPASS|SUDO_ASKPASS|NPM_CONFIG_[A-Z_]+|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|PIP_TRUSTED_HOST|UV_INDEX_URL"
    r"|[A-Z0-9_]*_API_KEY|[A-Z0-9_]*_AUTH_TOKEN|ANTHROPIC_CUSTOM_HEADERS|OTEL_EXPORTER_OTLP_[A-Z_]*"
)


def dangerous_env(name: str) -> bool:
    """An environment name that redirects an agent's endpoint, credentials, trust or the programs it runs."""
    return bool(_DANGEROUS_ENV.fullmatch(name.strip().upper()))


def env_overrides(c: Collector, rule: str, where: str, env: object) -> None:
    if not isinstance(env, dict):
        return
    for name, value in env.items():
        if dangerous_env(str(name)):
            c.add(
                rule,
                f"{where}.{name}={norm(value)}",
                f"environment override {name} at {where}: it can redirect the agent's endpoint, credentials or programs",
                line=c.line_of(where.split(".", 1)[0], str(name)),
            )
