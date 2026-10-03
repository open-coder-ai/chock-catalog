"""verify-mcp-allowlist: the rules one server entry is judged by (urls, credentials, options, floors, allowlist)."""

from __future__ import annotations

import pytest
from policies import mcpkit

g = mcpkit.gate()
rules, entry, allowlist, tables = g.rules, g.entry, g.allowlist, g.rules.tables
D = mcpkit.DIGEST


def server(config: dict, name: str = "s") -> object:
    return entry.from_config(name, config)


def rule_names(config: dict, allowed: tuple = ()) -> list[str]:
    return [rule for rule, _ in rules.judge(server(config), allowed)]


def allowed(*items: dict) -> tuple:
    return allowlist.parse(mcpkit.allowlist_text(*items))


PIN = ["pkg@1.0.0"]


@pytest.mark.parametrize(
    ("url", "want"),
    [
        ("https://mcp.example.invalid/mcp", []),
        ("http://mcp.example.invalid/mcp", ["url"]),
        ("mcp.example.invalid/mcp", ["url"]),
        ("ws://mcp.example.invalid/mcp", ["url"]),
        ("https://user:pw@mcp.example.invalid/mcp", ["url"]),
        ("https://mcp.example.invalid\\@evil.invalid/", ["url"]),
        ("https://[::1", ["url"]),
        ("https://0x7f.1/mcp", ["url"]),
    ],
)
def test_a_url_must_be_https_with_no_credentials_and_one_reading(url: str, want: list[str]) -> None:
    got = [r for r in rule_names({"url": url}) if r != "allowlist"]
    assert got == want


@pytest.mark.parametrize("key", ["url", "httpUrl", "serverUrl"])
def test_every_url_key_is_read(key: str) -> None:
    assert "url" in rule_names({key: "http://a.example.invalid/"})


@pytest.mark.parametrize(
    "value",
    [
        "${TOKEN}",
        "$TOKEN",
        "{env:TOKEN}",
        "${env:TOKEN}",
        "${input:token}",
        "%TOKEN%",
        "Bearer ${TOKEN}",
        "basic $U:$P",
        "",
    ],
)
def test_a_reference_is_not_a_literal_credential(value: str) -> None:
    config = {"command": "npx", "args": PIN, "env": {"API_TOKEN": value}, "headers": {"Authorization": value}}
    assert "secret" not in rule_names(config)


@pytest.mark.parametrize(
    "value", ["abc123", "Bearer abc123", "${TOKEN:-fallback}", "prefix-${TOKEN}", "${TOKEN}-suffix", "token"]
)
def test_a_literal_in_a_credential_slot_is_refused(value: str) -> None:
    for slot in ("env", "environment", "headers", "http_headers"):
        names = rule_names({"command": "npx", "args": PIN, slot: {"X_API_KEY": value}})
        assert names.count("secret") == 1, slot


@pytest.mark.parametrize(
    "name",
    [
        "TOKEN",
        "api_key",
        "MY_SECRET",
        "DB_PASSWORD",
        "AUTHORIZATION",
        "X-Auth",
        "GITHUB_CREDENTIALS",
        "COOKIE",
        "BEARER",
    ],
)
def test_every_credential_word_in_a_name_counts(name: str) -> None:
    assert "secret" in rule_names({"command": "npx", "args": PIN, "env": {name: "literal"}})


def test_a_variable_that_is_not_a_credential_may_hold_a_literal() -> None:
    assert "secret" not in rule_names({"command": "npx", "args": PIN, "env": {"LOG_LEVEL": "debug", "PORT": 8080}})


@pytest.mark.parametrize(
    ("args", "refused"),
    [
        (["-e", "GITHUB_TOKEN=ghp_fake"], True),
        (["--env=API_KEY=abc"], True),
        (["-e", "GITHUB_TOKEN"], False),
        (["-e", "GITHUB_TOKEN=${GITHUB_TOKEN}"], False),
        (["-e", "LOG=debug"], False),
        (["--token", "abc"], True),
        (["--api-key=abc"], True),
        (["--password", "x"], True),
        (["--access-token", "x"], True),
        (["--token", "${T}"], False),
        (["--token", "--other"], False),
        (["--token-file", "/x"], False),
        (["--secret-path=/x"], False),
        (["--tokens-per-page", "5"], False),
        (["--header", "Authorization: Bearer abc"], True),
        (["-H", "X-Api-Key: abc"], True),
        (["--header", "Authorization: Bearer ${T}"], False),
        (["--header", "Accept: text/plain"], False),
        (["--header", "no-colon"], False),
    ],
)
def test_a_credential_passed_as_an_argument_is_refused(args: list[str], refused: bool) -> None:
    got = rules.judge(server({"command": "docker", "args": ["run", *args, f"img@{D}"]}), ())
    assert ("secret" in [r for r, _ in got]) is refused


def test_a_credential_scalar_key_in_the_entry_is_refused_unless_a_reference() -> None:
    assert "secret" in rule_names({"command": "npx", "args": PIN, "bearer_token": "abc"})
    assert "secret" in rule_names({"command": "npx", "args": PIN, "apiKey": "abc"})
    assert "secret" not in rule_names({"command": "npx", "args": PIN, "apiKey": "${KEY}"})
    assert "secret" not in rule_names({"url": "https://a.example.invalid/", "bearer_token_env_var": "TOKEN"})
    assert "secret" not in rule_names({"command": "npx", "args": PIN, "authType": "oauth"})


@pytest.mark.parametrize(
    "args",
    [
        ["--allow-all"],
        ["--no-sandbox"],
        ["--dangerously-skip-permissions"],
        ["--privileged"],
        ["--index-url", "https://i.invalid"],
        ["--extra-index-url=https://i.invalid"],
        ["--registry", "https://r.invalid"],
        ["--NETWORK=host"],
        ["--network", "host"],
        ["--net=host"],
        ["--pid", "host"],
        ["--cap-add", "SYS_ADMIN"],
        ["--cap-add=ALL"],
        ["--security-opt", "seccomp=unconfined"],
    ],
)
def test_a_denied_option_is_refused(args: list[str]) -> None:
    assert "option" in rule_names({"command": "npx", "args": [*PIN, *args]})


@pytest.mark.parametrize(
    "args", [["--network", "none"], ["--network"], ["--cap-add", "NET_BIND_SERVICE"], ["--port", "1"]]
)
def test_an_ordinary_option_passes(args: list[str]) -> None:
    assert "option" not in rule_names({"command": "npx", "args": [*PIN, *args]})


def test_one_denied_option_is_one_finding() -> None:
    config = {"command": "npx", "args": [*PIN, "--no-sandbox", "--no-sandbox=1"]}
    assert rule_names(config).count("option") == 1


@pytest.mark.parametrize(
    "key", ["NODE_OPTIONS", "node_options", "LD_PRELOAD", "PYTHONPATH", "NPM_CONFIG_REGISTRY", "HTTPS_PROXY"]
)
def test_a_denied_environment_variable_is_refused(key: str) -> None:
    assert "option" in rule_names({"command": "npx", "args": PIN, "env": {key: "x"}})


@pytest.mark.parametrize(
    ("mount", "refused"),
    [
        ("/:/host", True),
        ("/var/run/docker.sock:/var/run/docker.sock", True),
        ("~:/h", True),
        ("$HOME:/h", True),
        ("${HOME}:/h", True),
        ("type=bind,source=/,target=/h", True),
        ("type=bind,src=/var/run/docker.sock,target=/s", True),
        ("/work:/work", False),
        ("type=bind,source=/work,target=/w", False),
        ("named-volume:/data", False),
    ],
)
def test_a_dangerous_mount_is_refused(mount: str, refused: bool) -> None:
    for flag in ("-v", "--volume", "--mount"):
        config = {"command": "docker", "args": ["run", flag, mount, f"img@{D}"]}
        assert ("option" in rule_names(config)) is refused, (flag, mount)


@pytest.mark.parametrize(
    ("args", "refused"),
    [
        (["-y", "mcp-remote@0.1.15", "https://a.example.invalid/"], True),
        (["-y", "mcp-remote@0.1.16", "https://a.example.invalid/"], False),
        (["-y", "mcp-remote@0.2.0"], False),
        (["-y", "mcp-remote@0.0.99"], True),
        (["-y", "mcp-remote@0.1.16-beta.1"], False),
        (["-y", "mcp-remote@latest"], False),
        (["-y", "other@0.0.1"], False),
    ],
)
def test_a_package_below_its_floor_is_refused(args: list[str], refused: bool) -> None:
    assert ("floor" in rule_names({"command": "npx", "args": args})) is refused


@pytest.mark.parametrize(
    ("spec", "refused"),
    [
        ("mcp-server-git==2025.12.17", True),
        ("mcp-server-git==2025.12.18", False),
        ("mcp_server_git==2025.12.18", False),
        ("MCP-Server-Git==2024.1.1", True),
        ("mcp-server-git==2026.1.1", False),
        ("mcp-server-git", False),
    ],
)
def test_a_python_package_floor_is_compared_numerically(spec: str, refused: bool) -> None:
    assert ("floor" in rule_names({"command": "uvx", "args": [spec]})) is refused


def test_an_inspector_that_is_not_pinned_is_refused_as_unpinned() -> None:
    assert rule_names({"command": "npx", "args": ["-y", "@modelcontextprotocol/inspector"]}) == [
        "unpinned",
        "allowlist",
    ]
    assert "unpinned" not in rule_names({"command": "npx", "args": ["-y", "@modelcontextprotocol/inspector@0.17.2"]})


def test_the_versions_compare_as_numbers() -> None:
    assert rules.version("2025.12.18") > rules.version("2025.2.1")
    assert rules.version("0.1.16-beta") == (0, 1, 16)
    assert rules.version("x.1") == (0, 1)


def test_an_entry_with_nothing_to_run_is_unverifiable() -> None:
    assert rule_names({"source": "extension"}) == ["no-source", "allowlist"]
    assert rule_names({}) == ["no-source", "allowlist"]


def test_the_findings_never_quote_the_launch_line() -> None:
    config = {
        "command": "npx",
        "args": ["-y", "evil@latest", "--token", "SECRET-VALUE-123"],
        "env": {"API_KEY": "SECRET-ENV-456"},  # pragma: allowlist secret
    }
    text = " ".join(message for _, message in rules.judge(server(config), ()))
    assert "SECRET" not in text
    assert "API_KEY" in text


FS = mcpkit.FS_ALLOWED


REMOTE = mcpkit.REMOTE_ALLOWED


def test_a_credential_flag_with_nothing_after_it_is_read_as_empty() -> None:
    assert rules._flag_values(("run", "-e"), rules.ENV_FLAGS) == []
    assert rules._flag_values(("run", "--env=A=1", "-E", "B=2"), rules.ENV_FLAGS) == ["A=1", "B=2"]
