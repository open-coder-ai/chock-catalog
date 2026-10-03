"""The rules one MCP server entry is judged by; each finding is a (rule, message) pair that never quotes the launch line."""

from __future__ import annotations

import re

from chock_scan.hosts import UnparseableError
from chock_scan.urls import parse_url

from mcpcheck import launchers, tables
from mcpcheck.allowlist import Allowed, matches
from mcpcheck.entry import Server, is_reference, literal_secrets

Finding = tuple[str, str]
#: The rules that refuse (the v1 tier); every other rule is new in v2 and only warns while it is observed (D15).
ENFORCED = frozenset({"allowlist"})
SECRET_FLAG = re.compile(
    r"-{1,2}(?:[a-z0-9]+-)*(?:token|secret|password|passwd|api-?key|apikey|authorization|bearer|credentials?)"
    r"(?:-[a-z0-9]+)*",
    re.IGNORECASE,
)
NOT_A_VALUE = re.compile(r".*-(?:file|path|env|env-var|var)$", re.IGNORECASE)
ENV_FLAGS = frozenset({"-e", "--env"})
HEADER_FLAGS = frozenset({"-h", "--header"})
MOUNT_FLAGS = frozenset({"-v", "--volume", "--mount"})
HOME_SOURCES = frozenset({"~", "$home", "${home}"})


def version(text: str) -> tuple[int, ...]:
    """The numeric parts of a version, leading digits only per part (2025.12.18 -> (2025, 12, 18))."""
    return tuple(int(m.group()) if (m := re.match(r"\d+", part)) else 0 for part in text.split("."))


def _flag_values(args: tuple[str, ...], flags: frozenset[str]) -> list[str]:
    """Every value given to any of the flags, as `--flag value` or `--flag=value`."""
    found = []
    for i, arg in enumerate(args):
        flag, eq, value = arg.partition("=")
        if flag.lower() in flags:
            if eq:
                found.append(value)
            elif i + 1 < len(args):
                found.append(args[i + 1])
    return found


def _options(server: Server) -> list[Finding]:
    deny = tables.denylist()
    seen = set()
    for i, arg in enumerate(server.args):
        flag = arg.partition("=")[0].lower()
        joined = (
            arg.lower() if "=" in arg else f"{flag}={server.args[i + 1].lower()}" if i + 1 < len(server.args) else ""
        )
        if flag in deny["options"] or joined in deny["option_values"]:
            seen.add(flag)
    keys = [key for key, _ in server.env if key.upper() in deny["env_keys"]]
    return [("option", f"it passes the denied option {flag}") for flag in sorted(seen)] + [
        ("option", f"it sets the denied environment variable {key}") for key in sorted(keys)
    ]


def _mounts(server: Server) -> list[Finding]:
    found = []
    for value in _flag_values(server.args, MOUNT_FLAGS):
        mount = dict(part.partition("=")[::2] for part in value.split(",")) if "=" in value else {}
        source = (mount.get("source") or mount.get("src") or value.split(":")[0]).rstrip("/")
        if source in {"", *HOME_SOURCES} or source.lower() in HOME_SOURCES or "docker.sock" in value:
            found.append(("option", "it mounts the host root, the home directory or the container socket"))
    return found


def _secrets(server: Server) -> list[Finding]:
    """Credentials written as literals: environment values, headers, credential keys, `-e K=V`, `--header`, `--token x`."""
    env_args = tuple(
        (k, v) for kv in _flag_values(server.args, ENV_FLAGS) if "=" in kv for k, _, v in [kv.partition("=")]
    )
    header_args = tuple(
        (name.strip(), value.strip())
        for header in _flag_values(server.args, HEADER_FLAGS)
        if ":" in header
        for name, _, value in [header.partition(":")]
    )
    names = [
        *literal_secrets(server.env),
        *literal_secrets(server.headers),
        *literal_secrets(env_args),
        *literal_secrets(header_args),
        *(name for name, value in server.secrets if not is_reference(value)),
    ]
    found = [
        ("secret", f"it sets a literal credential in {name}; use a reference such as ${{VAR}}")
        for name in sorted(set(names))
    ]
    for i, arg in enumerate(server.args):
        flag, eq, value = arg.partition("=")
        value = value if eq else (server.args[i + 1] if i + 1 < len(server.args) else "")
        if (
            SECRET_FLAG.fullmatch(flag)
            and not NOT_A_VALUE.fullmatch(flag)
            and not value.startswith("-")
            and not is_reference(value)
        ):
            found.append(("secret", f"it passes a literal credential in the argument {flag}"))
    return found


def _urls(server: Server) -> list[Finding]:
    found = []
    for url in server.urls:
        try:
            parsed = parse_url(url)
        except UnparseableError:
            found.append(("url", "its url cannot be read the same way by every client, so its host cannot be verified"))
            continue
        if parsed.scheme != "https":
            found.append(("url", "its url is not https"))
        if parsed.userinfo:
            found.append(("url", "its url embeds credentials"))
    return found


def _floor(launch: launchers.Launch) -> list[Finding]:
    if launch.package is None or launch.package[2] is None:
        return []
    ecosystem, name, exact = launch.package
    floor = tables.floors().get((ecosystem, name))
    return (
        [("floor", f"it runs {name} {exact}, older than the minimum {floor}")]
        if floor and version(exact) < version(floor)
        else []
    )


def _listed(server: Server, allowed: tuple[Allowed, ...]) -> list[Finding]:
    named = [entry for entry in allowed if entry.name == server.name]
    if not named:
        return [("allowlist", "it is not on the allowlist")]
    if not any(matches(server, entry) for entry in named):
        return [
            (
                "allowlist",
                "it is on the allowlist, but its command, arguments or url host differ from the approved entry",
            )
        ]
    return []


def judge(server: Server, allowed: tuple[Allowed, ...]) -> list[Finding]:
    """Every finding for one server entry: structure first, then the allowlist."""
    found: list[Finding] = []
    if not server.launcher and not server.urls:
        found.append(("no-source", "it has neither a command nor a url, so it cannot be verified"))
    launch = launchers.analyze(server.launcher, list(server.args)) if server.launcher else launchers.Launch("")
    return [
        *found,
        *launch.issues,
        *_urls(server),
        *_secrets(server),
        *_options(server),
        *_mounts(server),
        *_floor(launch),
        *_listed(server, allowed),
    ]
