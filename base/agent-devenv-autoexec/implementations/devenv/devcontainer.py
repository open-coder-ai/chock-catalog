"""Dev containers: initializeCommand runs on the host; lifecycle commands, privileges and mounts reach it too."""

from __future__ import annotations

import re

from devenv.agents import object_of, truthy
from devenv.commands import run
from devenv.core import ASK, BLOCK, Collector, network, norm, strings
from devenv.vscode import extensions, settings

RULE = "dev-devcontainer-init"
LIFECYCLE = ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand")
#: A bind source that hands the container the host: the Docker socket, credential folders, the home or root folder.
_HOST_SOURCE = re.compile(
    r"(?i)docker\.sock|(?:^|[/\\])\.(?:ssh|aws|kube|gnupg|docker|azure|config[/\\]gcloud)(?:[/\\]|$)"
    r"|^(?:\$\{localenv:(?:home|userprofile)\})+[/\\]?$|^~[/\\]?$|^[a-z]:[/\\]?$"
    r"|^/(?:etc|root|var|var/run|run|proc|sys|dev|home|users|var/lib/docker|private|opt|usr|srv|mnt)?/?$|^/(?:home|users)/[^/]+/?$"
)
_HOST_NAMESPACES = frozenset({"--network", "--net", "--pid", "--ipc", "--uts", "--userns", "--cgroupns"})
_MOUNT_FLAGS = frozenset({"-v", "--volume", "--mount"})
_VALUE_FLAGS = _HOST_NAMESPACES | _MOUNT_FLAGS | {"--cap-add", "--security-opt", "--device", "--volumes-from"}
_ARG = re.compile(r"^(--?[A-Za-z][\w-]*)(?:[= ]\s*(.*))?$", re.DOTALL)
_WIDE_CAPS = frozenset(
    {"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF"}
)


def host_source(spec: str) -> bool:
    """Whether a mount (`type=bind,source=X,...`, or `X:Y[:opts]` as -v takes it) binds a host path that matters."""
    text = spec.strip().strip("'\"")
    fields = [part.strip().strip("'\"").partition("=") for part in text.split(",")]
    sources = [
        value.strip().strip("'\"") for key, eq, value in fields if eq and key.strip().lower() in ("source", "src")
    ]
    if not sources and not any(eq for _, eq, _ in fields):
        drive = re.match(r"^[A-Za-z]:[\\/]", text)
        # The source ends at the first `:` outside a ${...} variable (`${localEnv:HOME}/.ssh:/root/.ssh`).
        head = re.match(r"(?:\$\{[^}]*\}|[^:])*", text[2:] if drive else text).group(0)
        sources = [text[:2] + head if drive else head]
    return any(_HOST_SOURCE.search(source) for source in sources)


def _risky_arg(flag: str, value: str) -> bool:
    if flag == "--privileged":
        return value.strip().lower() in ("", "true", "1", "yes", "on")
    if flag in _HOST_NAMESPACES:
        return value.strip().lower() == "host"
    if flag == "--cap-add":
        return value.strip().upper().removeprefix("CAP_") in _WIDE_CAPS
    if flag == "--security-opt":
        return bool(re.search(r"(?i)unconfined|disable", value))
    if flag in _MOUNT_FLAGS:
        return host_source(value)
    return flag in ("--device", "--volumes-from")


def _run_args(raw: object) -> list[tuple[str, str]]:
    """(flag, value) pairs: `--flag=value`, `--flag value` in one item, or the value in the next item."""
    args = [str(a) for a in raw if isinstance(a, str | int)] if isinstance(raw, list) else []
    pairs, index = [], 0
    while index < len(args):
        arg = args[index].strip()
        found = _ARG.match(arg)
        index += 1
        if found:
            flag, value = found.group(1).lower(), found.group(2)
        elif re.match(r"^-[A-Za-z]\S", arg):
            flag, value = arg[:2].lower(), arg[2:]
        else:
            continue
        if value is None and flag in _VALUE_FLAGS and index < len(args):
            value, index = args[index], index + 1
        pairs.append((flag, value or ""))
    return pairs


_PINNED_FEATURE = re.compile(r"^[a-z0-9.-]+(?::\d+)?/[^:@\s]+(?::(?!latest$)[^:@/\s]+|@sha256:[0-9a-f]{64})$")


def devcontainer(c: Collector) -> None:
    config = object_of(c.text)
    for command in strings(config.get("initializeCommand")):
        run(c, RULE, "initializeCommand", command, "initializeCommand runs on the host before the container exists")
    for key in LIFECYCLE:
        value = config.get(key)
        named = value.items() if isinstance(value, dict) else [("", value)]
        for name, item in named:
            for command in strings(item):
                online = network(command)
                label = "lifecycle command that reaches the network" if online else "lifecycle command"
                run(c, RULE, f"{key}.{name}" if name else key, command, label, severity=BLOCK if online else ASK)
    _privileges(c, config)
    _mounts(c, config)
    _features(c, config.get("features"))
    vscode = config.get("customizations", {})
    vscode = vscode.get("vscode") if isinstance(vscode, dict) else None
    if isinstance(vscode, dict):
        settings(c, vscode.get("settings"), "customizations.vscode.settings")
        extensions(c, {"recommendations": vscode.get("extensions")}, "customizations.vscode.extensions")


def _privileges(c: Collector, config: dict) -> None:
    if truthy(config.get("privileged")):
        c.add(RULE, "privileged=true", "container runs privileged", line=c.line_of('"privileged"'))
    for user_key in ("remoteUser", "containerUser"):
        if str(config.get(user_key, "")).lower() == "root":
            c.add(RULE, f"{user_key}=root", f"{user_key} is root", severity=ASK, line=c.line_of(user_key))
    for flag, value in _run_args(config.get("runArgs")):
        if _risky_arg(flag, value):
            spot = f"{flag}={value}" if value else flag
            c.add(RULE, f"runArgs={norm(spot)}", f"runArgs grant host access: {norm(spot)[:60]}", line=c.line_of(flag))
    caps = config.get("capAdd") if isinstance(config.get("capAdd"), list) else []
    for cap in caps:
        if str(cap).upper().removeprefix("CAP_") in _WIDE_CAPS:
            c.add(RULE, f"capAdd={str(cap).upper()}", f"capability {cap} added", line=c.line_of(str(cap)))
    opts = config.get("securityOpt") if isinstance(config.get("securityOpt"), list) else []
    for opt in opts:
        if re.search(r"(?i)unconfined|disable", str(opt)):
            c.add(
                RULE,
                f"securityOpt={norm(opt)}",
                f"security option {opt} turns confinement off",
                line=c.line_of(str(opt)),
            )


def _mounts(c: Collector, config: dict) -> None:
    mounts = config.get("mounts") if isinstance(config.get("mounts"), list) else []
    workspace = config.get("workspaceMount")
    for mount in [*mounts, *([workspace] if workspace else [])]:
        if isinstance(mount, dict):
            text = ",".join(f"{k}={v}" for k, v in mount.items())
        else:
            text = mount if isinstance(mount, str) else ""
        if host_source(text):
            c.add(RULE, f"mounts={norm(text)}", f"host path mounted: {norm(text)[:80]}", line=c.line_of("ount"))


def _features(c: Collector, features: object) -> None:
    for ref in features if isinstance(features, dict) else {}:
        text = str(ref)
        if text.startswith(("./", "../", "http://", "https://")) or not _PINNED_FEATURE.match(text):
            c.add(
                RULE,
                f"features={norm(text)}",
                f"feature not pinned to a version or digest: {norm(text)[:80]}",
                severity=ASK,
                line=c.line_of(text),
            )
