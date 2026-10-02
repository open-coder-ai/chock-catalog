"""Dev containers: initializeCommand runs on the host; lifecycle commands, privileges and mounts reach it too."""

from __future__ import annotations

import re

from devenv.agents import object_of, truthy
from devenv.commands import run
from devenv.core import ASK, BLOCK, Collector, network, norm, strings
from devenv.vscode import extensions, settings

RULE = "dev-devcontainer-init"
LIFECYCLE = ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand")
_HOST_PATHS = re.compile(
    r"(?i)(?:docker\.sock|/\.ssh\b|/\.aws\b|/\.kube\b|/\.config/gcloud|/\.gnupg|/\.docker\b|\$\{localenv:home\}"
    r"|\$\{localenv:userprofile\}|(?:source|src)=/(?:,|$)|^/(?::|$))"
)
_PRIVILEGED_ARG = re.compile(
    r"(?i)^--privileged$|^--(?:network|net|pid|ipc|uts|userns)[= ]host$|^--cap-add[= ](?:all|sys_admin|sys_ptrace|net_admin|sys_module)$"
    r"|^--security-opt[= ](?:seccomp|apparmor|label)[=:](?:unconfined|disable)$|^--device\b"
)
_WIDE_CAPS = frozenset({"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH"})
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
    args = (
        [str(a) for a in config.get("runArgs", []) if isinstance(a, str | int)]
        if isinstance(config.get("runArgs"), list)
        else []
    )
    joined = [" ".join(args[i : i + 2]) for i in range(len(args))]
    for arg in {*args, *joined}:
        if _PRIVILEGED_ARG.search(arg) or (
            arg.startswith(("-v ", "--volume ", "--mount ")) and _HOST_PATHS.search(arg)
        ):
            c.add(
                RULE,
                f"runArgs={norm(arg)}",
                f"runArgs grant host access: {norm(arg)[:60]}",
                line=c.line_of(arg.split()[0]),
            )
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
    for mount in mounts:
        text = (
            mount
            if isinstance(mount, str)
            else ",".join(f"{k}={v}" for k, v in mount.items())
            if isinstance(mount, dict)
            else ""
        )
        if _HOST_PATHS.search(text):
            c.add(RULE, f"mounts={norm(text)}", f"host path mounted: {norm(text)[:80]}", line=c.line_of("mounts"))


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
