"""Uploaders other than curl and wget: raw sockets, scp/rsync/sftp/ftp, ssh, cloud storage CLIs, gh and git remotes."""

from __future__ import annotations

import re

from chock_shellparse import Cmd, after, flags_of, git_parts, positionals
from egress_core import (
    ASK_PERSON,
    COMMAND_SUBST,
    WHOLE_VARIABLE,
    Allowlist,
    Verdict,
    confirm,
    permitted,
    refuse,
    unapproved,
)

NC = frozenset(("nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"))
NC_VALUE = frozenset(("-p", "-s", "-w", "-i", "-I", "-O", "-P", "-q", "-T", "-X", "-x", "-m", "-e", "-c", "-g", "-G"))
SOCAT_ADDRESS = re.compile(
    r"(?:tcp|udp|sctp|ssl|openssl|socks4a?|proxy)(?![\w-]*listen)[\w-]*:(\[[^\]]+\]|[^:,]+)", re.IGNORECASE
)
REMOTE = re.compile(r"(?:[^@/:\s]+@)?(\[[^\]]+\]|[^@/:\s]{2,}):")
COPY_VALUE = {
    "scp": frozenset(("-P", "-i", "-o", "-F", "-J", "-c", "-l", "-S", "-D")),
    "rsync": frozenset(
        ("-e", "--rsh", "--rsync-path", "--port", "--exclude", "--include", "-f", "--filter", "--bwlimit")
    ),
}
GIT_VALUE = frozenset(("--repo", "--receive-pack", "--exec", "-o", "--push-option", "-t", "-m", "--track", "--master"))
INSTEAD_OF = re.compile(r"url\.(.+)\.insteadof", re.IGNORECASE)
REMOTE_URL_KEY = re.compile(r"remote\..+\.(?:push)?url")
SSH_VALUE = frozenset(
    [
        "-p",
        "-i",
        "-l",
        "-o",
        "-F",
        "-J",
        "-L",
        "-R",
        "-D",
        "-b",
        "-c",
        "-E",
        "-e",
        "-I",
        "-m",
        "-O",
        "-Q",
        "-S",
        "-W",
        "-w",
    ]
)
CLOUD_VALUE = frozenset(
    (
        "--profile",
        "--region",
        "--endpoint-url",
        "--output",
        "--query",
        "--ca-bundle",
        "--color",
        "-h",
        "-o",
        "-i",
        "-u",
        "--project",
        "--account",
    )
)


def remote_host(operand: str, *, variable: bool = False) -> str | None:
    """The host of an scp/rsync/sftp operand (`user@host:path`, `host::module`, `scp://host/p`), or None for a local path."""
    if "://" in operand:
        return None if operand.lower().startswith("file:") else operand
    if variable and WHOLE_VARIABLE.fullmatch(operand):
        return operand
    match = None if operand.startswith(("/", ".", "~")) else REMOTE.match(operand)
    return match.group(1) if match else None


def sockets(cmd: Cmd, allow: Allowlist) -> Verdict:
    """nc, ncat, telnet, socat: a connection to a host outside the allowlist moves whatever is piped or redirected in."""
    name = cmd.name.rsplit("/", 1)[-1]
    if name in NC:
        if flags_of(cmd.args) & {"-l", "-z", "-h", "--listen", "--help"}:
            return None
        ops = positionals(cmd.args, NC_VALUE)
        hosts = ops[:1]
    elif name == "telnet":
        hosts = positionals(cmd.args, frozenset(("-l", "-b", "-e", "-S", "-X")))[:1]
    elif name == "socat":
        hosts = [m.group(1) for arg in cmd.args if (m := SOCAT_ADDRESS.match(arg))]
    else:
        return None
    return next((v for host in hosts if (v := unapproved(allow, f"{name} to", host))), None)


def openssl(cmd: Cmd, allow: Allowlist) -> Verdict:
    """openssl s_client -connect|-host: block with a file fed in, ask otherwise (a piped body is not visible here)."""
    if cmd.name != "openssl" or "s_client" not in cmd.args:
        return None
    flag = next((a for a in cmd.args if a.split("=", 1)[0] in ("-connect", "-host")), "")
    target = flag.partition("=")[2] or after(cmd.args, flag)
    if not target or permitted(allow, target):
        return None
    if [r for r in cmd.reads if r != "/dev/null"]:
        return unapproved(allow, "openssl s_client to", target)
    return confirm(
        f"'openssl s_client {target[:60]}' may carry piped data to a host outside the allowlist. {ASK_PERSON}"
    )


def copiers(cmd: Cmd, allow: Allowlist) -> Verdict:
    """scp and rsync with a remote destination; sftp and ftp to a host (they can put whatever is typed or batched)."""
    if cmd.name in COPY_VALUE:
        ops = positionals(cmd.args, COPY_VALUE[cmd.name])
        host = remote_host(ops[-1], variable=cmd.name == "scp") if len(ops) > 1 else None
        return unapproved(allow, f"{cmd.name} to", host) if host else None
    if cmd.name in ("sftp", "ftp", "lftp"):
        ops = positionals(
            cmd.args, frozenset(("-P", "-i", "-o", "-F", "-J", "-b", "-c", "-l", "-S", "-B", "-R", "-s", "-u", "-p"))
        )
        host = (remote_host(ops[0]) or ops[0]) if ops else None
        return unapproved(allow, f"{cmd.name} to", host) if host else None
    return None


def ssh(cmd: Cmd, allow: Allowlist) -> Verdict:
    """ssh to a host outside the allowlist: block with a remote command, ask for a bare login or a jump/proxy command."""
    if cmd.name != "ssh":
        return None
    if "-J" in cmd.args or re.search(r"proxy(?:command|jump)", " ".join(cmd.args), re.IGNORECASE):
        return confirm(
            f"an ssh jump host or proxy command sends the connection through a host the line does not show. {ASK_PERSON}"
        )
    ops = positionals(cmd.args, SSH_VALUE)
    if not ops or permitted(allow, ops[0]):
        return None
    if len(ops) > 1:
        return unapproved(allow, "ssh command on", ops[0])
    return confirm(
        f"'ssh {ops[0][:60]}' opens a session outside the egress allowlist; anything piped in leaves. {ASK_PERSON}"
    )


def cloud(cmd: Cmd) -> Verdict:
    """aws s3 cp|sync|mv, gsutil and gcloud storage cp|rsync|mv, az storage upload: a bucket as destination, not a source."""
    ops = positionals(cmd.args, CLOUD_VALUE)
    storage = ops[1:] if cmd.name == "gcloud" and ops[:1] in (["alpha"], ["beta"]) else ops
    scheme = {"aws": "s3://", "gsutil": "gs://", "gcloud": "gs://"}.get(cmd.name, "")
    verbs = (["cp"], ["sync"], ["mv"]) if cmd.name == "aws" else (["cp"], ["rsync"], ["mv"])
    lead = {"aws": 2, "gcloud": 2, "gsutil": 1}.get(cmd.name, 0)
    sends = (
        (cmd.name == "aws" and ops[:1] == ["s3"] and ops[1:2] in verbs)
        or (cmd.name == "gsutil" and ops[:1] in verbs)
        or (cmd.name == "gcloud" and storage[:1] == ["storage"] and storage[1:2] in verbs)
    ) and any(o.startswith(scheme) for o in (storage if cmd.name == "gcloud" else ops)[lead + 1 :])
    sends = sends or (cmd.name == "aws" and ops[:1] == ["s3api"] and ops[1:2] in (["put-object"], ["upload-part"]))
    sends = sends or (
        cmd.name == "az" and ops[:1] == ["storage"] and any(o.startswith(("upload", "sync")) for o in ops[1:4])
    )
    if sends:
        return refuse(
            f"{cmd.name} {' '.join(ops[:3])[:60]} writes to cloud storage, which the host allowlist cannot judge. {ASK_PERSON}"
        )
    return None


def gh(cmd: Cmd) -> Verdict:
    """gh gist create, issue|pr create|comment|review with a file or substituted body, gh api writes, release upload: ask."""
    if cmd.name != "gh":
        return None
    ops = positionals(cmd.args, frozenset(("-R", "--repo")))
    head = ops[:2]
    body = any(a.startswith(("-F", "--body-file")) or COMMAND_SUBST.search(a) for a in cmd.args)
    writes_api = ops[:1] == ["api"] and any(
        a in ("--input",) or a.upper() in ("POST", "PUT", "PATCH") for a in cmd.args
    )
    publishes = (
        head in (["gist", "create"], ["release", "upload"])
        or (ops[:1] in (["issue"], ["pr"]) and ops[1:2] in (["create"], ["comment"], ["review"], ["edit"]) and body)
        or writes_api
    )
    if publishes:
        return confirm(f"'gh {' '.join(head)}' publishes content to GitHub, outside the egress allowlist. {ASK_PERSON}")
    return None


def git_urls(sub: str, conf: list[str], rest: list[str]) -> list[str]:
    """The repository URLs a git command would send to: push targets, new remotes, remote.X.url and url.X.insteadOf settings."""
    ops = positionals(rest, GIT_VALUE)
    keyed = [(k, v) for k, _, v in (c.partition("=") for c in conf)]
    if sub == "config" and ops[1:2]:
        keyed.append((ops[0], ops[1]))
    urls = [v for k, v in keyed if REMOTE_URL_KEY.fullmatch(k.lower())]
    urls += [m.group(1) for k, _ in keyed if (m := INSTEAD_OF.fullmatch(k))]
    if sub == "push":
        flag = after(rest, "--repo") or next((a.split("=", 1)[1] for a in rest if a.startswith("--repo=")), "")
        urls.append(flag or next(iter(ops), ""))
    elif sub == "remote" and ops[:1] in (["add"], ["set-url"]):
        urls += ops[2:3]
    return urls


def git_remote(cmd: Cmd, allow: Allowlist) -> Verdict:
    """git push <url>, git remote add|set-url <name> <url> and a remote URL set by -c or git config, outside the allowlist."""
    if cmd.name != "git":
        return None
    sub, conf, rest = git_parts(cmd.args)
    hosts = [h for url in git_urls(sub, conf, rest) if url and (h := remote_host(url, variable=True))]
    return next((v for host in hosts if (v := unapproved(allow, f"git {sub} to", host))), None)
