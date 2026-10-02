"""Uploaders other than curl and wget: raw sockets, scp/rsync/sftp/ftp, ssh, cloud storage CLIs, gh and git remotes."""

from __future__ import annotations

import re

from chock_shellparse import Cmd, flags_of, git_parts, positionals
from egress_core import ASK_PERSON, Allowlist, Verdict, confirm, permitted, refuse, unapproved

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
GIT_VALUE = frozenset(("--repo", "--receive-pack", "--exec", "-o", "--push-option"))
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


def remote_host(operand: str) -> str | None:
    """The host of an scp/rsync/sftp operand (`user@host:path`, `host::module`, `scp://host/p`), or None for a local path."""
    if "://" in operand:
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
    """openssl s_client -connect host: block with a file fed in, ask otherwise (a piped body is not visible here)."""
    if cmd.name != "openssl" or "s_client" not in cmd.args or "-connect" not in cmd.args:
        return None
    index = cmd.args.index("-connect") + 1
    target = cmd.args[index] if index < len(cmd.args) else ""
    if not target or permitted(allow, target):
        return None
    if [r for r in cmd.reads if r != "/dev/null"]:
        return unapproved(allow, "openssl s_client to", target)
    return confirm(
        f"'openssl s_client -connect {target[:60]}' may carry piped data to a host outside the allowlist. {ASK_PERSON}"
    )


def copiers(cmd: Cmd, allow: Allowlist) -> Verdict:
    """scp and rsync with a remote destination; sftp and ftp to a host (they can put whatever is typed or batched)."""
    if cmd.name in COPY_VALUE:
        ops = positionals(cmd.args, COPY_VALUE[cmd.name])
        host = remote_host(ops[-1]) if len(ops) > 1 else None
        return unapproved(allow, f"{cmd.name} to", host) if host else None
    if cmd.name in ("sftp", "ftp", "lftp"):
        ops = positionals(
            cmd.args, frozenset(("-P", "-i", "-o", "-F", "-J", "-b", "-c", "-l", "-S", "-B", "-R", "-s", "-u", "-p"))
        )
        host = (remote_host(ops[0]) or ops[0]) if ops else None
        return unapproved(allow, f"{cmd.name} to", host) if host else None
    return None


def ssh(cmd: Cmd, allow: Allowlist) -> Verdict:
    """ssh to a host outside the allowlist: block with a remote command (`cat file`), ask for a bare login."""
    if cmd.name != "ssh":
        return None
    ops = positionals(cmd.args, SSH_VALUE)
    if not ops or permitted(allow, ops[0]):
        return None
    if len(ops) > 1:
        return unapproved(allow, "ssh command on", ops[0])
    return confirm(
        f"'ssh {ops[0][:60]}' opens a session outside the egress allowlist; anything piped in leaves. {ASK_PERSON}"
    )


def cloud(cmd: Cmd) -> Verdict:
    """aws s3 cp|sync|mv to s3://, gsutil/gcloud storage cp|rsync|mv to gs://, az storage upload: bucket names are not hosts."""
    ops = positionals(cmd.args, CLOUD_VALUE)
    ending = ops[-1] if ops else ""
    sends = (
        (
            cmd.name == "aws"
            and ops[:1] == ["s3"]
            and ops[1:2] in (["cp"], ["sync"], ["mv"])
            and ending.startswith("s3://")
        )
        or (cmd.name == "aws" and ops[:1] == ["s3api"] and ops[1:2] in (["put-object"], ["upload-part"]))
        or (cmd.name == "gsutil" and ops[:1] in (["cp"], ["rsync"], ["mv"]) and ending.startswith("gs://"))
        or (
            cmd.name == "gcloud"
            and ops[:1] == ["storage"]
            and ops[1:2] in (["cp"], ["rsync"], ["mv"])
            and ending.startswith("gs://")
        )
        or (cmd.name == "az" and ops[:1] == ["storage"] and any(o.startswith(("upload", "sync")) for o in ops[1:4]))
    )
    if sends:
        return refuse(
            f"{cmd.name} {' '.join(ops[:3])[:60]} writes to cloud storage, which the host allowlist cannot judge. {ASK_PERSON}"
        )
    return None


def gh(cmd: Cmd) -> Verdict:
    """gh gist create and gh issue|pr create|comment with a file body publish text this guard cannot read: ask."""
    if cmd.name != "gh":
        return None
    ops = positionals(cmd.args, frozenset(("-R", "--repo")))
    file_body = bool({"-F", "--body-file"} & {a.split("=", 1)[0] for a in cmd.args})
    if ops[:2] == ["gist", "create"] or (
        ops[:1] in (["issue"], ["pr"]) and ops[1:2] in (["create"], ["comment"]) and file_body
    ):
        return confirm(
            f"'gh {' '.join(ops[:2])}' publishes file content to GitHub, outside the egress allowlist. {ASK_PERSON}"
        )
    return None


def git_urls(sub: str, conf: list[str], rest: list[str]) -> list[str]:
    """The repository URLs a git command would send to: push targets, new remotes, -c remote.X.url, git config remote.X.url."""
    ops = positionals(rest, GIT_VALUE)
    urls = [v for k, _, v in (c.partition("=") for c in conf) if REMOTE_URL_KEY.fullmatch(k.lower())]
    if sub == "push":
        urls.append(next((a.split("=", 1)[1] for a in rest if a.startswith("--repo=")), "") or next(iter(ops), ""))
    elif sub == "remote" and ops[:1] in (["add"], ["set-url"]):
        urls += ops[2:3]
    elif sub == "config" and ops[1:2] and REMOTE_URL_KEY.fullmatch(ops[0].lower()):
        urls.append(ops[1])
    return urls


def git_remote(cmd: Cmd, allow: Allowlist) -> Verdict:
    """git push <url>, git remote add|set-url <name> <url> and a remote URL set by -c or git config, outside the allowlist."""
    if cmd.name != "git":
        return None
    sub, conf, rest = git_parts(cmd.args)
    hosts = [h for url in git_urls(sub, conf, rest) if url and (h := remote_host(url))]
    return next((v for host in hosts if (v := unapproved(allow, f"git {sub} to", host))), None)
