#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a command that sends data to a host outside the egress allowlist: curl/wget/iwr uploads, raw sockets, scp/rsync,
# ssh, cloud-storage CLIs, git remotes, and data hidden in a URL or hostname. Ask where the destination or code is opaque.
# A tool-time floor, not a network sandbox: fetch-only traffic is left alone, and a determined adversary needs real sandboxing.

import os
import shlex
import sys
from pathlib import Path

import egress_exfil as exfil
import egress_scan as scan
import egress_upload as upload
from chock_shellparse import Cmd, commands
from egress_core import BLOCK, Allowlist, Verdict, load_allowlist
from egress_http import http_target, upload_verdict

DEPTH = 3


def judge(cmd: Cmd, allow: Allowlist) -> list[Verdict]:
    """Every verdict one simple command earns."""
    urls, uploads, pre = http_target(cmd, allow)
    found = [pre, upload_verdict(allow, urls) if uploads else None, exfil.get_exfil(allow, urls)]
    found += [exfil.dns_exfil(cmd), exfil.interpreter_http(cmd), exfil.rewires_clients(cmd)]
    found += [
        upload.sockets(cmd, allow),
        upload.openssl(cmd, allow),
        upload.copiers(cmd, allow),
        upload.ssh(cmd, allow),
    ]
    found += [upload.cloud(cmd), upload.gh(cmd), upload.git_remote(cmd, allow)]
    return found


def judged(raw: str, allow: Allowlist, depth: int = 0) -> list[Verdict]:
    """Verdicts for every command of a line, of heredocs fed to a shell, of find -exec and of every substitution body."""
    found = [] if depth else [exfil.backtick_client(raw), scan.dev_sockets(raw, allow)]
    for cmd in commands(raw):
        for each in (cmd, *scan.find_exec(cmd)):
            found += judge(each, allow)
        if cmd.name in scan.SHELLS and cmd.doc and depth < DEPTH:
            found += judged(cmd.doc, allow, depth + 1)
    for body in scan.substitutions(raw) if depth < DEPTH else []:
        found += judged(body, allow, depth + 1)
    return found


def check(raw: str, allow: Allowlist) -> Verdict:
    """The first block over any command in the line (every segment is judged), else the first ask, else None."""
    verdicts = [v for v in judged(raw, allow) if v]
    return next((v for v in verdicts if v[0] == BLOCK), verdicts[0] if verdicts else None)


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        verdict = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv), load_allowlist(Path.cwd()))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-unapproved-egress: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if verdict:
        print(verdict[1], file=sys.stderr)
    return verdict[0] if verdict else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
