"""Per-instruction Dockerfile rules: secrets in ENV/ARG and COPY sources, remote ADD, EXPOSE 22, ONBUILD RUN, sshd."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import PurePosixPath

from dkscan import secrets, shellrules, stages
from dkscan.dockerfile import Instr
from dkscan.rules import Ctx, Hit

#: block-fetch-exec-in-files (HP03) reads `ADD <url>` with no --checksum on one line; that line is its to report.
HP03_ADD = re.compile(r"^\s*(?i:add)\s+(?:--(?!checksum)[\w-]+(?:=\S+)?\s+)*[\"']?https?://")
HTTP = re.compile(r"^https?://", re.IGNORECASE)
REMOTE = re.compile(r"^(?:https?://|git@|git://|ssh://)", re.IGNORECASE)
GIT_SOURCE = re.compile(r"^(?:git@|git://|ssh://)|\.git(?:#|$)", re.IGNORECASE)
PINNED_GIT = re.compile(r"#[0-9a-fA-F]{40}(?::|$)")
KEY_FILE = re.compile(
    r"^(?:\.env(?:\.(?!example$|sample$|template$|dist$|defaults$)[\w.-]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|\.npmrc|\.pypirc|\.netrc"
    r"|\.git-credentials|\.pgpass|[\w.-]*\.(?:key|p12|pfx|jks|keystore)|[\w.-]*(?:key|priv)[\w.-]*\.pem)$",
    re.IGNORECASE,
)
SECRET_DIRS = frozenset({".aws", ".ssh", ".gnupg", ".kube", ".docker"})
WHOLE_CONTEXT = frozenset({".", "./", "*", "./*"})
SSHD = re.compile(r"(?:^|[\s\"'/\[,])sshd(?![\w.-])")
PORT_22 = re.compile(r"^22(?:/tcp)?$")


def _sources(instr: Instr) -> list[str]:
    form = instr.exec_form()
    found = form if form is not None else stages.words(instr.args.split("<<", 1)[0])
    return found[:-1]


def _secret_path(source: str) -> bool:
    path = PurePosixPath(source.replace("\\", "/"))
    return bool(KEY_FILE.match(path.name)) or any(part in SECRET_DIRS for part in path.parts)


def env_arg(instr: Instr) -> Iterator[Hit]:
    pairs = (
        stages.env_pairs(instr.args)
        if instr.keyword == "ENV"
        else [(name, value) for name, eq, value in (w.partition("=") for w in stages.words(instr.args)) if eq]
    )
    for name, value in pairs:
        if secrets.is_secret_name(name) and secrets.is_literal(value):
            if any(name in raw and secrets.scan_secrets_reads(raw) for raw in instr.raw):
                continue
            yield Hit(
                "dk-secret-arg-env", instr.line, f"{instr.keyword} {name}", f"{instr.keyword} {name} holds a literal"
            )


def copy_add(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    sources = _sources(instr)
    for source in sources:
        if _secret_path(source):
            yield Hit(
                "dk-copy-secrets",
                instr.line,
                f"{instr.keyword} {source}",
                f"{instr.keyword} of {source} into the image",
            )
    if not ctx.ignored and "from" not in instr.flags and any(s in WHOLE_CONTEXT for s in sources):
        yield Hit(
            "dk-copy-all",
            instr.line,
            f"{instr.keyword} all",
            f"{instr.keyword} of the whole context with no .dockerignore",
        )
    if instr.keyword == "ADD":
        yield from _add_remote(instr, sources)


def _add_remote(instr: Instr, sources: list[str]) -> Iterator[Hit]:
    if "checksum" in instr.flags:
        return
    for source in sources:
        if not REMOTE.match(source) or (HTTP.match(source) and HP03_ADD.match(instr.raw[0])):
            continue
        if not GIT_SOURCE.search(source):
            yield Hit("dk-add-remote", instr.line, f"ADD {source}", "ADD of a URL with no --checksum")
        elif not PINNED_GIT.search(source):
            yield Hit("dk-add-remote", instr.line, f"ADD {source}", "ADD of a git source with no 40-hex commit")


def expose(instr: Instr) -> Iterator[Hit]:
    if any(PORT_22.match(word) for word in instr.args.split()):
        yield Hit("dk-sudo-sshd", instr.line, "EXPOSE 22", "EXPOSE 22: an SSH server in the image")


def command(instr: Instr) -> Iterator[Hit]:
    if SSHD.search(instr.args):
        yield Hit("dk-sudo-sshd", instr.line, f"{instr.keyword} sshd", f"{instr.keyword} starts an SSH server")


def onbuild(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    inner = (instr.args.split(None, 1) or [""])[0].upper()
    if inner == "RUN":
        yield Hit("dk-onbuild-run", instr.line, instr.text, "ONBUILD RUN runs in every downstream build")
        yield from shellrules.run_hits(instr, ctx)


def instruction_hits(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    """Every per-instruction finding (stage-aware FROM and USER rules live in stages)."""
    handlers: dict[str, Callable[[], Iterator[Hit]]] = {
        "RUN": lambda: shellrules.run_hits(instr, ctx),
        "ENV": lambda: _env_like(instr, ctx),
        "ARG": lambda: _env_like(instr, ctx),
        "COPY": lambda: copy_add(instr, ctx),
        "ADD": lambda: copy_add(instr, ctx),
        "EXPOSE": lambda: expose(instr),
        "CMD": lambda: command(instr),
        "ENTRYPOINT": lambda: command(instr),
        "ONBUILD": lambda: onbuild(instr, ctx),
    }
    handler = handlers.get(instr.keyword)
    return handler() if handler else iter(())


def _env_like(instr: Instr, ctx: Ctx) -> Iterator[Hit]:
    yield from env_arg(instr)
    yield from shellrules.tls_hits(instr, ctx)
