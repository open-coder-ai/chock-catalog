#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Carved out for rtk-ai/rtk#1007: rtk's own decision table as a chock pre-tool guard.
# Exit 1 refuses, exit 3 asks (the first line printed is the prompt), exit 0 stays silent.
# Not a security boundary; bypasses are possible via aliases, interpreters and indirect scripts.
# Destructive verdicts come from chock_destructive's table, shared with block-destructive-commands;
# the credential rows (file reads, echoes, inline literals) are this policy's own.

import re
import sys
from collections.abc import Callable
from fnmatch import fnmatchcase

import chock_destructive
from chock_shellparse import Cmd, operands

BLOCK = chock_destructive.BLOCK
KEY_FILES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa*", "id_ed25519*")
KEY_FILES += ("id_ecdsa*", "id_dsa*", ".credentials", "credentials", ".netrc", ".pgpass", ".git-credentials")
KEY_DIRS = ("*/.ssh/*", "*/.aws/*", "*/.gnupg/*", "*/.kube/config")
TEMPLATES = (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.local.example")
KEY_VAR = re.compile(r"(api_key|apikey|secret|token|password|passwd|private_key|access_key)(_|$)", re.IGNORECASE)
READERS = frozenset(
    (
        *("cat", "head", "tail", "less", "more", "bat", "strings", "xxd", "hexdump", "base64", "od", "nl", "tac"),
        *("grep", "egrep", "fgrep", "rg", "ag", "ack", "awk", "gawk", "sed", "cut", "sort", "uniq", "jq", "yq", "diff"),
    )
)


def refuse(text: str) -> chock_destructive.Verdict:
    return BLOCK, f"BLOCKED: {text}"


def is_protected_file(path: str) -> bool:
    """A file whose contents are a credential; example and template copies stay readable."""
    name, full = path.replace("\\", "/").rsplit("/", 1)[-1], "/" + path.replace("\\", "/")
    hit = any(fnmatchcase(name, p) for p in KEY_FILES) or any(fnmatchcase(full, p) for p in KEY_DIRS)
    return hit and name not in TEMPLATES


def protected_file_read(cmd: Cmd) -> chock_destructive.Verdict:
    paths = [
        *operands(cmd.args),
        *cmd.reads,
        *(a.split("=", 1)[1] for a in cmd.args if a.startswith("--") and "=" in a),
    ]
    hit = next((p for p in paths if is_protected_file(p)), None)
    if hit is None:
        return None
    return refuse(
        f"reading a credential-bearing file ('{hit.rsplit('/', 1)[-1]}') into the agent's context is not allowed; read the value from the environment where it is needed."
    )


def echo_env_ref(cmd: Cmd) -> chock_destructive.Verdict:
    for arg in cmd.args:
        name = re.sub(r"[^A-Za-z0-9_].*", "", arg.partition("$")[2].lstrip("{"))
        if "$" in arg and name and KEY_VAR.search(name):
            return refuse(f"echoing ${name} would print a credential into the transcript; use it without printing it.")
    return None


def inline_env_literal(cmd: Cmd) -> chock_destructive.Verdict:
    # The message names no variable: the name travels with the literal value, so it stays out of logs.
    if any(KEY_VAR.search(name) and value and not value.startswith("$") for name, value in cmd.env.items()):
        return refuse(
            "a literal credential is being passed inline as an environment variable; export it from a secret store or the environment instead."
        )
    return None


HOST_FILE_RULES: dict[str, Callable[[Cmd], chock_destructive.Verdict]] = {
    "echo": echo_env_ref,
    "printf": echo_env_ref,
    **dict.fromkeys(READERS, protected_file_read),
}


def credentials(cmd: Cmd, container: bool) -> chock_destructive.Verdict:  # noqa: FBT001 -- the shared Extra hook
    """This policy's own rows. Inside a container the paths are the container's, so file and echo rows are skipped."""
    if leak := inline_env_literal(cmd):
        return leak
    rule = None if container else HOST_FILE_RULES.get(cmd.name)
    return rule(cmd) if rule else None


def check(raw: str) -> chock_destructive.Verdict:
    """A block wins over an ask; the first ask wins over the rest."""
    return chock_destructive.check(raw, credentials)


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        verdict = check(chock_destructive.raw_command(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(
            f"rtk-dangerous-actions-blocker: internal error ({type(exc).__name__}); command not checked",
            file=sys.stderr,
        )
        return 2
    if verdict:
        print(verdict[1], file=sys.stderr)
    return verdict[0] if verdict else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
