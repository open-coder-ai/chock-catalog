#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Carved out for rtk-ai/rtk#1007: rtk's own decision table as a chock pre-tool guard.
# Exit 1 refuses, exit 3 asks (the first line printed is the prompt), exit 0 stays silent.
# Not a security boundary; bypasses are possible via aliases, interpreters and indirect scripts.

import os
import re
import shlex
import sys
from collections.abc import Callable
from fnmatch import fnmatchcase

from chock_shellparse import (
    POWERSHELL_REMOVERS,
    Cmd,
    abbreviates,
    after,
    commands,
    flags_of,
    git_parts,
    is_dangerous_target,
    operands,
    positionals,
    removes_root_recursively,
)

BLOCK, ASK = 1, 3
Verdict = tuple[int, str] | None
# rtk's safe list: build output a developer deletes all day, matched on the last path segment.
SAFE_DIRS = ("node_modules", "dist", "build", ".next", "__pycache__", ".cache", "tmp", ".tmp")
SAFE_DIRS += ("coverage", ".nyc_output", "target", ".turbo", ".parcel-cache")
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
SQL_CLIENTS = frozenset(("psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client"))
SQL_REFUSED = (
    (r"drop\s+(table|database|schema|collection)", "a DROP statement", "take a backup and run it by hand"),
    (r"(^|[^a-z])truncate(\s|$)", "a TRUNCATE statement", "take a backup and run it by hand"),
    (
        r"delete\s+from\s+[a-z0-9_.\"`]+\s*(;|$)",
        "DELETE FROM without a WHERE clause",
        "scope it or run it by hand",
    ),
    (r"(^|[^a-z])(flushall|flushdb)([^a-z]|$)", "FLUSHALL/FLUSHDB", "delete keys by pattern instead"),
)
PRUNE = {
    "system": "removes every stopped container, unused network and dangling image",
    "volume": "deletes every unused volume's data",
}
PRUNE_KINDS = ("system", "volume", "container", "image", "network", "builder")
KUBECTL_VALUES = frozenset(("-n", "--namespace", "--context", "--cluster", "--user", "--kubeconfig", "--server", "-s"))
HELM_VALUES = frozenset(("-n", "--namespace", "--kube-context", "--kubeconfig", "--kube-apiserver", "--kube-token"))
DOCKER_VALUES = frozenset(("-H", "--host", "--context", "-c", "--config", "-l", "--log-level"))
EXEC_VALUES = frozenset(("-e", "-u", "-w", "--env", "--user", "--workdir", "--env-file"))
AWS_VALUES = frozenset(("--profile", "--region", "--endpoint-url", "--output", "--query", "--ca-bundle", "--color"))


def refuse(text: str) -> Verdict:
    return BLOCK, f"BLOCKED: {text}"


def confirm(text: str) -> Verdict:
    return ASK, f"CONFIRM: {text}"


def block(reason: str) -> Verdict:
    return refuse(f"{reason} is not allowed without approval.")


def is_protected_file(path: str) -> bool:
    """A file whose contents are a credential; example and template copies stay readable."""
    name, full = path.replace("\\", "/").rsplit("/", 1)[-1], "/" + path.replace("\\", "/")
    hit = any(fnmatchcase(name, p) for p in KEY_FILES) or any(fnmatchcase(full, p) for p in KEY_DIRS)
    return hit and name not in TEMPLATES


def rm(cmd: Cmd) -> Verdict:
    flags = flags_of(cmd.args)
    if not (flags & {"-r", "-R", "--recursive"} and flags & {"-f", "--force"}):
        return None
    targets = operands(cmd.args)
    if hit := next((t for t in targets if is_dangerous_target(t)), None):
        return refuse(
            f"rm -rf targeting '{hit}' (root, home, parent or absolute path) is not allowed; use a relative path."
        )
    if hit := next((t for t in targets if t.rstrip("/").rsplit("/", 1)[-1] not in SAFE_DIRS), None):
        return confirm(
            f"rm -rf on '{hit}' is recursive and unrecoverable; confirm the target, or use a trash/dry-run alternative."
        )
    return None


def git_push(flags: set[str], targets: list[str]) -> Verdict:
    forced = min((t for t in targets if t.startswith("+") or ":+" in t), default="")
    if flags & {"-f", "--force"}:
        return refuse("git push --force is not allowed; use --force-with-lease on a feature branch.")
    if forced:
        return refuse(
            f"git push with a '+' force-refspec ('{forced}') overwrites the remote ref; use --force-with-lease on a feature branch."
        )
    return None


def git(cmd: Cmd) -> Verdict:
    sub, _, rest = git_parts(cmd.args)
    flags, targets = flags_of(rest), operands(rest)
    if sub == "push":
        return git_push(flags, targets)
    asks = {
        "reset": (
            any(abbreviates(f, "--hard", 3) for f in flags),
            "git reset --hard discards uncommitted changes; confirm, or git stash first.",
        ),
        "clean": (
            any(f == "-f" or abbreviates(f, "--force", 3) for f in flags),
            "git clean -f deletes untracked files; confirm, or run git clean -n to preview.",
        ),
        "checkout": (
            "." in targets,
            "git checkout . discards every uncommitted change in the tree; confirm, or git stash first.",
        ),
        "branch": (
            "-D" in flags,
            "git branch -D deletes a branch even if unmerged; confirm, or use -d for a merged branch.",
        ),
    }
    hit, why = asks.get(sub, (False, ""))
    return confirm(why) if hit else None


def protected_file_read(cmd: Cmd) -> Verdict:
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


def echo_env_ref(cmd: Cmd) -> Verdict:
    for arg in cmd.args:
        name = re.sub(r"[^A-Za-z0-9_].*", "", arg.partition("$")[2].lstrip("{"))
        if "$" in arg and name and KEY_VAR.search(name):
            return refuse(f"echoing ${name} would print a credential into the transcript; use it without printing it.")
    return None


def inline_env_literal(cmd: Cmd) -> Verdict:
    # The message names no variable: the name travels with the literal value, so it stays out of logs.
    if any(KEY_VAR.search(name) and value and not value.startswith("$") for name, value in cmd.env.items()):
        return refuse(
            "a literal credential is being passed inline as an environment variable; export it from a secret store or the environment instead."
        )
    return None


def sql(cmd: Cmd) -> Verdict:
    text = f"{' '.join(cmd.args)} {cmd.doc}"
    for pattern, what, fix in SQL_REFUSED:
        if re.search(pattern, text, re.IGNORECASE):
            return refuse(f"{what} through {cmd.name} is not allowed; {fix}.")
    return None


def docker(cmd: Cmd, raw: str) -> Verdict:
    items, flags = positionals(cmd.args, DOCKER_VALUES), flags_of(cmd.args)
    first, second = [*items, "", ""][:2]
    if second == "prune" and first in PRUNE_KINDS:
        return confirm(
            f"docker {first} prune {PRUNE.get(first, f'sweeps every unused {first}')}; confirm, or remove one by name."
        )
    if (first, second) == ("volume", "rm"):
        return block("docker volume rm (it destroys the volume's data)")
    substituted = any(a.startswith(("$(", "`")) or a == "$" for a in cmd.args) or bool(
        re.search(r"\$\(docker ps|`docker ps", raw)
    )
    if first == "rm" and flags & {"-f", "--force"} and substituted:
        return confirm(
            "docker rm -f over a command substitution removes every container it lists; confirm, or name the containers."
        )
    return None


def cloud(cmd: Cmd) -> Verdict:
    """kubectl, terraform, aws s3, helm and gcloud rows kept from block-destructive-commands."""
    flags = flags_of(cmd.args)
    if cmd.name == "kubectl":
        return block("kubectl delete") if positionals(cmd.args, KUBECTL_VALUES)[:1] == ["delete"] else None
    if cmd.name == "terraform":
        return block("terraform destroy") if operands(cmd.args)[:1] == ["destroy"] else None
    if cmd.name == "aws":
        action = after(positionals(cmd.args, AWS_VALUES), "s3")
        refused = (action == "rm" and "--recursive" in flags) or (action == "rb" and "--force" in flags)
        return block(f"aws s3 {action} --{'recursive' if action == 'rm' else 'force'}") if refused else None
    if cmd.name == "helm":
        return (
            block("helm uninstall/delete")
            if positionals(cmd.args, HELM_VALUES)[:1] in (["uninstall"], ["delete"], ["del"], ["un"])
            else None
        )
    return block("gcloud delete") if "delete" in operands(cmd.args) else None


def powershell_remove(cmd: Cmd) -> Verdict:
    if removes_root_recursively(cmd):
        return block("destructive PowerShell/cmd removal targeting a drive root or home path")
    return None


HOST_FILE_RULES: dict[str, Callable[[Cmd], Verdict]] = {
    "rm": rm,
    "echo": echo_env_ref,
    "printf": echo_env_ref,
    **dict.fromkeys(READERS, protected_file_read),
    **dict.fromkeys(POWERSHELL_REMOVERS, powershell_remove),
}
RULES: dict[str, Callable[[Cmd], Verdict]] = {
    "git": git,
    "dropdb": lambda _cmd: block("dropdb"),
    **dict.fromkeys(SQL_CLIENTS, sql),
    **dict.fromkeys(("kubectl", "terraform", "aws", "helm", "gcloud"), cloud),
}


def inner_command(cmd: Cmd) -> list[str]:
    """The words of the command a `docker exec` or `kubectl exec` runs inside its container, or []."""
    if cmd.name == "kubectl" and positionals(cmd.args, KUBECTL_VALUES)[:1] == ["exec"] and "--" in cmd.args:
        return cmd.args[cmd.args.index("--") + 1 :]
    if cmd.name != "docker" or positionals(cmd.args, DOCKER_VALUES)[:1] != ["exec"]:
        return []
    words, skip, named = [], False, False
    for arg in cmd.args[cmd.args.index("exec") + 1 :]:
        if named:
            words.append(arg)
        elif skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in EXEC_VALUES
        else:
            named = True
    return words


def judge(cmd: Cmd, raw: str, *, container: bool) -> Verdict:
    """One command's verdict. Inside a container the paths are the container's, so host-path rows are skipped."""
    if leak := inline_env_literal(cmd):
        return leak
    if cmd.name == "docker":
        return docker(cmd, raw)
    rule = RULES.get(cmd.name) or (None if container else HOST_FILE_RULES.get(cmd.name))
    return rule(cmd) if rule else None


def judge_all(cmds: list[Cmd], raw: str, *, container: bool) -> Verdict:
    """A block wins over an ask; the first ask wins over the rest."""
    asked: Verdict = None
    for cmd in cmds:
        words = inner_command(cmd)
        inner = judge_all(commands(shlex.join(words)), raw, container=True) if words else None
        for verdict in (judge(cmd, raw, container=container), inner):
            if verdict and verdict[0] == BLOCK:
                return verdict
            asked = asked or verdict
    return asked


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        raw = os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv)
        verdict = judge_all(commands(raw), raw, container=False)
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
