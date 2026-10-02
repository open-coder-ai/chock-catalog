"""Infrastructure, cloud, platform and data rows, judged on the host and inside a container exec (shared byte for byte)."""

import re
from collections.abc import Callable

from chock_shellparse import Cmd, after, flags_of, operands, positionals

from .api import curl, gh

Hit = tuple[str, str] | None
KUBECTL_VALUES = frozenset(("-n", "--namespace", "--context", "--cluster", "--user", "--kubeconfig", "--server", "-s"))
HELM_VALUES = frozenset(("-n", "--namespace", "--kube-context", "--kubeconfig", "--kube-apiserver", "--kube-token"))
DOCKER_VALUES = frozenset(
    (
        "-H",
        "--host",
        "--context",
        "-c",
        "--config",
        "-l",
        "--log-level",
        "--log-format",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
    )
)
_COMPOSE_VALUES = frozenset(
    (
        "-f",
        "--file",
        "-p",
        "--project-name",
        "--profile",
        "--env-file",
        "--project-directory",
        "--ansi",
        "--progress",
        "--parallel",
    )
)
_AWS_VALUES = frozenset(
    (
        *("--profile", "--region", "--endpoint-url", "--output", "--query", "--ca-bundle", "--color"),
        *("--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format"),
    )
)
_IAC_VALUES = frozenset(
    (
        *(
            "-C",
            "--cwd",
            "-s",
            "--stack",
            "--working-dir",
            "--terragrunt-working-dir",
            "--config",
            "--terragrunt-config",
        ),
        *("--log-level", "--terragrunt-log-level", "--source", "--terragrunt-source"),
    )
)
_PLATFORM_VALUES = frozenset(
    (
        *(
            "-a",
            "--app",
            "-r",
            "--remote",
            "-t",
            "--token",
            "-S",
            "--scope",
            "--workdir",
            "--profile",
            "-v",
            "--verbose",
        ),
        *("--subscription", "-o", "--output", "--region", "--project-ref", "-C", "--cwd", "-A", "--local-config"),
    )
)
_DOCTL_VALUES = frozenset(("-t", "--access-token", "-c", "--config", "--context", "-o", "--output", "-u", "--api-url"))
_FLY_VALUES = frozenset(("-a", "--app", "-c", "--config", "-r", "--region", "-t", "--access-token"))
_PRUNE_KINDS = frozenset(("container", "image", "network", "builder", "buildx"))
_AWS_DELETES = {
    "s3api": ("delete-bucket", "delete-object", "delete-objects"),
    "dynamodb": ("delete-table",),
    "lambda": ("delete-function",),
    "eks": ("delete-cluster", "delete-nodegroup"),
    "secretsmanager": ("delete-secret",),
    "ecr": ("delete-repository",),
    "kms": ("schedule-key-deletion",),
    "route53": ("delete-hosted-zone",),
    "ec2": ("terminate-instances",),
    "cloudformation": ("delete-stack",),
    "rds": ("delete-db-",),
    "iam": ("delete-",),
}
_SQL = (
    (r"drop\s+(table|database|schema|collection)", "a DROP statement"),
    (r"(^|[^a-z])truncate(\s|$)", "a TRUNCATE statement"),
    (r"delete\s+from\s+[a-z0-9_.\"`]+\s*(;|$)", "DELETE FROM without a WHERE clause"),
    (r"(^|[^a-z])(flushall|flushdb)([^a-z]|$)", "FLUSHALL/FLUSHDB"),
    (r"\.drop(database)?\s*\(", "a MongoDB drop()"),
)
SQL_CLIENTS = frozenset(("psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client"))


def kubectl(cmd: Cmd) -> Hit:
    verb = positionals(cmd.args, KUBECTL_VALUES)[:1]
    return {"delete": ("kubectl-delete", ""), "drain": ("kubectl-drain", "")}.get(verb[0]) if verb else None


def _opts(args: list[str]) -> dict[str, str]:
    """terraform-style single- or double-dash options: `-destroy`, `-auto-approve=true`."""
    return {a.lstrip("-").split("=", 1)[0]: a.partition("=")[2] or "true" for a in args if a.startswith("-")}


def terraform(cmd: Cmd) -> Hit:
    """terraform, tofu and terragrunt: destroy, apply -destroy (block); apply -auto-approve (ask)."""
    items, opts = [*positionals(cmd.args, _IAC_VALUES), "", ""], _opts(cmd.args)
    sub = items[1] if items[0] in ("run-all", "run") and cmd.name == "terragrunt" else items[0]
    if sub in ("destroy", "destroy-all") or (sub == "apply" and opts.get("destroy", "false") != "false"):
        return "iac-destroy", f"{cmd.name} {sub} (destroy)"
    approve = sub == "apply" and opts.get("auto-approve", "false") != "false"
    return ("iac-auto-approve", f"{cmd.name} apply") if approve else None


def pulumi(cmd: Cmd) -> Hit:
    verb = positionals(cmd.args, _IAC_VALUES)[:1]
    return ("iac-destroy", f"pulumi {verb[0]}") if verb in (["destroy"], ["down"]) else None


def aws(cmd: Cmd) -> Hit:
    items, flags = positionals(cmd.args, _AWS_VALUES), flags_of(cmd.args)
    service = next((i for i in items if i == "s3" or i in _AWS_DELETES), "")
    action = after(items, service)
    s3 = {"rm": "--recursive", "rb": "--force", "sync": "--delete"}
    if service == "s3" and s3.get(action) in flags:
        return "cloud-delete", f"aws s3 {action} {s3[action]}"
    hit = bool(action) and any(
        action == d or (d.endswith("-") and action.startswith(d)) for d in _AWS_DELETES.get(service, ())
    )
    return ("cloud-delete", f"aws {service} {action}") if hit else None


def named(verbs: dict[str, tuple[tuple[str, ...], ...]]) -> Callable[[Cmd], Hit]:
    """A CLI whose destructive form is a fixed run of leading words (`az group delete`, `supabase db reset`)."""

    def check(cmd: Cmd) -> Hit:
        items = tuple(positionals(cmd.args, _PLATFORM_VALUES))
        hit = next((v for v in verbs.get(cmd.name, ()) if items[: len(v)] == v), None)
        return None if hit is None else ("cloud-delete", " ".join((cmd.name, *hit)))

    return check


PLATFORMS = named(
    {
        "eksctl": (("delete",),),
        "heroku": (("apps:destroy",), ("destroy",), ("addons:destroy",), ("pg:reset",)),
        "vercel": (("rm",), ("remove",), ("project", "rm"), ("project", "remove")),
        "supabase": (("db", "reset"), ("projects", "delete")),
    }
)


def anywhere(words: tuple[str, ...], limit: int | None, values: frozenset[str] = frozenset()) -> Callable[[Cmd], Hit]:
    """A CLI that takes its destructive verb after a resource noun (`gcloud compute instances delete`)."""

    def check(cmd: Cmd) -> Hit:
        hit = next((w for w in positionals(cmd.args, values)[:limit] if w in words), None)
        return None if hit is None else ("cloud-delete", f"{cmd.name} ... {hit}")

    return check


def helm(cmd: Cmd) -> Hit:
    verb = positionals(cmd.args, HELM_VALUES)[:1]
    return ("helm-uninstall", "") if verb and verb[0] in ("uninstall", "delete", "del", "un") else None


def compose(name: str, args: list[str]) -> Hit:
    items = positionals(args, _COMPOSE_VALUES)
    down = items[:1] == ["down"] and bool(flags_of(args[args.index("down") :]) & {"-v", "--volumes"})
    return ("compose-down-volumes", name) if down else None


def docker(cmd: Cmd, raw: str) -> Hit:
    items = positionals(cmd.args, DOCKER_VALUES)
    first = (items or [""])[0]
    if first == "compose":
        return compose("docker compose", cmd.args[cmd.args.index("compose") + 1 :])
    if after(items, "volume") in ("rm", "remove", "prune"):
        return "docker-volume", ""
    if after(items, "system") == "prune":
        return "docker-system-prune", ""
    if kind := next((k for k in _PRUNE_KINDS if after(items, k) == "prune"), None):
        return "docker-prune", kind
    substituted = any(a.startswith(("$(", "`")) or a == "$" for a in cmd.args) or bool(
        re.search(r"\$\(docker ps|`docker ps", raw)
    )
    rm_forced = first == "rm" and bool(flags_of(cmd.args) & {"-f", "--force"})
    return ("docker-rm-substituted", "") if rm_forced and substituted else None


def sql(cmd: Cmd) -> Hit:
    # SQL comments separate words as whitespace does: DROP/**/TABLE is DROP TABLE, and `-- note` ends a statement.
    text = re.sub(r"/\*.*?\*/|(?<!\S)--([ \t][^\n]*|$)", " ", f"{' '.join(cmd.args)} {cmd.doc}", flags=re.DOTALL)
    hit = next((what for pattern, what in _SQL if re.search(pattern, text, re.IGNORECASE)), None)
    return None if hit is None else ("sql", f"{hit} through {cmd.name}")


def dropdb(cmd: Cmd) -> Hit:
    if cmd.name == "dropdb":
        return "drop-database", "dropdb"
    return ("drop-database", "mysqladmin drop") if "drop" in (a.lower() for a in operands(cmd.args)) else None


RULES: dict[str, Callable[[Cmd], Hit]] = {
    "kubectl": kubectl,
    "terraform": terraform,
    "tofu": terraform,
    "terragrunt": terraform,
    "pulumi": pulumi,
    "aws": aws,
    "gcloud": anywhere(("delete",), None),
    "az": anywhere(("delete",), 4, _PLATFORM_VALUES),
    "doctl": anywhere(("delete", "del", "rm"), 3, _DOCTL_VALUES),
    "fly": anywhere(("destroy",), 2, _FLY_VALUES),
    "flyctl": anywhere(("destroy",), 2, _FLY_VALUES),
    "helm": helm,
    "docker-compose": lambda cmd: compose("docker-compose", cmd.args),
    "dropdb": dropdb,
    "mysqladmin": dropdb,
    "gh": gh,
    **dict.fromkeys(("eksctl", "heroku", "vercel", "supabase"), PLATFORMS),
    **dict.fromkeys(SQL_CLIENTS, sql),
}
RAW_RULES: dict[str, Callable[[Cmd, str], Hit]] = {"docker": docker, "curl": curl}
