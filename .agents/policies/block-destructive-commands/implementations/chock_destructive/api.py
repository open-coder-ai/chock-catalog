"""Deletes sent straight to an infrastructure API with credentials: curl and gh (shared byte for byte)."""

import re

from chock_shellparse import Cmd, operands

Hit = tuple[str, str] | None
# Provider control planes, matched on the URL's host (exact, or as a parent domain when it starts with '.').
INFRA_HOSTS = (
    *("api.github.com", "gitlab.com", "api.cloudflare.com", "api.digitalocean.com", "api.heroku.com"),
    *("api.vercel.com", "api.fly.io", "api.machines.dev", "api.render.com", "api.netlify.com", "api.supabase.com"),
    *("management.azure.com", "api.linode.com", "api.hetzner.cloud", "backboard.railway.app", "console.neon.tech"),
    *("api.planetscale.com", ".googleapis.com", ".amazonaws.com"),
)
_AUTH_HEADER = re.compile(r"\s*(authorization|private-token|x-api-key|api-key|x-auth-token|x-auth-key)\s*:", re.I)
_AUTH_FLAGS = ("--oauth2-bearer", "--aws-sigv4", "-n", "--netrc", "--netrc-file", "-b", "--cookie", "-K", "--config")
_HOST = re.compile(r"(?:https?://)?(?:[^@/?#]*@)?([^:/?#]+)", re.IGNORECASE)
_MUTATION = re.compile(r"\bmutation\b[\s\S]*?(delete|destroy|remove)", re.IGNORECASE)


def _values(args: list[str], short: str, long: str) -> list[str]:
    """Every value given to a flag: `-X DELETE`, `-XDELETE`, `--request DELETE`, `--request=DELETE`."""
    found = []
    for i, arg in enumerate(args):
        if arg in (short, long) and i + 1 < len(args):
            found.append(args[i + 1])
        elif arg.startswith(f"{long}="):
            found.append(arg.partition("=")[2])
        elif len(short) == len("-X") and arg[:1] == "-" and arg[1:2] != "-" and short[1] in arg[1:]:
            # A short-flag cluster: `-sX DELETE` takes the next word, `-sXDELETE` the rest of this one.
            rest = arg[arg.index(short[1], 1) + 1 :]
            found.extend([rest] if rest else args[i + 1 : i + 2])
    return found


def _infra_host(url: str) -> bool:
    match = _HOST.match(url)
    host = match.group(1).lower().rstrip(".") if match else ""
    return any(host == h or (h.startswith(".") and host.endswith(h)) for h in INFRA_HOSTS)


def _data(args: list[str]) -> str:
    flags = ("--data", "--data-raw", "--data-binary", "--json", "--data-urlencode")
    return " ".join(v for flag in flags for v in _values(args, "-d" if flag == "--data" else flag, flag))


def curl(cmd: Cmd, _raw: str) -> Hit:
    """curl DELETE, or a GraphQL delete/destroy mutation, to a provider API with an auth header or credentials."""
    args = cmd.args
    if not any(_infra_host(u) for u in (*operands(args), *_values(args, "--url", "--url"))):
        return None
    authed = (
        any(_AUTH_HEADER.match(h) for h in _values(args, "-H", "--header"))
        or bool(_values(args, "-u", "--user"))
        or any(a.split("=", 1)[0] in _AUTH_FLAGS for a in args)
    )
    deleting = any(v.upper() == "DELETE" for v in _values(args, "-X", "--request"))
    mutation = _MUTATION.search(_data(args)) is not None
    return ("api-delete", f"curl {'DELETE' if deleting else 'mutation'}") if authed and (deleting or mutation) else None


def gh(cmd: Cmd) -> Hit:
    """gh repo delete (block); gh api with DELETE or a delete mutation (ask) -- gh always sends its token."""
    items = operands(cmd.args)
    if items[:2] == ["repo", "delete"]:
        return "cloud-delete", "gh repo delete"
    if items[:1] != ["api"]:
        return None
    deleting = any(v.upper() == "DELETE" for v in _values(cmd.args, "-X", "--method"))
    fields = " ".join(
        v for short, long in (("-f", "--raw-field"), ("-F", "--field")) for v in _values(cmd.args, short, long)
    )
    mutation = _MUTATION.search(fields) is not None
    return ("api-delete", f"gh api {'DELETE' if deleting else 'mutation'}") if deleting or mutation else None
