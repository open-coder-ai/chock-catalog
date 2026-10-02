"""Compose rules over each service's flattened entries: privilege, host namespaces, mounts, secrets, ports, images."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator

from dkscan import images, secrets
from dkscan.composeyaml import Entry, UnreadableError, flatten, services
from dkscan.rules import Ctx, Hit

TRUTHY = frozenset({"true", "yes", "on", "1"})
BAD_CAPS = frozenset({"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"})
UNCONFINED = re.compile(r"(?:seccomp|apparmor|systempaths)\s*[:=]\s*unconfined|label\s*[:=]\s*disable", re.IGNORECASE)
NAMESPACES = frozenset({"network_mode", "pid", "ipc", "userns_mode", "uts", "cgroup"})
#: Container runtime sockets: each hands the container the host's runtime, as docker.sock does.
SOCKETS = ("docker.sock", "podman.sock", "containerd.sock")
SENSITIVE = ("/etc", "/proc", "/sys", "/boot", "/dev", "/root", "~/.ssh", "~/.aws", "~/.kube", "/var/lib/docker")
SOCKET_DIRS = frozenset({"/var", "/var/run", "/run"})
EXEMPT = ("/etc/localtime", "/etc/timezone", "/etc/ssl/certs")
HOME = {"HOME": "~", "USERPROFILE": "~"}
#: Database, cache, broker and admin ports that should not listen on every interface (record 08).
DB_PORTS = frozenset(
    {
        5432,
        3306,
        1433,
        1521,
        27017,
        27018,
        6379,
        11211,
        9200,
        9300,
        5984,
        8086,
        7474,
        7687,
        9042,
        2379,
        8500,
        5672,
        15672,
        9092,
        2181,
        2375,
        2376,
    }
)
LOOPBACK = re.compile(r"^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|\[?::1\]?)$")
PORT = re.compile(r"^(\d+)(?:-(\d+))?(?:/\w+)?$")
#: A list item sits at (key, index); a short port with a host address has three colon parts.
ITEM, WITH_HOST_IP = 2, 3
SPLIT = re.compile(r"\$\{[^}]*\}|\[[^\]]*\]|[^:]+|:")


def colon_parts(value: str) -> list[str]:
    """`value` split on colons outside ${...} and [...]."""
    parts, current = [], ""
    for piece in SPLIT.findall(value):
        if piece == ":":
            parts.append(current)
            current = ""
        else:
            current += piece
    return [*parts, current]


def host_path(source: str) -> str | None:
    """A bind source as a normalized host path ("~" for home); None for a variable without a default or a relative path."""
    resolved = images.substitute(source, HOME)
    if resolved is None or not resolved.startswith(("/", "~")):
        return None
    collapsed = re.sub(r"/+", "/", resolved)
    return "/" if collapsed == "/" else posixpath.normpath(collapsed).rstrip("/") or "/"


def mount_rule(source: str) -> str | None:
    if any(socket in source for socket in SOCKETS):
        return "cm-docker-sock"
    path = host_path(source)
    if path is None or any(path == e or path.startswith(e + "/") for e in EXEMPT):
        return None
    if path in SOCKET_DIRS:
        return "cm-docker-sock"
    under = any(path == s or path.startswith(s + "/") for s in SENSITIVE)
    above = path == "/" or any(s.startswith(path + "/") for s in SENSITIVE)
    return "cm-sensitive-mount" if under or above else None


def _port_hit(target: str, host_ip: str) -> bool:
    found = PORT.match(target.strip())
    if not found or LOOPBACK.match(host_ip.strip()):
        return False
    low = int(found.group(1))
    high = int(found.group(2) or low)
    return any(low <= port <= high for port in DB_PORTS)


def short_port(value: str) -> bool:
    parts = colon_parts(value)
    host_ip = parts[0] if len(parts) == WITH_HOST_IP else ""
    return _port_hit(parts[-1], host_ip)


class Service:
    def __init__(self, name: str, rows: list[Entry], lines: list[str], ctx: Ctx) -> None:
        self.ctx = ctx
        self.name, self.rows, self.lines = name, rows, lines
        self.by_path = {row.path: row for row in rows}

    def hit(self, rule: str, row: Entry, why: str) -> Hit:
        return Hit(
            rule, row.line, f"{self.name}|{'.'.join(map(str, row.path))}={row.value}", f"service {self.name}: {why}"
        )

    def line_text(self, row: Entry) -> str:
        return self.lines[row.line - 1] if 0 < row.line <= len(self.lines) else ""

    def get(self, *path: str | int) -> str:
        row = self.by_path.get(path)
        return row.value if row else ""

    def scan(self) -> Iterator[Hit]:
        for row in self.rows:
            if row.scalar:
                yield from self.row(row)
        yield from self.image()

    def row(self, row: Entry) -> Iterator[Hit]:
        head, value = row.path[0], row.value.strip()
        if row.path == ("privileged",) and value.lower() in TRUTHY:
            yield self.hit("cm-privileged-caps", row, "privileged: true")
        elif head == "cap_add" and value.upper().removeprefix("CAP_") in BAD_CAPS:
            yield self.hit("cm-privileged-caps", row, f"cap_add {value}")
        elif head == "security_opt" and UNCONFINED.search(value):
            yield self.hit("cm-privileged-caps", row, f"security_opt {value}")
        elif head == "devices" and row.path[-1] in (row.path[1], "source"):
            yield self.hit("cm-privileged-caps", row, f"host device {value}")
        elif len(row.path) == 1 and head in NAMESPACES and value.lower() == "host":
            yield self.hit("cm-host-namespaces", row, f"{head}: host")
        elif head == "volumes":
            yield from self.volume(row, value)
        elif head == "environment":
            yield from self.environment(row, value)
        elif head == "ports":
            yield from self.port(row, value)

    def volume(self, row: Entry, value: str) -> Iterator[Hit]:
        long_form = row.path[-1] == "source"
        if not long_form and (len(row.path) != ITEM or len(colon_parts(value)) < ITEM):
            return
        rule = mount_rule(value if long_form else colon_parts(value)[0])
        if rule:
            yield self.hit(rule, row, f"host path mounted: {value}")

    def environment(self, row: Entry, value: str) -> Iterator[Hit]:
        if len(row.path) != ITEM:
            return
        listed = not isinstance(row.path[1], str)
        name, eq, literal = value.partition("=") if listed else (str(row.path[1]), ":", value)
        written = f"{name}={literal}" if listed else f"{name}: {literal}"
        if (
            eq
            and secrets.is_secret_name(name)
            and secrets.is_literal(literal)
            and not secrets.scan_secrets_reads(written)
        ):
            yield self.hit("cm-literal-secrets", row._replace(value=name), f"environment {name} holds a literal")

    def port(self, row: Entry, value: str) -> Iterator[Hit]:
        short = len(row.path) == ITEM and short_port(value)
        if short or (row.path[-1] == "target" and _port_hit(value, self.get("ports", row.path[1], "host_ip"))):
            yield self.hit("cm-ports-all-interfaces", row, f"port {value} published on every interface")

    def image(self) -> Iterator[Hit]:
        row = self.by_path.get(("image",))
        if (
            row is None
            or any(r.path[0] == "build" for r in self.rows)
            or (self.ctx.pins_elsewhere and images.HP06_IMAGE.search(self.line_text(row)))
        ):
            return
        resolved = images.substitute(row.value.strip(), {})
        verdict = "floating" if resolved is None else images.judge(resolved)
        if verdict == "floating":
            yield self.hit("cm-image-floating", row, f"image {row.value} has no tag, latest, or no value to judge")
        elif verdict == "no-digest":
            yield self.hit("cm-image-no-digest", row, f"image {row.value} has no digest")


def compose_hits(text: str, ctx: Ctx | None = None) -> list[Hit]:
    try:
        docs = flatten(text)
    except UnreadableError as exc:
        return [Hit("cm-unreadable", 1, "unreadable", f"compose file cannot be read with certainty ({exc})")]
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    hits: list[Hit] = []
    for entries in docs:
        for name, rows in services(entries).items():
            hits.extend(Service(name, rows, lines, ctx or Ctx()).scan())
    return hits
