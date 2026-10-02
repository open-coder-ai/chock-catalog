"""One MCP server entry read into the parts the rules judge: launcher, arguments, urls, environment and headers."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass

URL_KEYS = ("url", "httpUrl", "serverUrl")
ENV_KEYS = ("env", "environment")
HEADER_KEYS = ("headers", "http_headers")
#: Entry-level scalar keys that hold a credential themselves (compared lowercase, without `_` or `-`).
SECRET_KEYS = frozenset(
    {"bearertoken", "token", "apikey", "password", "secret", "authorization", "accesstoken", "clientsecret"}
)
#: Names of environment variables and headers whose value is a credential (the roadmap's HP16 rule).
SECRET_NAME = re.compile(r"token|key|secret|password|auth|credential|passwd|bearer|cookie", re.IGNORECASE)
#: `${VAR}`, `${env:VAR}`, `${input:id}`, `$VAR`, `{env:VAR}`, `%VAR%`: a reference to a value kept elsewhere.
REFERENCE = re.compile(
    r"\$\{(?:env:|input:)?[A-Za-z_][A-Za-z0-9_.-]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{env:[A-Za-z_][A-Za-z0-9_]*\}|%[A-Za-z_][A-Za-z0-9_]*%"
)
SCHEME_WORD = re.compile(r"^\s*(?:bearer|basic|token)?[\s:]*$", re.IGNORECASE)


class EntryError(ValueError):
    """The entry is not shaped like any MCP server the clients read."""


@dataclass(frozen=True)
class Server:
    """`launcher` is the command as written ('' for a remote server); the pairs are sorted (name, value)."""

    name: str
    launcher: str
    args: tuple[str, ...]
    urls: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    headers: tuple[tuple[str, str], ...]
    secrets: tuple[tuple[str, str], ...]

    def digest(self) -> str:
        """A short fingerprint of everything the entry says, so any change to it is a different key."""
        parts = [self.launcher, self.args, self.urls, self.env, self.headers, self.secrets]
        return hashlib.sha256(json.dumps(parts, sort_keys=True).encode("utf-8", errors="replace")).hexdigest()[:16]


def is_reference(value: str) -> bool:
    """True for an empty value or one made only of references (and a scheme word such as Bearer)."""
    return not value or (
        REFERENCE.search(value) is not None and SCHEME_WORD.match(REFERENCE.sub("", value)) is not None
    )


def literal_secrets(pairs: tuple[tuple[str, str], ...]) -> list[str]:
    """Names of the pairs whose name says credential and whose value is a literal."""
    return [name for name, value in pairs if SECRET_NAME.search(name) and not is_reference(value)]


def _text(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        msg = "a value that is not text"
        raise EntryError(msg)
    return str(value)


def _pairs(config: dict, keys: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    for key in keys:
        table = config.get(key)
        if table is None:
            continue
        if not isinstance(table, dict):
            msg = f"{key} is not a table"
            raise EntryError(msg)
        found += [(str(name), _text(value)) for name, value in table.items()]
    return tuple(sorted(found))


def _command(config: dict) -> tuple[str, list[str], dict]:
    """(launcher, arguments, a command object's own table): the command as a string, a list or a Zed-style object."""
    command, args = config.get("command"), config.get("args", [])
    own: dict = {}
    if isinstance(command, dict):
        own, command, args = command, command.get("path"), command.get("args", args)
    if command is None:
        return "", [], own
    if isinstance(command, list):
        command, args = (command[0] if command else ""), [*command[1:], *(args if isinstance(args, list) else [])]
    if not isinstance(command, str) or not isinstance(args, list):
        msg = "a command or args that is not text"
        raise EntryError(msg)
    if re.search(r"\s", command.strip()) and not args:
        try:
            command, *args = shlex.split(command, posix="\\" not in command)
        except ValueError:
            msg = "a command line with an unbalanced quote"
            raise EntryError(msg) from None
    return command, [_text(arg) for arg in args], own


def from_config(name: str, config: object) -> Server:
    """The server a config entry declares; EntryError when it is not an object or holds a value of the wrong shape."""
    if not isinstance(config, dict):
        msg = "not an object"
        raise EntryError(msg)
    launcher, args, own = _command(config)
    urls = tuple(_text(config[key]) for key in URL_KEYS if key in config)
    scalars = tuple(
        sorted(
            (str(key), value)
            for key, value in config.items()
            if isinstance(value, str) and re.sub(r"[_-]", "", str(key).lower()) in SECRET_KEYS
        )
    )
    return Server(
        name=name,
        launcher=launcher,
        args=tuple(args),
        urls=urls,
        env=tuple(sorted({*_pairs(config, ENV_KEYS), *_pairs(own, ("env",))})),
        headers=_pairs(config, HEADER_KEYS),
        secrets=scalars,
    )
