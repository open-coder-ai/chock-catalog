"""Reading Spring configuration keys: one dotted key per line, `.properties` or YAML alike.

Shared by every rule in this pack that reads `application*.properties` / `application*.yml` /
`bootstrap*.yml` -- a key such as `management.endpoint.env.show-values` is spelled flat in
properties and nested in YAML, and a rule that only understood one form would miss the other.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

from chock_security.decision import FileText

#: File names this pack treats as Spring configuration -- not any `.yml` a repository carries.
_CONFIG_STEMS = ("application", "bootstrap")
_CONFIG_SUFFIXES = (".properties", ".yml", ".yaml")


@dataclass(frozen=True)
class ConfigEntry:
    """One key this file sets, wherever it was spelled: `line_no`, the dotted `key`, its `value`."""

    line_no: int
    key: str
    value: str


#: An opening and a closing quote.
_QUOTE_PAIR = 2


def is_spring_config_file(path: str) -> bool:
    """Whether this is a Spring configuration file: `application*` or `bootstrap*`, not any YAML."""
    name = PurePosixPath(path).name.lower()
    return name.endswith(_CONFIG_SUFFIXES) and name.startswith(_CONFIG_STEMS)


def is_test_resource(path: str) -> bool:
    """Whether this file lives under a test source root -- Maven and Gradle both use `src/test/`."""
    return "src/test/" in path.replace("\\", "/")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= _QUOTE_PAIR and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _properties_pairs(text: FileText) -> Iterator[ConfigEntry]:
    for line_no, raw in enumerate(text.lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        candidates = [i for i in (stripped.find("="), stripped.find(":")) if i != -1]
        if not candidates:
            continue
        split = min(candidates)
        key = stripped[:split].strip()
        value = _unquote(stripped[split + 1 :])
        if key:
            yield ConfigEntry(line_no, key, value)


def _yaml_pairs(text: FileText) -> Iterator[ConfigEntry]:
    #: The open path to this line: each entry is (indent, key-segment) of an enclosing mapping.
    stack: list[tuple[int, str]] = []
    for line_no, raw in enumerate(text.lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "- ")):
            continue
        if ":" not in stripped:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key, _, value = stripped.partition(":")
        key = _unquote(key)
        value = value.strip()
        if not value or value in {"|", ">"}:
            stack.append((indent, key))
            continue
        value = value.split(" #", 1)[0].strip()
        full_key = ".".join([*(seg for _, seg in stack), key])
        yield ConfigEntry(line_no, full_key, _unquote(value))


def config_pairs(text: FileText) -> Iterator[ConfigEntry]:
    """Every key this configuration file sets, dotted the same way in `.properties` and YAML.

    Every rule in this pack calls this only after its own suffix gate has already narrowed
    `text` to `.properties`, `.yml` or `.yaml`, so those are the only two shapes handled here.
    """
    if text.suffix == ".properties":
        yield from _properties_pairs(text)
    else:
        yield from _yaml_pairs(text)


def key_ends_with(key: str, *suffixes: str) -> bool:
    """Whether a dotted/kebab config key's last segment matches one of these plain-word suffixes.

    `server.error.include-exception` and `client_secret` both reduce to letters only, so a rule
    naming `secret` catches `client-secret`, `clientSecret` and `client_secret` alike.
    """
    last = key.rsplit(".", 1)[-1]
    normalized = "".join(ch for ch in last.lower() if ch.isalnum())
    return any(normalized.endswith("".join(ch for ch in s.lower() if ch.isalnum())) for s in suffixes)
