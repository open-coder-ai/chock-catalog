"""Hibernate's schema-generation setting can drop or rewrite the production schema on deploy."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "persistence-destructive-ddl"

_FACTS = facts("persistence")["ddl_auto"]

_MESSAGE = (
    "`{key}` is set to `{value}` in main configuration, so Hibernate rewrites the schema itself "
    "on startup -- `create`/`create-drop` drop every table first, and `update` can alter columns "
    "in ways that lose data. Set it to `validate` (schema checked, never changed) or `none`, and "
    "let a migration tool (Flyway, Liquibase) own the schema. A profile that must generate its "
    f"own schema needs 'chock: allow {RULE_ID}' on this line."
)

_XML_PROPERTY = re.compile(r'name="([^"]+)"[^>]*value="([^"]+)"')


def _is_main_config(path: str) -> bool:
    """Main deploy configuration only -- never a dev/local/test profile or a test fixture."""
    if _FACTS["test_path_marker"] in path:
        return False
    name = PurePosixPath(path).name
    if name in _FACTS["main_config_names"]:
        return True
    return any(name.startswith(prefix) for prefix in _FACTS["main_config_prefixes"])


def _clean(value: str) -> str:
    return value.split("#", 1)[0].strip().strip("\"'")


def _properties_hits(text: FileText) -> Iterator[tuple[int, str]]:
    for line_no, line in enumerate(text.lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, rest = stripped.partition("=")
        if key.strip() in _FACTS["keys"] and _clean(rest) in _FACTS["destructive_values"]:
            yield line_no, line


def _yaml_hits(text: FileText) -> Iterator[tuple[int, str]]:
    """A destructive value under the dotted key path its indentation nests it inside."""
    stack: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if ":" not in stripped:
            continue
        key, _, rest = stripped.partition(":")
        key = key.strip().strip("\"'")
        value = _clean(rest)
        path = ".".join([*(k for _, k in stack), key])
        if value:
            if path in _FACTS["keys"] and value in _FACTS["destructive_values"]:
                yield line_no, line
        else:
            stack.append((indent, key))


def _xml_hits(text: FileText) -> Iterator[tuple[int, str]]:
    for line_no, line in enumerate(text.lines, 1):
        match = _XML_PROPERTY.search(line)
        if match and match.group(1) in _FACTS["keys"] and match.group(2) in _FACTS["destructive_values"]:
            yield line_no, line


def scan(text: FileText) -> Iterator[Finding]:
    """A destructive schema-generation value, in the main configuration that deploy reads."""
    if not _is_main_config(text.path):
        return
    if text.suffix == ".properties":
        hits = _properties_hits(text)
    elif text.suffix in {".yml", ".yaml"}:
        hits = _yaml_hits(text)
    else:
        hits = _xml_hits(text)
    for line_no, line in hits:
        stripped = line.strip()
        key = next((k for k in _FACTS["keys"] if k in stripped), "the schema-generation setting")
        value = next((v for v in _FACTS["destructive_values"] if v in stripped), "")
        yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(key=key, value=value))


RULE = Rule(
    id=RULE_ID,
    pack="persistence",
    title="Destructive schema-generation in main config",
    suffixes=(".properties", ".yml", ".yaml", ".xml"),
    scan=scan,
    constraint=(
        "never(set): spring.jpa.hibernate.ddl-auto|hibernate.hbm2ddl.auto|"
        "javax|jakarta.persistence.schema-generation.database.action to "
        "create|create-drop|drop|update in main config -- use validate|none and a migration tool"
    ),
    refuses=(
        "`ddl-auto`/`hbm2ddl.auto`/`schema-generation.database.action` set to `create`, "
        "`create-drop`, `drop` or `update` in application.properties/yml, an application-prod* "
        "profile, persistence.xml or hibernate.cfg.xml"
    ),
    silent_on=(
        "`validate` and `none`; the same key in an application-dev/-local/-test profile or "
        "under src/test/; and any file that is not a Spring/Hibernate/JPA config file"
    ),
    cwe=("CWE-1188",),
    references=("https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/",),
)
