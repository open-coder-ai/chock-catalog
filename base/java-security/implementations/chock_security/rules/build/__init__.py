"""The build pack: Build and dependencies."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.build import (
    build_checksum_disabled,
    build_dynamic_version,
    build_insecure_repository,
    build_vulnerable_dependency,
)

PACK = Pack(
    id="build",
    title="Build and dependencies",
    covers=(
        "Maven pom.xml and Gradle build scripts: repositories, checksums, and dependency versions with known remote-code-execution flaws."
    ),
)

RULES: tuple[Rule, ...] = (
    build_insecure_repository.RULE,
    build_checksum_disabled.RULE,
    build_vulnerable_dependency.RULE,
    build_dynamic_version.RULE,
)
