"""The build pack: Build and dependencies."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="build",
    title="Build and dependencies",
    covers=(
        "Maven pom.xml and Gradle build scripts: repositories, checksums, and dependency versions with known remote-code-execution flaws."
    ),
)

RULES: tuple[Rule, ...] = (
)
