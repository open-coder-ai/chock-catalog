"""The bundle's rules: pack, tier, weakness and the tool or benchmark ids each one mirrors (roadmap 6.4, record 08 s2)."""

from __future__ import annotations

from typing import NamedTuple

DENY = "deny"
ASK = "ask"


class Rule(NamedTuple):
    id: str
    pack: str
    tier: str
    cwe: str
    refs: str
    fix: str


class Ctx(NamedTuple):
    """Per-file facts: which installed sibling gate already reads a one-line form here, and whether a .dockerignore exists."""

    ignored: bool = False
    fetch_exec_elsewhere: bool = False
    pins_elsewhere: bool = False
    node_tls_elsewhere: bool = False


class Hit(NamedTuple):
    """One finding: rule id, 1-based line, the text its baseline key is built from, and what is wrong."""

    rule: str
    line: int
    detail: str
    why: str


_TABLE = (
    (
        "dk-from-floating",
        "image",
        DENY,
        "CWE-829",
        "hadolint DL3006/DL3007, Trivy DS001, CKV_DOCKER_7",
        "name an exact tag, or better a digest (image:1.27.1@sha256:...)",
    ),
    (
        "dk-from-unresolved",
        "image",
        ASK,
        "CWE-829",
        "hadolint DL3006",
        "give the ARG a pinned default, or write the image out",
    ),
    (
        "dk-from-no-digest",
        "image",
        ASK,
        "CWE-829",
        "OpenSSF Scorecard Pinned-Dependencies",
        "add the digest: image:tag@sha256:...",
    ),
    (
        "cm-image-floating",
        "image",
        ASK,
        "CWE-829",
        "Trivy DS001, KICS Image Version Using 'latest'",
        "name an exact tag or digest, or a default in ${VAR:-image:1.2.3}",
    ),
    (
        "cm-image-no-digest",
        "image",
        ASK,
        "CWE-829",
        "OpenSSF Scorecard Pinned-Dependencies",
        "add the digest: image:tag@sha256:...",
    ),
    (
        "dk-fetch-exec",
        "build",
        DENY,
        "CWE-494",
        "roadmap HP03 (continuation-split forms)",
        "download to a file, verify it (sha256sum -c), then run it",
    ),
    (
        "dk-add-remote",
        "build",
        DENY,
        "CWE-494",
        "record 08 docker-add-remote-url",
        "ADD --checksum=sha256:... for a URL; a git source pinned to a 40-hex commit",
    ),
    (
        "dk-git-clone-unpinned",
        "build",
        ASK,
        "CWE-829",
        "record 08 docker-git-clone-unpinned",
        "git checkout <40-hex commit> after the clone, in the same RUN",
    ),
    (
        "dk-onbuild-run",
        "build",
        ASK,
        "CWE-829",
        "record 08 docker-onbuild",
        "move the step into the downstream Dockerfile, where it is reviewed",
    ),
    (
        "dk-run-insecure",
        "build",
        DENY,
        "CWE-250",
        "BuildKit RUN --security=insecure (privileged build step)",
        "drop --security=insecure; grant only the capability the step needs",
    ),
    (
        "dk-tls-off",
        "tls",
        DENY,
        "CWE-295",
        "CKV2_DOCKER_2-6, CKV2_DOCKER_12-16",
        "keep verification on; add a private CA to the trust store instead",
    ),
    (
        "dk-signature-bypass",
        "tls",
        DENY,
        "CWE-347",
        "CKV2_DOCKER_7-11, Dockle CIS-DI-0011",
        "import the repository's signing key; keep signature checks on",
    ),
    (
        "dk-secret-arg-env",
        "secrets",
        DENY,
        "CWE-798",
        "hadolint DL3064, Trivy DS031, CIS Docker 4.10",
        "RUN --mount=type=secret,id=... and a secret passed at build time",
    ),
    (
        "dk-copy-secrets",
        "secrets",
        DENY,
        "CWE-538",
        "Dockle CIS-DI-0010, CIS Docker 4.10",
        "keep the file out of the context (.dockerignore); RUN --mount=type=secret for build use",
    ),
    (
        "dk-copy-all",
        "secrets",
        ASK,
        "CWE-200",
        "record 08 docker-copy-all",
        "add a .dockerignore that excludes .git, .env and key files",
    ),
    (
        "dk-chpasswd",
        "secrets",
        DENY,
        "CWE-259",
        "CKV2_DOCKER_17, Dockle DKL-LI-0001",
        "no passwords in the image; authenticate with keys at run time",
    ),
    (
        "dk-last-user-root",
        "hygiene",
        DENY,
        "CWE-250",
        "hadolint DL3002, CKV_DOCKER_8, Trivy DS002, CIS Docker 4.1",
        "end the final stage with USER <non-root uid>",
    ),
    (
        "dk-chmod-setuid",
        "hygiene",
        ASK,
        "CWE-732",
        "Dockle CIS-DI-0008, record 08 docker-chmod-777",
        "grant the narrowest mode (755, 644) to the owning user; no setuid bits",
    ),
    (
        "dk-sudo-sshd",
        "hygiene",
        ASK,
        "CWE-250",
        "hadolint DL3004, CKV2_DOCKER_1, Trivy DS004/DS010, CWE-1327",
        "no sudo or sshd in a container; run as the needed user, docker exec to get in",
    ),
    (
        "cm-privileged-caps",
        "compose-priv",
        DENY,
        "CWE-250",
        "CIS Docker 5.4/5.3, KICS Privileged Containers Enabled",
        "drop privileged; cap_add only the narrow capability; keep seccomp and apparmor profiles",
    ),
    (
        "cm-host-namespaces",
        "compose-priv",
        DENY,
        "CWE-668",
        "CIS Docker 5.9/5.15/5.16/5.21",
        "use the container's own network, pid, ipc, uts and user namespaces",
    ),
    (
        "cm-docker-sock",
        "compose-priv",
        DENY,
        "CWE-250",
        "CIS Docker 5.31",
        "no Docker socket in a container; a socket proxy limited to read-only endpoints if one must",
    ),
    (
        "cm-sensitive-mount",
        "compose-priv",
        DENY,
        "CWE-732",
        "CIS Docker 5.5",
        "mount only the project directory or a named volume, read-only where possible",
    ),
    (
        "cm-literal-secrets",
        "secrets",
        DENY,
        "CWE-798",
        "record 08 compose-literal-secrets",
        "${VAR} from the environment, env_file, or a secrets: entry",
    ),
    (
        "cm-ports-all-interfaces",
        "compose-priv",
        ASK,
        "CWE-668",
        "record 08 compose-ports-all-interfaces",
        "publish on 127.0.0.1:host:container, or do not publish the port",
    ),
    (
        "dk-unjudgeable",
        "build",
        ASK,
        "",
        "roadmap 2.6 trap 15 (a construct the gate cannot read in full is reported)",
        "split the command into shorter commands or RUN steps",
    ),
    (
        "cm-unreadable",
        "compose-priv",
        DENY,
        "",
        "roadmap 2.6 trap 15 (unparseable security config)",
        "write the compose file so a YAML loader reads it one way only",
    ),
)

RULES: dict[str, Rule] = {row[0]: Rule(*row) for row in _TABLE}
