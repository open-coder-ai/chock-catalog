"""dockerfile-compose-security: compose rules, with YAML aliases and merge keys expanded."""

from __future__ import annotations

import pytest
from policies import dockerkit

mod = dockerkit.load()

from dkscan import compose, composeyaml  # noqa: E402

DIGEST = "@sha256:" + "0" * 64
IMG = f"    image: app:1{DIGEST}\n"


def found(text: str, path: str = "compose.yaml") -> list[tuple[str, int]]:
    return [(f["rule"], f["line"]) for f in mod.findings({"event": "tool_use", "writes": {path: text}})]


def service(body: str) -> set[str]:
    return {rule for rule, _ in found("services:\n  web:\n" + IMG + body)}


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ("    privileged: true\n", "cm-privileged-caps"),
        ("    privileged: yes\n", "cm-privileged-caps"),
        ("    cap_add: [ALL]\n", "cm-privileged-caps"),
        ("    cap_add:\n      - CAP_SYS_ADMIN\n", "cm-privileged-caps"),
        ("    cap_add: [net_admin]\n", "cm-privileged-caps"),
        ('    security_opt: ["seccomp=unconfined"]\n', "cm-privileged-caps"),
        ("    security_opt:\n      - apparmor:unconfined\n", "cm-privileged-caps"),
        ("    security_opt: [label:disable]\n", "cm-privileged-caps"),
        ("    devices: [/dev/kvm:/dev/kvm]\n", "cm-privileged-caps"),
        ("    devices:\n      - source: /dev/sda\n        target: /dev/sda\n", "cm-privileged-caps"),
        ("    network_mode: host\n", "cm-host-namespaces"),
        ("    pid: 'host'\n", "cm-host-namespaces"),
        ("    ipc: host\n", "cm-host-namespaces"),
        ("    userns_mode: host\n", "cm-host-namespaces"),
        ("    uts: host\n", "cm-host-namespaces"),
        ("    volumes: [/var/run/docker.sock:/var/run/docker.sock]\n", "cm-docker-sock"),
        ("    volumes: ['//var/run/docker.sock:/s']\n", "cm-docker-sock"),
        ("    volumes: [/run:/host/run]\n", "cm-docker-sock"),
        ("    volumes: ['${SOCK:-/var/run/docker.sock}:/s']\n", "cm-docker-sock"),
        (
            "    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /s\n",
            "cm-docker-sock",
        ),
        ("    volumes: ['/:/host:ro']\n", "cm-sensitive-mount"),
        ("    volumes: [/etc:/host/etc]\n", "cm-sensitive-mount"),
        ("    volumes: [/etc/shadow:/s]\n", "cm-sensitive-mount"),
        ("    volumes: [/proc:/host/proc:ro]\n", "cm-sensitive-mount"),
        ("    volumes: ['~/.ssh:/root/.ssh']\n", "cm-sensitive-mount"),
        ("    volumes: ['$HOME/.aws:/root/.aws']\n", "cm-sensitive-mount"),
        ("    volumes: ['${HOME}:/home/me']\n", "cm-sensitive-mount"),
        ("    volumes: [/var/lib:/v]\n", "cm-sensitive-mount"),
        ("    volumes: [/etc/../root:/r]\n", "cm-sensitive-mount"),
        ("    environment:\n      DB_PASSWORD: hunter2\n", "cm-literal-secrets"),
        ("    environment:\n      - API_TOKEN=abc123\n", "cm-literal-secrets"),
        ("    ports: ['5432:5432']\n", "cm-ports-all-interfaces"),
        ("    ports: ['0.0.0.0:6379:6379']\n", "cm-ports-all-interfaces"),
        ("    ports: ['27017']\n", "cm-ports-all-interfaces"),
        ("    ports: ['${HOST_PORT}:5432']\n", "cm-ports-all-interfaces"),
        ("    ports: ['9200-9300:9200-9300/tcp']\n", "cm-ports-all-interfaces"),
        ("    ports:\n      - target: 3306\n        published: 3306\n", "cm-ports-all-interfaces"),
    ],
)
def test_reported(body: str, rule: str) -> None:
    assert rule in service(body)


@pytest.mark.parametrize(
    "body",
    [
        "    privileged: false\n",
        "    cap_add: [CHOWN, NET_BIND_SERVICE]\n",
        "    cap_drop: [ALL]\n",
        "    security_opt: [no-new-privileges:true]\n",
        "    network_mode: bridge\n    pid: 'service:db'\n",
        "    deploy:\n      resources:\n        reservations:\n          devices:\n            - capabilities: [gpu]\n",
        "    volumes: [./data:/data, data:/var/lib/postgresql/data, /tmp/x]\n",
        "    volumes: [/etc/localtime:/etc/localtime:ro, /etc/ssl/certs:/etc/ssl/certs:ro]\n",
        "    volumes: ['${DATA_DIR}:/data', '../src:/src']\n",
        "    volumes:\n      - type: volume\n        source: data\n        target: /d\n      - type: tmpfs\n        target: /t\n",
        "    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n      - X\n".replace("      - X\n", ""),
        "    environment:\n      - DB_PASSWORD\n      - DB_PASSWORD_FILE=/run/s/db\n",
        "    ports: ['127.0.0.1:5432:5432', '[::1]:6379:6379', '8080:80', '${P}:80']\n",
        "    ports:\n      - target: 3306\n        host_ip: 127.0.0.1\n",
        "    environment:\n      DB_PASSWORD:\n        nested: hunter2\n",
        "    environment:\n      DB_PASSWORD: " + "x" * 6 + "Y" * 8 + "\n",
    ],
)
def test_silent(body: str) -> None:
    assert not service(body)


def test_merged_anchor_and_alias_values_are_read() -> None:
    text = (
        "x-base: &base\n  privileged: true\n  cap_add: &caps [SYS_ADMIN]\n"
        "x-sock: &sock /var/run/docker.sock:/var/run/docker.sock\n"
        "services:\n  web:\n    <<: *base\n" + IMG + "    volumes: [*sock]\n"
        "  job:\n    <<: [*base]\n    privileged: false\n" + IMG + "    cap_add: *caps\n"
    )
    hits = found(text)
    assert ("cm-privileged-caps", 7) in hits
    assert ("cm-docker-sock", 9) in hits
    assert not [line for rule, line in hits if line == 11]
    assert ("cm-privileged-caps", 14) in hits


def test_inline_merge_map() -> None:
    assert "cm-host-namespaces" in service("    <<: {pid: host}\n")


@pytest.mark.parametrize(
    "text",
    [
        "services:\n  web:\n\timage: x\n",
        "services:\n  web:\n    <<: *missing\n",
        "a: &a\n  b: *a\n",
        "a: &a [x]\n"
        + "".join(
            f"l{i}: &l{i} [*{'a' if i == 0 else f'l{i - 1}'}, *{'a' if i == 0 else f'l{i - 1}'}]\n" for i in range(18)
        ),
    ],
)
def test_unreadable_compose_is_reported_not_passed(text: str) -> None:
    assert ("cm-unreadable", 1) in found(text)


@pytest.mark.parametrize(
    ("image", "rule"),
    [
        ("nginx", "cm-image-floating"),
        ("registry.example.com:5000/app", "cm-image-floating"),
        ("${IMAGE}", "cm-image-floating"),
        ("nginx:1.27", "cm-image-no-digest"),
        ("app:${TAG:-1.2}", "cm-image-no-digest"),
    ],
)
def test_images(image: str, rule: str) -> None:
    assert (rule, 3) in found(f"services:\n  web:\n    image: {image}\n")


@pytest.mark.parametrize(
    "text",
    [
        f"services:\n  web:\n    image: nginx:1.27{DIGEST}\n",
        "services:\n  web:\n    image: nginx:" + "late" + "st\n",
        "services:\n  web:\n    build: .\n    image: myapp\n",
        "services:\n  web:\n    build:\n      context: .\n    image: myapp\n",
    ],
)
def test_pinned_built_and_hp06_images_are_silent(text: str) -> None:
    assert not found(text)


def test_v1_layout_and_multi_document() -> None:
    text = "web:\n  image: nginx\n  privileged: true\nversion: '2'\nx-a: {privileged: true}\nnotes: {a: 1}\n---\nservices:\n  b:\n    pid: host\n"
    rules = {rule for rule, _ in found(text, "docker-compose.override.yml")}
    assert rules == {"cm-image-floating", "cm-privileged-caps", "cm-host-namespaces"}


def test_waiver_on_the_line_or_the_comment_above_counts_only_at_commit() -> None:
    text = (
        "services:\n  web:\n"
        + IMG
        + "    # chock: allow cm-host-namespaces\n    pid: host\n    ipc: host  # chock: allow cm-host-namespaces\n"
    )
    commit = mod.findings({"event": "commit", "writes": {"compose.yaml": text}})
    assert not commit
    assert len(mod.findings({"event": "tool_use", "writes": {"compose.yaml": text}})) == 2


def test_colon_parts_and_host_paths() -> None:
    assert compose.colon_parts("${A:-/x}:/y:ro") == ["${A:-/x}", "/y", "ro"]
    assert compose.colon_parts("[::1]:5432:5432") == ["[::1]", "5432", "5432"]
    assert compose.host_path("//etc//") == "/etc"
    assert compose.host_path("/") == "/"
    assert compose.host_path("rel") is None
    assert compose.mount_rule("${X}") is None


def test_services_ignores_top_level_non_services() -> None:
    entries = composeyaml.flatten("version: '3'\nnetworks: {a: {}}\n")[0]
    assert composeyaml.services(entries) == {}
