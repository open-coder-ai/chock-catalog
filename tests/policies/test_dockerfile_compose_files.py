"""dockerfile-compose-security: ENV/ARG secrets, COPY of key files and the whole context, remote ADD."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from policies import dockerkit

mod = dockerkit.load()

from dkscan import secrets  # noqa: E402

HEAD = "FROM a@sha256:" + "0" * 64 + "\n"
TAIL = "USER 1000\n"
SHA = "c0ffee" * 6 + "abcd"


def rules(body: str, writes: dict[str, str] | None = None, root: str = dockerkit.BARE) -> set[str]:
    payload = {"event": "tool_use", "repo_root": root, "writes": {"Dockerfile": HEAD + body + TAIL, **(writes or {})}}
    return {f["rule"] for f in mod.findings(payload)}


@pytest.mark.parametrize(
    "body",
    [
        "ENV DB_PASSWORD=hunter2\n",
        "ENV DB_PASSWORD hunter2\n",
        "ENV A=1 apiKey=abc123\n",
        "ARG GITHUB_TOKEN=abc123\n",
        "ENV PRIVATE_KEY='k1'\n",
        "ENV Secret=changeme\n",
        "ENV AWS_SECRET_ACCESS_KEY=abc\n",
    ],
)
def test_secret_literals_in_env_and_arg(body: str) -> None:
    assert "dk-secret-arg-env" in rules(body)


@pytest.mark.parametrize(
    "body",
    [
        "ARG GITHUB_TOKEN\n",
        "ENV DB_PASSWORD=${DB_PASSWORD}\n",
        "ENV DB_PASSWORD_FILE=/run/s/db\n",
        "ENV TOKEN_URL=https://example.com/t\n",
        "ENV AWS_ACCESS_KEY_ID=x\n",
        "ENV REQUIRE_TOKEN=true\n",
        "ENV PWD=/app\n",
        "ENV TOKENIZERS_PARALLELISM=false BYPASS_CACHE=1\n",
        "ENV API_KEY=<your-key>\n",
        "ENV API_KEY=\n",
    ],
)
def test_references_pointers_and_flags_are_not_secrets(body: str) -> None:
    assert "dk-secret-arg-env" not in rules(body)


def test_a_line_scan_secrets_refuses_is_left_to_it() -> None:
    long_value = "x" * 6 + "Y" * 8
    assert "dk-secret-arg-env" not in rules(f"ENV password={long_value}\n")
    assert "dk-secret-arg-env" in rules(f"ENV password={long_value[:8]}\n")


def test_secret_name_and_value_readers() -> None:
    assert secrets.is_secret_name("clientSecret")
    assert secrets.is_secret_name("DB_PASS")
    assert not secrets.is_secret_name("PASSWORD_MIN")
    assert not secrets.is_secret_name("")
    assert not secrets.is_secret_name("HOSTNAME")
    assert not secrets.is_literal("/run/secrets/db")
    assert not secrets.is_literal("{{ vault }}")


@pytest.mark.parametrize(
    "body",
    [
        "COPY .env /app/\n",
        "COPY .env.production /app/\n",
        "COPY id_rsa /root/.ssh/\n",
        "ADD server.key /etc/tls/\n",
        "COPY deploy-key.pem /k\n",
        "COPY .npmrc .pypirc /root/\n",
        "COPY ~/.aws /root/.aws\n",
        "COPY config/.ssh/known_hosts /x\n",
        'COPY ["certs/client.p12", "/c/"]\n',
        "COPY --from=build /src/.env /app/\n",
    ],
)
def test_copy_of_secret_files(body: str) -> None:
    assert "dk-copy-secrets" in rules(body)


@pytest.mark.parametrize(
    "body",
    [
        "COPY .env.example /app/\n",
        "COPY ca.pem /usr/local/share/ca-certificates/\n",
        "COPY id_rsa.pub /root/\n",
        "COPY src/ /app/\n",
        "COPY <<EOF /app/.env\nA=1\nEOF\n",
    ],
)
def test_ordinary_copies_are_silent(body: str) -> None:
    assert "dk-copy-secrets" not in rules(body)


def test_whole_context_copy_needs_a_dockerignore(tmp_path: Path) -> None:
    assert "dk-copy-all" in rules("COPY . .\n", root=str(tmp_path))
    assert "dk-copy-all" in rules("ADD ./ /app\n", root=str(tmp_path))
    assert "dk-copy-all" not in rules("COPY . .\n", {".dockerignore": ".git\n"}, root=str(tmp_path))
    assert "dk-copy-all" not in rules("COPY --from=build . .\n", root=str(tmp_path))
    (tmp_path / ".dockerignore").write_text(".env\n", encoding="utf-8")
    assert "dk-copy-all" not in rules("COPY . .\n", root=str(tmp_path))


def test_dockerignore_named_for_the_dockerfile(tmp_path: Path) -> None:
    payload = {
        "event": "tool_use",
        "repo_root": str(tmp_path),
        "writes": {"svc/Dockerfile": HEAD + "COPY . .\n" + TAIL, "svc/Dockerfile.dockerignore": "*\n"},
    }
    assert "dk-copy-all" not in {f["rule"] for f in mod.findings(payload)}
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / ".dockerignore").write_text("*\n", encoding="utf-8")
    payload["writes"] = {"svc/Dockerfile": HEAD + "COPY . .\n" + TAIL}
    assert "dk-copy-all" not in {f["rule"] for f in mod.findings(payload)}


@pytest.mark.parametrize(
    "body",
    [
        "ADD git@github.com:org/repo.git /src\n",
        "ADD --keep-git-dir=true git://example.com/r.git#main /src\n",
        "ADD \\\n  https://example.com/tool.tgz /opt/\n",
        'ADD ["https://example.com/tool.tgz", "/opt/"]\n',
    ],
)
def test_remote_add_without_a_pin(body: str) -> None:
    assert "dk-add-remote" in rules(body)


ONE_LINE_ADD = [
    "ADD https://example.com/tool.tgz /opt/\n",
    "ADD --chown=1:1 https://example.com/tool.tgz /opt/\n",
    "ADD https://github.com/org/repo.git /src\n",
]


@pytest.mark.parametrize("body", ONE_LINE_ADD)
def test_one_line_url_add_is_reported_unless_block_fetch_exec_in_files_reads_it(body: str, tmp_path: Path) -> None:
    assert "dk-add-remote" in rules(body)
    assert "dk-add-remote" not in rules(body, root=dockerkit.installed(tmp_path, dockerkit.FETCH_EXEC))


@pytest.mark.parametrize(
    "body",
    [
        "ADD --checksum=sha256:" + "0" * 64 + " https://example.com/tool.tgz /opt/\n",
        f"ADD git@github.com:org/repo.git#{SHA} /src\n",
        "ADD local.tgz /opt/\n",
    ],
)
def test_pinned_and_local_adds_are_silent(body: str) -> None:
    assert "dk-add-remote" not in rules(body)


@pytest.mark.parametrize(
    ("body", "rule", "expected"),
    [
        ("ENV PGPASSWORD=hunter2\n", "dk-secret-arg-env", True),
        ("ENV PASSWORD_HASH_ALGO=bcrypt PASS_MIN_DAYS=7\n", "dk-secret-arg-env", False),
        ("ENV DB_PASSWORD=hunter2 TEST_JWT=ey" + "J0.e30.x\n", "dk-secret-arg-env", True),
        ("COPY .env* /app/\n", "dk-copy-secrets", True),
        ("COPY .env.* /app/\n", "dk-copy-secrets", True),
    ],
)
def test_review_round_one_secret_cases(body: str, rule: str, expected: bool) -> None:
    assert (rule in rules(body)) is expected


def test_long_env_line_stays_fast() -> None:
    body = "ENV " + " ".join(f"K{i}_PASSWORD=v{i}" for i in range(3000)) + "\n"
    start = time.monotonic()
    assert "dk-secret-arg-env" in rules(body)
    assert time.monotonic() - start < 5
