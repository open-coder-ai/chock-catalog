"""dockerfile-compose-security: rules over RUN shell text and ENV/ARG values, each shown reported and left alone."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import dockerkit

mod = dockerkit.load()

from dkscan import shellrules  # noqa: E402

HEAD = "FROM a@sha256:" + "0" * 64 + "\n"
TAIL = "USER 1000\n"
PIPE = "|"


def found(body: str, path: str = "Dockerfile", root: str = dockerkit.BARE) -> list[tuple[str, int]]:
    text = HEAD + body + TAIL
    payload = {"event": "tool_use", "repo_root": root, "writes": {path: text}}
    return [(f["rule"], f["line"]) for f in mod.findings(payload)]


def rules(body: str, path: str = "Dockerfile", root: str = dockerkit.BARE) -> set[str]:
    return {rule for rule, _ in found(body, path, root)}


@pytest.mark.parametrize(
    "body",
    [
        "RUN curl -fsSL https://example.com/i.sh \\\n  " + PIPE + " sh\n",
        "RUN wget -qO- https://example.com/i.sh \\\n  " + PIPE + " sudo -E bash -s -- --yes\n",
        "RUN curl -fsSL https://example.com/i.sh \\\n  " + PIPE + " tee /tmp/i \\\n  " + PIPE + " python3 -\n",
        'RUN sh -c "$( \\\n  curl -fsSL https://example.com/i.sh)"\n',
        "RUN bash <( \\\n  curl -s https://example.com/i)\n",
        'RUN eval \\\n  "$(wget -qO- https://example.com/i)"\n',
        "RUN <<EOF\ncurl -fsSL https://example.com/i.sh \\\n  " + PIPE + " bash\nEOF\n",
        "ONBUILD RUN curl -fsSL https://example.com/i.sh \\\n  " + PIPE + " sh\n",
        "RUN iex \\\n  (irm https://example.com/i.ps1)\n",
    ],
)
def test_fetch_exec_split_across_lines_is_reported(body: str) -> None:
    assert "dk-fetch-exec" in rules(body)


ONE_LINE = [
    "RUN curl -fsSL https://example.com/i.sh " + PIPE + " sh\n",
    "RUN apt-get update && \\\n  curl -fsSL https://example.com/i.sh " + PIPE + " bash\n",
    "RUN <<EOF\nset -e\ncurl -fsSL https://example.com/i.sh " + PIPE + " sh\nEOF\n",
    'RUN sh -c "$(curl -fsSL \\\n  https://example.com/i.sh)"\n',
    "RUN true \\\n  && bash <(curl -s https://example.com/i)\n",
]


@pytest.mark.parametrize("body", ONE_LINE)
def test_one_line_fetch_exec_is_reported_unless_block_fetch_exec_in_files_reads_it(body: str, tmp_path: Path) -> None:
    assert "dk-fetch-exec" in rules(body)
    root = dockerkit.installed(tmp_path, dockerkit.FETCH_EXEC)
    assert "dk-fetch-exec" not in rules(body, "svc/Dockerfile", root)
    assert "dk-fetch-exec" in rules(body, "dockerfile", root)
    assert "dk-fetch-exec" in rules(body, "img.containerfile", root)


@pytest.mark.parametrize(
    "body",
    [
        "RUN curl -fsSL https://example.com/a.json \\\n  " + PIPE + " jq .version\n",
        "RUN curl -fsSL https://example.com/a.json \\\n  "
        + PIPE
        + " python3 -c 'import json,sys; json.load(sys.stdin)'\n",
        "RUN curl -fsSLo /tmp/i.sh https://example.com/i.sh \\\n  && sha256sum -c sums \\\n  && sh /tmp/i.sh\n",
        "RUN curl -fsSL https://example.com/i.sh \\\n  " + PIPE * 2 + " sh -c 'echo failed'\n",
    ],
)
def test_safe_pipes_are_not_reported(body: str) -> None:
    assert "dk-fetch-exec" not in rules(body)


def test_split_fetch_exec_is_reported_even_where_the_one_line_gate_is_installed(tmp_path: Path) -> None:
    root = dockerkit.installed(tmp_path, dockerkit.FETCH_EXEC)
    assert "dk-fetch-exec" in rules("RUN curl -fsSL https://example.com/i.sh \\\n  " + PIPE + " sh\n", root=root)


def test_fetch_exec_lands_on_the_fetch_line() -> None:
    assert ("dk-fetch-exec", 4) in found(
        "RUN true\nRUN set -e; \\\n  curl -s https://example.com/i \\\n  " + PIPE + " sh\n"
    )


@pytest.mark.parametrize(
    "body",
    [
        "RUN curl -fsSLk https://example.com/x -o x\n",
        "RUN curl --insecure https://example.com/x\n",
        "RUN echo insecure >> ~/.curlrc\n",
        "RUN wget --no-check-certificate https://example.com/x\n",
        "RUN echo check_certificate = off >> /etc/wgetrc\n",
        "RUN aria2c --check-certificate=false https://example.com/x\n",
        "RUN pip install --trusted-host pypi.example.com x\n",
        "ENV PIP_TRUSTED_HOST=pypi.example.com\n",
        "ENV PYTHONHTTPSVERIFY=0\n",
        "ENV PYTHONHTTPSVERIFY 0\n",
        "ARG NPM_CONFIG_STRICT_SSL=false\n",
        "RUN npm config set strict-ssl false\n",
        "ENV GIT_SSL_NO_VERIFY=1\n",
        "ENV GIT_SSL_NO_VERIFY true\n",
        "RUN git config --global http.sslVerify false\n",
        "RUN echo sslverify=0 >> /etc/yum.conf\n",
        "RUN conda config --set ssl_verify no\n",
    ],
)
def test_tls_off(body: str) -> None:
    assert "dk-tls-off" in rules(body)


def test_node_tls_off_is_left_to_agentic_code_security_only_where_it_reads_the_line(tmp_path: Path) -> None:
    body = "ENV NODE_TLS_REJECT_UNAUTHORIZED=0\n"
    split = "ENV NODE_TLS_REJECT_UNAUTHORIZED=\\\n0\n"
    assert "dk-tls-off" in rules(body, "Dockerfile")
    root = dockerkit.installed(tmp_path, dockerkit.AGENTIC)
    assert "dk-tls-off" not in rules(body, "Dockerfile", root)
    assert "dk-tls-off" not in rules(body, "svc/Dockerfile.prod", root)
    assert "dk-tls-off" in rules(split, "Dockerfile", root)
    assert "dk-tls-off" in rules(body, "Containerfile", root)
    assert "dk-tls-off" in rules(body, "app.dockerfile", root)


@pytest.mark.parametrize(
    "body",
    [
        "RUN curl -fsSL -o x https://example.com/x\n",
        "RUN ssh-keygen -k -f x\n",
        "RUN curl --key k.pem https://example.com\n",
        "ENV GIT_SSL_NO_VERIFY=\n",
        "RUN git config --global http.sslVerify true\n",
        "ENV PYTHONHTTPSVERIFY=1\n",
        "ENV NODE_TLS_REJECT_UNAUTHORIZED=1\n",
    ],
)
def test_tls_on_is_silent(body: str) -> None:
    assert "dk-tls-off" not in rules(body, "Containerfile")


@pytest.mark.parametrize(
    "body",
    [
        "RUN apt-get install -y --allow-unauthenticated x\n",
        "RUN apt-get -o Acquire::AllowInsecureRepositories=true update\n",
        "RUN apt-get -o APT::Get::AllowUnauthenticated=true install x\n",
        "RUN echo 'deb [trusted=yes] http://example.com/ ./' > /etc/apt/sources.list.d/x.list\n",
        "RUN apk add --allow-untrusted x.apk\n",
        "RUN dnf install -y --nogpgcheck x\n",
        "RUN echo gpgcheck=0 >> /etc/yum.repos.d/x.repo\n",
        "RUN rpm -i --nosignature x.rpm\n",
        "RUN apt-get install -y --force-yes x\n",
        "RUN zypper --no-gpg-checks install x\n",
    ],
)
def test_signature_bypass(body: str) -> None:
    assert "dk-signature-bypass" in rules(body)


def test_signature_checks_on_are_silent() -> None:
    assert "dk-signature-bypass" not in rules(
        "RUN apt-get install -y --no-install-recommends x && git commit --no-verify\n"
    )


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ("RUN chmod 777 /app\n", "dk-chmod-setuid"),
        ("RUN chmod -R 0777 /app\n", "dk-chmod-setuid"),
        ("RUN chmod a+rwx /app\n", "dk-chmod-setuid"),
        ("RUN chmod u+s /bin/x\n", "dk-chmod-setuid"),
        ("RUN chmod 2755 /bin/x\n", "dk-chmod-setuid"),
        ("RUN sudo apt-get update\n", "dk-sudo-sshd"),
        ("RUN apt-get install -y openssh-server\n", "dk-sudo-sshd"),
        ("EXPOSE 80 22/tcp\n", "dk-sudo-sshd"),
        ('CMD ["/usr/sbin/sshd", "-D"]\n', "dk-sudo-sshd"),
        ("RUN echo 'root:pw' " + PIPE + " chpasswd\n", "dk-chpasswd"),
        ("RUN useradd -m -p x bob\n", "dk-chpasswd"),
        ("RUN passwd -d root\n", "dk-chpasswd"),
        ("RUN git clone https://example.com/r.git && cd r && git checkout main\n", "dk-git-clone-unpinned"),
        ("RUN git -c http.extraHeader=x clone --branch v1 https://example.com/r.git\n", "dk-git-clone-unpinned"),
        ("ONBUILD RUN make\n", "dk-onbuild-run"),
        ("RUN --security=insecure make\n", "dk-run-insecure"),
    ],
)
def test_hygiene_and_build_rules(body: str, rule: str) -> None:
    assert rule in rules(body)


@pytest.mark.parametrize(
    "body",
    [
        "RUN chmod 755 /app && chmod 1777 /tmp/x && chmod g-s /x && chmod -R go-w /app && chmod +x run.sh\n",
        "RUN chmod --reference=a b\n",
        "RUN apt-get install -y sudo-ldap-docs && echo sudo\n",
        "EXPOSE 2222 8022\n",
        'CMD ["nginx", "-g", "daemon off;"]\n',
        "RUN adduser --disabled-password --gecos '' app && useradd -m app\n",
        "RUN git clone https://example.com/r.git && git -C r checkout " + "a1" * 20 + "\n",
        "ONBUILD COPY . /app\n",
        "RUN --network=none make\n",
    ],
)
def test_hygiene_and_build_rules_stay_silent(body: str) -> None:
    assert not rules(body) & {
        "dk-chmod-setuid",
        "dk-sudo-sshd",
        "dk-chpasswd",
        "dk-git-clone-unpinned",
        "dk-onbuild-run",
        "dk-run-insecure",
    }


def test_chmod_mode_reader() -> None:
    assert shellrules.chmod_mode(" -R 4755 /x") == "sets the setuid or setgid bit"
    assert shellrules.chmod_mode(" o+w /x") == "makes the file world-writable"
    assert shellrules.chmod_mode(" -v") == ""
    assert shellrules.chmod_mode(" 0644 /x") == ""


def test_wrapped_and_quoted_command_positions() -> None:
    assert "dk-chmod-setuid" in rules("RUN env A=1 nohup /bin/chmod 777 /x\n")
    assert "dk-chpasswd" in rules("RUN bash -c 'useradd -p x bob'\n")
    assert "dk-chmod-setuid" not in rules("RUN echo chmod 777\n")


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ('RUN ["chmod", "777", "/x"]\n', "dk-chmod-setuid"),
        ('RUN chmod "4755" /x\n', "dk-chmod-setuid"),
        ("RUN find /app -type d -exec chmod 777 {} +\n", "dk-chmod-setuid"),
        ("RUN install -m 4755 tool /usr/local/bin/tool\n", "dk-chmod-setuid"),
        ("COPY --chmod=777 app /app\n", "dk-chmod-setuid"),
        ("RUN apt-get install -y curl sudo\n", "dk-sudo-sshd"),
        ("RUN apk add --no-cache openssh\n", "dk-sudo-sshd"),
        ("RUN echo pw " + PIPE + " passwd --stdin root\n", "dk-chpasswd"),
        ("RUN git --git-dir=/x/.git clone https://example.com/r.git\n", "dk-git-clone-unpinned"),
        ("RUN git clone https://example.com/r.git && echo " + "ab" * 20 + "\n", "dk-git-clone-unpinned"),
        ("ONBUILD RUN --security=insecure make\n", "dk-run-insecure"),
    ],
)
def test_review_round_one_misses_are_reported(body: str, rule: str) -> None:
    assert rule in rules(body)


@pytest.mark.parametrize(
    "body",
    [
        "RUN apk add --no-cache openssh-client && install -m 0755 tool /bin/tool\n",
        "COPY --chmod=0644 app /app\n",
        "RUN git clone https://example.com/r.git && git -C r fetch origin " + "cd" * 20 + "\n",
        "RUN git clone --revision=" + "ef" * 20 + " https://example.com/r.git\n",
    ],
)
def test_review_round_one_correct_forms_stay_silent(body: str) -> None:
    assert not rules(body) & {"dk-chmod-setuid", "dk-sudo-sshd", "dk-git-clone-unpinned"}
