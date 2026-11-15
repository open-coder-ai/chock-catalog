"""dockerfile-compose-security: the infra hardening review's catches and correct-work pairs (H-9), rebuilt as cases.

Case ids are the review's (REVIEW-infra.md, section 5). `judged` applies the engine's baseline rule to the gate's
findings: each finding of the HEAD copy absolves one of the same path and key, unless the finding says `new`.

Five review cases carry a literal secret and are not rebuilt here; each is held by a case already committed:

| review id | form | committed case |
|---|---|---|
| C04 | secret literal in ENV | eval tc-012 |
| C04v | secret literal in ARG default | test_dockerfile_compose_files.py, the ARG GITHUB_TOKEN row |
| C13 | compose literal in environment | test_dockerfile_compose_compose.py, the map-form DB_PASSWORD row |
| C13v | compose list form KEY=value | test_dockerfile_compose_compose.py, the list-form API_TOKEN row |
| S18 | dev override, 5432 published with a literal | eval tc-023 |
"""

from __future__ import annotations

import json

import pytest
from policies.dockerreview import BASE, IMG, LEGACY_COMPOSE, LEGACY_DOCKERFILE, PIN, SHA, SUM, compose, judged

# id -> (head files, written files)
CATCH = {
    "C01": (None, {"Dockerfile": "FROM ubuntu:latest\nUSER 1000\n"}),
    "C01v": (None, {"Dockerfile": "ARG BASE=ubuntu:latest\nFROM ${BASE}\nUSER 1000\n"}),
    "C02": (None, {"Dockerfile": "FROM ubuntu\nUSER 1000\n"}),
    "C02v": (None, {"Dockerfile": "FROM --platform=linux/amd64 ubuntu AS base\nUSER 1000\n"}),
    "C03": (None, {"Dockerfile": BASE + "USER 1000\nUSER root\n"}),
    "C03v": (None, {"Dockerfile": BASE + "RUN true\n"}),
    "C05": (None, {"Dockerfile": BASE + "RUN curl -fsSL https://example.com/i.sh | sh\nUSER 1000\n"}),
    "C05v": (None, {"Dockerfile": BASE + 'RUN bash -c "$(curl -fsSL \\\n  https://example.com/i.sh)"\nUSER 1000\n'}),
    "C06": (None, {"Dockerfile": BASE + "ADD https://example.com/app.tar.gz /opt/\nUSER 1000\n"}),
    "C06v": (None, {"Dockerfile": BASE + "ARG URL=https://example.com/app.tar.gz\nADD ${URL} /opt/\nUSER 1000\n"}),
    "C07": (None, {"Dockerfile": BASE + "RUN chmod 777 /app\nUSER 1000\n"}),
    "C07v": (None, {"Dockerfile": BASE + "RUN chmod -R a+rwx /app\nUSER 1000\n"}),
    "C08": (None, {"compose.yaml": compose("    privileged: true\n")}),
    "C08v": (
        None,
        {"compose.yaml": f"x-priv: &priv\n  privileged: true\nservices:\n  app:\n    <<: *priv\n    image: {IMG}\n"},
    ),
    "C09": (None, {"compose.yaml": compose("    network_mode: host\n")}),
    "C09v": (None, {"compose.yaml": compose('    pid: "host"\n')}),
    "C10": (None, {"compose.yaml": compose("    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n")}),
    "C10v": (
        None,
        {
            "compose.yaml": compose(
                "    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /var/run/docker.sock\n"
            )
        },
    ),
    "C11": (None, {"compose.yaml": compose('    ports:\n      - "5432:5432"\n')}),
    "C11v": (None, {"compose.yaml": compose('    ports:\n      - "0.0.0.0:${DB_PORT}:5432"\n')}),
    "C12": (None, {"compose.yaml": compose("    cap_add:\n      - ALL\n")}),
    "C12v": (None, {"compose.yaml": compose("    cap_add:\n      - SYS_ADMIN\n")}),
    "C14": (None, {"compose.yaml": compose("", image="nginx:latest")}),
    "C14v": (None, {"compose.yaml": json.dumps({"services": {"app": {"image": "nginx:latest"}}}, indent=2) + "\n"}),
}
MISSES = {"C06v"}

CORRECT = {
    "S01": (None, {"Dockerfile": BASE + "USER 1000\n"}),
    "S02": (
        None,
        {
            "Dockerfile": f"FROM golang:1.23{PIN} AS build\nUSER root\nRUN go build -o /app .\n{BASE}COPY --from=build /app /app\nUSER 1000\n"
        },
    ),
    "S03": (None, {"Dockerfile": "FROM scratch\nCOPY app /app\nUSER 10001\n"}),
    "S04": (None, {"Dockerfile": "FROM python:3.12.4-slim\nUSER 1000\n"}),
    "S05": (None, {"Dockerfile": BASE + "# never write USER root, FROM x:latest or curl | sh\nUSER 1000\n"}),
    "S06": (None, {"docs/containers.md": "Never write `privileged: true` or `USER root` in a final stage.\n"}),
    "S07": (
        None,
        {"tests/fixtures/bad/Dockerfile": "FROM ubuntu:latest\nRUN curl -fsSL https://example.com/i.sh | sh\n"},
    ),
    "S08": (None, {"Dockerfile": f"FROM gcr.io/distroless/static:nonroot{PIN}\nCOPY app /app\n"}),
    "S09": (None, {"Dockerfile": BASE + "RUN chmod 755 /app && chmod +x /entry.sh\nUSER 1000\n"}),
    "S10": (
        None,
        {
            "Dockerfile": BASE
            + f'RUN curl -fsSLo /tmp/i.sh https://example.com/i.sh && echo "{SUM}  /tmp/i.sh" | sha256sum -c - && sh /tmp/i.sh\nUSER 1000\n'
        },
    ),
    "S11": (None, {"Dockerfile": BASE + f"ADD --checksum=sha256:{SUM} https://example.com/a.tgz /opt/\nUSER 1000\n"}),
    "S12": (
        None,
        {
            "Dockerfile": BASE
            + "ARG TOKEN_TTL=3600\nRUN --mount=type=secret,id=npm_token NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci\nUSER 1000\n"
        },
    ),
    "S13": (None, {"Dockerfile": f"ARG BASE=alpine:3.20{PIN}\nFROM ${{BASE}}\nUSER 1000\n"}),
    "S14": (None, {"Dockerfile": BASE + "COPY . .\nUSER 1000\n", ".dockerignore": ".git\n.env\n"}),
    "S15": (
        None,
        {
            "compose.yaml": compose(
                '    ports:\n      - "8080:80"\n    cap_add:\n      - NET_BIND_SERVICE\n    volumes:\n'
                "      - data:/var/lib/data\n      - ./conf:/etc/app/conf:ro\n      - /etc/localtime:/etc/localtime:ro\n"
            )
            + "volumes:\n  data:\n"
        },
    ),
    "S16": (None, {"compose.yaml": compose('    ports:\n      - "127.0.0.1:5432:5432"\n')}),
    "S17": (
        None,
        {
            "compose.override.yaml": compose(
                '    ports:\n      - "127.0.0.1:5432:5432"\n', image="postgres:16.4", name="db"
            )
        },
    ),
    "S19": (None, {"compose.yaml": "services:\n  app:\n    build: .\n"}),
    "S20": (None, {"compose.yaml": json.dumps({"services": {"app": {"image": IMG}}}, indent=2) + "\n"}),
    "S21": (
        None,
        {"compose.yaml": compose('    healthcheck:\n      test: ["CMD", "curl", "-f", "http://localhost/health"]\n')},
    ),
    "S22": ({"Dockerfile": LEGACY_DOCKERFILE}, {"Dockerfile": LEGACY_DOCKERFILE + "LABEL team=infra\n"}),
    "S23": (
        {"Dockerfile": LEGACY_DOCKERFILE},
        {"Dockerfile": "\n" + LEGACY_DOCKERFILE.replace("\n", "\n\n") + "# end\n"},
    ),
    "S24": ({"Dockerfile": LEGACY_DOCKERFILE}, {"docker/Dockerfile": LEGACY_DOCKERFILE}),
    "S25": (
        {"compose.yaml": LEGACY_COMPOSE},
        {"compose.yaml": LEGACY_COMPOSE + '    healthcheck:\n      test: ["CMD", "true"]\n'},
    ),
    "S26": (
        {"compose.yaml": LEGACY_COMPOSE},
        {"compose.yaml": LEGACY_COMPOSE.replace("redis:latest", f"redis:7.2{PIN}")},
    ),
    "S27": ({"compose.yaml": LEGACY_COMPOSE}, {"compose.yaml": LEGACY_COMPOSE.replace("cache:", "store:")}),
    "S28": (None, {"build.py": 'DOCKERFILE = "FROM ubuntu:latest\\nUSER root\\n"\n'}),
    "S29": (None, {"compose.debug.yaml": compose("    profiles: [debug]\n    cap_add:\n      - SYS_PTRACE\n")}),
    "S30": (
        None,
        {
            "Dockerfile": BASE
            + f"RUN git clone https://github.com/example/r.git /r && git -C /r checkout {SHA}\nUSER 1000\n"
        },
    ),
    "S31": ({"Dockerfile": "FROM ubuntu:22.04\nUSER 1000\n"}, {"Dockerfile": "FROM ubuntu:24.04\nUSER 1000\n"}),
    "S32": (
        {"compose.yaml": compose("", image="postgres:16.3", name="db")},
        {"compose.yaml": compose("", image="postgres:16.4", name="db")},
    ),
    "S33": (
        {"Dockerfile": "FROM ubuntu:latest\nRUN true\n"},
        {"Dockerfile": f"FROM ubuntu:22.04{PIN}\nRUN true\n"},
    ),
}
STILL_REFUSED = {"S07", "S24", "S29"}


@pytest.mark.parametrize("case", CATCH)
def test_review_violation_is_caught_unless_it_is_a_disclosed_miss(case: str) -> None:
    head, writes = CATCH[case]
    verdict, _ = judged(head, writes)
    assert (verdict == "allow") == (case in MISSES), (case, verdict)


@pytest.mark.parametrize("case", CORRECT)
def test_review_correct_work_is_allowed_unless_a_rule_as_designed_or_the_engine_refuses_it(case: str) -> None:
    head, writes = CORRECT[case]
    verdict, rules = judged(head, writes)
    assert (verdict != "allow") == (case in STILL_REFUSED), (case, verdict, rules)


def test_counts() -> None:
    caught = sum(judged(*CATCH[case])[0] != "allow" for case in CATCH)
    refused = sum(judged(*CORRECT[case])[0] != "allow" for case in CORRECT)
    assert (len(CATCH), caught, len(CORRECT), refused) == (24, 23, 32, 3)
