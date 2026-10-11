"""block-secret-store-reads: cloud instance-metadata credential endpoints (secret_metadata.py and its table).

The eval suite holds the headline verdicts; these hold the address forms, the interpreter-literal rule, the
other entry points (sockets, /dev/tcp) and what a broken endpoint table does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import guardkit
from trees import ROOT

POLICY = "block-secret-store-reads"
TABLE_PATH = ROOT / "base" / POLICY / "implementations" / "data" / "metadata_endpoints.json"
meta = guardkit.load_guard(POLICY, "secret_metadata")
GUARD = guardkit.load_guard(POLICY)
CREDS = "/latest/meta-data/iam/security-credentials/"


def verdict(command: str) -> int:
    found = GUARD.check(command)
    return found[0] if found else 0


@pytest.mark.parametrize(
    ("host", "want"),
    [
        ("169.254.169.254", "169.254.169.254"),
        ("169.254.169.254.", "169.254.169.254"),
        ("2852039166", "169.254.169.254"),
        ("0xA9FEA9FE", "169.254.169.254"),
        ("0251.0376.0251.0376", "169.254.169.254"),
        ("169.254.43518", "169.254.169.254"),
        ("[::ffff:169.254.169.254]", "169.254.169.254"),
        ("[64:ff9b::a9fe:a9fe]", "169.254.169.254"),
        ("[FD00:EC2:0::254%25eth0]", "fd00:ec2::254"),
        ("fd00:ec2::254", "fd00:ec2::254"),
        ("Metadata.Google.Internal.", "metadata.google.internal"),
        ("1.2.3.4.5", "1.2.3.4.5"),
        ("256.1.1.1", "256.1.1.1"),
        ("169.254.0x1g", "169.254.0x1g"),
        ("169.254.-1.1", "169.254.-1.1"),
        ("[not-an-address]", "[not-an-address]"),
    ],
)
def test_a_host_is_read_as_curl_reads_it(host: str, want: str) -> None:
    assert meta.canonical(host) == want


@pytest.mark.parametrize(
    ("url", "want"),
    [
        ("http://user:pw@169.254.169.254:80/latest/meta-data/?x=1#y", ("169.254.169.254", "/latest/meta-data")),
        (
            "169.254.169.254/latest/./meta-data//placement/region/",
            ("169.254.169.254", "/latest/meta-data/placement/region"),
        ),
        ("//[fd00:ec2::254]:80/a/%2e%2e/b", ("fd00:ec2::254", "/b")),
        ("http://169.254.169.254", ("169.254.169.254", "/")),
    ],
)
def test_a_url_splits_into_host_and_resolved_path(url: str, want: tuple[str, str]) -> None:
    assert meta.split(url) == want


@pytest.mark.parametrize(
    "command",
    [
        f"curl http://169.254.169.254{CREDS}",
        f"curl --url=http://169.254.169.254{CREDS}",
        f"curl 'http://169.254.169.{{253,254}}{CREDS}'",
        f"wget -O- http://[::ffff:a9fe:a9fe]{CREDS}",
        "curl -s http://169.254.169.254/latest/meta-data/placement/%72egion/../../iam/",
        'curl -s "$AWS_CONTAINER_CREDENTIALS_FULL_URI"',
        "nc 169.254.169.254 80",
        "telnet metadata.google.internal 80",
        "cat < /dev/tcp/169.254.170.2/80",
        "python3 -c \"import http.client as h; c = h.HTTPConnection('169.254.169.254'); c.request('GET', '/x')\"",
        "python3 -c \"import urllib.request as u; u.urlopen('http://169.254.169.254/latest/meta-data/placement/region' + p)\"",
        "python3 -c \"import urllib.request as u; u.urlopen(f'http://169.254.169.254/latest/meta-data/{p}')\"",
        f"python3 -c \"import urllib.request as u; u.urlopen('http://169.254.169.254{CREDS}')\"",
        'node -e "console.log(process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)"',
        f"python3 <<'EOF'\nimport urllib.request as u\nu.urlopen('http://169.254.169.254{CREDS}')\nEOF",
    ],
)
def test_a_request_for_a_metadata_credential_is_refused(command: str) -> None:
    assert verdict(command) == GUARD.BLOCK
    assert "cloud CLI or SDK" in GUARD.check(command)[1]


@pytest.mark.parametrize(
    "command",
    [
        "curl -s http://169.254.169.254/latest/meta-data/instance-id",
        "curl -s http://[fd00:ec2::254]/latest/meta-data/placement/availability-zone",
        "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/zone",
        "curl -s -H Authorization:'Bearer Oracle' http://169.254.169.254/opc/v2/instance/region",
        "curl -s http://169.254.170.2/v2/metadata",
        "python3 -c \"import urllib.request as u; print(u.urlopen('http://169.254.169.254/latest/meta-data/placement/region').read())\"",
        "python3 -c \"import urllib.request as u; r = 'http://169.254.169.254/latest/meta-data/instance-id'\"",
        "python3 -c \"print('http://169.254.169.254/latest/meta-data/instance-id')\"",
        "python3 -c \"x = 1 // 2; print('169.254.169.2540')\"",
        "nc -z 10.0.0.5 80",
        "ping -c1 169.254.169.254",
        "curl -o 169.254.169.254.json https://example.com/data",
        "cat < /dev/tcp/example.com/80",
        "echo 169.254.169.254 > notes.txt",
    ],
)
def test_correct_work_near_the_metadata_service_is_left_alone(command: str) -> None:
    assert verdict(command) == 0


def broken(tmp_path: Path, change: dict) -> Path:
    doc = json.loads(TABLE_PATH.read_text(encoding="utf-8"))
    doc["endpoints"][0].update(change)
    path = tmp_path / "data" / "metadata_endpoints.json"
    path.parent.mkdir()
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"hosts": ["0xa9fea9fe"]}, "not in canonical form"),
        ({"allow": ["/latest/(unclosed"]}, "allow '/latest/(unclosed'"),
    ],
)
def test_a_broken_endpoint_table_is_refused(tmp_path: Path, change: dict, problem: str) -> None:
    with pytest.raises(Exception, match="metadata_endpoints") as exc:
        meta.load(broken(tmp_path, change))
    assert problem in str(exc.value)


def test_the_shipped_table_names_every_endpoint_the_plan_lists() -> None:
    hosts = {host for endpoint in meta.load().endpoints for host in endpoint.hosts}
    assert hosts == {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "169.254.170.2"}
