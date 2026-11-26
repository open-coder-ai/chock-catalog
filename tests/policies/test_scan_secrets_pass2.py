"""scan-secrets 0.1.7 (R13-8): the owner's cases tc-101..tc-128 judged by the manifest's own pattern, and the silent forms."""

from __future__ import annotations

import re
import time

import pytest
import yaml
from policies import scriptkit
from trees import ROOT

PARAMS = scriptkit.manifest("scan-secrets")["hook"]["gate"]["params"]
PATTERN = re.compile(PARAMS["content_pattern"])
PATH = re.compile(PARAMS["forbidden_path_regex"])
SUITE = yaml.safe_load((ROOT / "base" / "scan-secrets" / "evals" / "suite.yaml").read_text(encoding="utf-8"))
# tc-109 (the jwt.io sample token) is not mirrored: the value the owner committed is not the one jwt.io shows today.
WAITING = {"tc-109"}
OWNER = [
    c
    for c in SUITE["suite"]["cases"]
    if re.fullmatch(r"tc-1[0-2]\d", c["id"]) and c["id"] not in WAITING and (c.get("execute") or {}).get("files")
]

# Forms that stay silent: references, placeholders and expressions, none of them a credential shape.
SILENT = """
PGPASSWORD=$DB_PASS psql -h db.acme-prod.io -U app prod
PGPASSWORD=changeme psql -h db.acme-prod.io -U app prod
PGPASSWORD=password psql -h db.acme-prod.io -U app prod
PGPASSWORD=${DB_PASS} psql -h db.acme-prod.io -U app prod
deployctl --host db.acme-prod.io --password=${DEPLOY_PASSWORD}
deployctl --host db.acme-prod.io --password=<password>
DB_PASSWORD=xxxx-xxxx-xxxx
DB_PASSWORD=xxxx\\nAPI_TOKEN=my-token
PASSWORD = get_password()
password = os.getenv("DB_PASSWORD", "not set")
let password = rpassword::prompt_password("Password: ")?;
password = foo.bar(baz)[0].qux
password = Optional<String>
password = event.target.value
password = settings.DB_PASSWORD
password = config.dbPassword
AccountKey=${AZURE_STORAGE_KEY};EndpointSuffix=core.windows.net
https://acme.blob.core.windows.net/data?sv=2022-11-02&se=2026-12-31&sig=${SAS_SIG}
https://acme.blob.core.windows.net/data/report.csv
""".strip().splitlines()


def verdict(files: dict[str, str]) -> str:
    """The verdict with no waiver honoured, as an agent's write is judged."""
    if any(PATH.search(name) for name in files):
        return "block"
    return "block" if any(PATTERN.search(line) for text in files.values() for line in text.splitlines()) else "allow"


def test_the_owner_cases_are_all_present() -> None:
    assert len(OWNER) == 27


@pytest.mark.parametrize("case", OWNER, ids=[c["id"] for c in OWNER])
def test_the_owner_case_gets_its_verdict(case: dict) -> None:
    assert verdict(case["execute"]["files"]) == case["execute"]["expect"]


@pytest.mark.parametrize("line", SILENT)
def test_the_pattern_is_silent(line: str) -> None:
    assert not PATTERN.search(line), line


@pytest.mark.parametrize(
    "path",
    ["keys/jwt-public.pem", "certs/ca.pem", "i18n/messages.key", "deploy/server.key", "tls/server.crt"],
)
def test_a_pem_or_key_file_is_judged_by_its_content_not_its_name(path: str) -> None:
    assert not PATH.search(path)


@pytest.mark.parametrize("path", [".env", "a/.env.production", "store.p12", "store.pfx", "store.jks", "store.keystore"])
def test_the_other_secret_files_keep_the_path_rule(path: str) -> None:
    assert PATH.search(path)


def test_a_private_key_block_is_refused_whatever_the_file_is_called() -> None:
    line = "-----BEGIN " + "RSA PRIVATE KEY-----"
    assert PATTERN.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "PGPASSWORD=" * 40000,
        "--password=" * 40000,
        "psql -h localhost " * 20000,
        "x;" * 100000 + "PGPASSWORD=",
        "?sv=2022-11-02&se=" * 20000,
        "?" * 200000,
        "password=a(" * 30000,
        "password=Aa." * 60000,
        "password=" + "a." * 100000,
    ],
    ids=lambda line: f"{line[:12]!r}x{len(line)}",
)
def test_the_new_alternatives_judge_a_hostile_line_in_linear_time(line: str) -> None:
    start = time.perf_counter()
    PATTERN.search(line)
    assert time.perf_counter() - start < 5.0
