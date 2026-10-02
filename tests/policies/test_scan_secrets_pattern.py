"""scan-secrets: every shape the content pattern names, shown refusing, silent on a look-alike, and under evasion."""

from __future__ import annotations

import re
import time

import pytest
from policies import scriptkit

PARAMS = scriptkit.manifest("scan-secrets")["hook"]["gate"]["params"]
PATTERN = re.compile(PARAMS["content_pattern"])
PATH = re.compile(PARAMS["forbidden_path_regex"])
LINEAR_BUDGET_S = 5.0

# One fixture per line, so each keeps its waiver on the line it waives.
# fmt: off
# (rule, a line it refuses, a look-alike it stays silent on, an evasion it still refuses)
RULES = [
    ("gitlab", "t = 'glpat-EXAMPLE0NOTAREAL0TOKEN'", "the glpat- prefix", "T='gldt-EXAMPLE0NOTAREAL0TOKEN'"),  # pragma: allowlist secret
    ("gitlab-runner", "GR1348941EXAMPLE0NOTAREAL0TOKEN", "GR1348941 short", "x=GR1348941EXAMPLE0NOTAREAL0TOKEN;"),  # pragma: allowlist secret
    ("huggingface", "hf_EXAMPLE0NOTAREAL0TOKEN000000000000", "hf_hub_download(repo)", "(hf_EXAMPLE0NOTAREAL0TOKEN000000000000)"),  # pragma: allowlist secret
    ("google-oauth", "ya29.EXAMPLE0NOTAREAL0TOKEN", "the ya29. prefix", "Bearer=ya29.EXAMPLE0NOTAREAL0TOKEN"),  # pragma: allowlist secret
    ("slack-webhook", "https://hooks.slack.com/services/TEXAMPLE0/BEXAMPLE0/NOTAREALWEBHOOK0SECRET", "https://hooks.slack.com/services/", "url=hooks.slack.com/workflows/TEXAMPLE0/BEXAMPLE0NOTAREAL"),  # pragma: allowlist secret
    ("slack-app", "xapp-1-EXAMPLE0NOTAREAL0TOKEN", "xapp-1 is the app token prefix", "t=xoxe.xoxp-1-EXAMPLE0NOTAREAL"),  # pragma: allowlist secret
    ("twilio", "SK00000000000000000000000000000000", "SKU00000000000000000000000000000000", "sid=SK0000000000000000000000000000000a,"),  # pragma: allowlist secret
    ("databricks", "dapi00000000000000000000000000000000", "dapi is the PAT prefix", "token: dapi0000000000000000000000000000000a"),  # pragma: allowlist secret
    ("doppler", "dp.st.EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0", "dp.st. is a service token", "dp.st.prd.EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0"),  # pragma: allowlist secret
    ("pulumi", "pul-0000000000000000000000000000000000000000", "pul-request", "PULUMI_ACCESS_TOKEN=pul-000000000000000000000000000000000000000a"),  # pragma: allowlist secret
    ("vault", "hvs.EXAMPLE0NOTAREAL0TOKEN0000", "hvs.short", "VAULT_TOKEN=hvb.EXAMPLE0NOTAREAL0TOKEN0000"),  # pragma: allowlist secret
    ("shopify", "shpat_00000000000000000000000000000000", "shpat_ prefix", "x-shopify:shpss_0000000000000000000000000000000a"),  # pragma: allowlist secret
    ("sentry", "sntryu_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0", "sntryu_short", "SENTRY=sntrys_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0"),  # pragma: allowlist secret
    ("grafana", "glsa_EXAMPLE0NOTAREAL0TOKEN0000000000_00000000", "glsa_ prefix", "glc_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0"),  # pragma: allowlist secret
    ("digitalocean", "dop_v1_0000000000000000000000000000000000000000000000000000000000000000", "dop_v1_ prefix", "doo_v1_000000000000000000000000000000000000000000000000000000000000000a"),  # pragma: allowlist secret
    ("linear", "lin_api_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0", "lin_api_ prefix", "lin_oauth_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0"),  # pragma: allowlist secret
    ("notion", "ntn_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0", "ntn_ prefix", "secret_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0TOK"),  # pragma: allowlist secret
    ("perplexity", "pplx-EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0TOKEN000", "pplx-api", "k=pplx-EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0TOKEN000;"),  # pragma: allowlist secret
    ("planetscale", "pscale_tkn_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAR", "pscale_tkn_ prefix", "pscale_pw_EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAR"),  # pragma: allowlist secret
    ("postman", "PMAK-000000000000000000000000-0000000000000000000000000000000000", "PMAK- prefix", "x-api-key:PMAK-00000000000000000000000a-000000000000000000000000000000000a"),  # pragma: allowlist secret
    ("heroku", "HRKU-EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0", "HRKU- prefix", "HEROKU_API_KEY=HRKU-EXAMPLE0NOTAREAL0TOKEN0EXAMPLE0NOTAREAL0"),  # pragma: allowlist secret
    ("pypi", "pypi-EXAMPLE0NOTAREAL0TOKEN0000000000000000000000000000000000000000000000000000000000000000000000", "pypi-simple", "password = pypi-EXAMPLE0NOTAREAL0TOKEN0000000000000000000000000000000000000000000000000000000000000000000000"),  # pragma: allowlist secret
    ("rubygems", "rubygems_000000000000000000000000000000000000000000000000", "rubygems_version", "GEM_HOST_API_KEY=rubygems_00000000000000000000000000000000000000000000000a"),  # pragma: allowlist secret
    ("openai-service", "sk-svcacct-EXAMPLE0NOTAREAL0TOKEN", "sk-svcacct- prefix", "OPENAI=sk-admin-EXAMPLE0NOTAREAL0TOKEN"),  # pragma: allowlist secret
    ("pem", "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----"),  # pragma: allowlist secret
    ("json-key", '"password": "s3cr3t-Value-99",', '"password": "changeme",', '{"API_KEY":"k3y-0123456789abcdef"}'),  # pragma: allowlist secret
    ("yaml-key", "accessToken: a1B2c3D4e5F6g7H8i9J0", "accessToken: ${ACCESS_TOKEN}", "ACCESS-TOKEN:\ta1B2c3D4e5F6g7H8i9J0"),  # pragma: allowlist secret
    ("aws-secret", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY0NOTREAL0", "AWS_SECRET_ACCESS_KEY=", "aws.secretAccessKey := 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY0NOTREAL0'"),  # pragma: allowlist secret
    ("hcl-key", 'password = "Sup3rS3cretPassw0rd"', "password = var.db_password", 'resource "x" { client_secret = "Gq8~abcDEF123ghiJKL456" }'),  # pragma: allowlist secret
    ("ruby-php-key", "'api_key' => 'a1b2c3d4e5f6g7h8i9'", "'api_key' => ENV['API_KEY']", "refresh_token: 'r3fr3shT0k3nV4lu3XYZ'"),  # pragma: allowlist secret
    ("uri", "postgres://app:s3cr3tpw@db.internal:5432/app", "postgres://postgres:postgres@localhost:5432/db", "REDIS=redis://:p4ssw0rdXY@cache:6379"),  # pragma: allowlist secret
    ("authorization", "-H 'Authorization: Bearer abc123def456ghi789'", "-H 'Authorization: Bearer $TOKEN'", '"authorization":"Basic dXNlcjpwYXNzd29yZA=="'),  # pragma: allowlist secret
    ("curl-user", "curl -u admin:S3cret99 https://api.internal", "curl -u user:password https://x", "curl -sS --user=admin:S3cret99 https://api.internal"),  # pragma: allowlist secret
    ("docker-login", "docker login -u bot -p S3cretPa55 registry.io", "docker login -u bot --password-stdin r.io", "podman login --password=S3cretPa55 r.io"),  # pragma: allowlist secret
    ("mysql", "mysql -u root -pS3cretPa55 db", "mysql -h db -P 3306 -u root -p db", "mysqldump -uroot -pS3cretPa55 db"),  # pragma: allowlist secret
    ("sshpass", "sshpass -p S3cretPa55 ssh host", "sshpass -p $PASS ssh host", "sshpass -pS3cretPa55 ssh host"),  # pragma: allowlist secret
    ("mysql-quoted", "mysql -u root -p'S3cretPa55' db", "mysql -u root -p db", "mysql -u root -p\"S3cretPa55\" db"),  # pragma: allowlist secret
    ("curl-attached", "curl -uadmin:S3cret99 https://api.internal", "curl --user-agent Foo:bar1 https://x", "curl --upload-file a.txt -uadmin:S3cret99 https://x"),  # pragma: allowlist secret
    ("docker-quoted", "docker login -u bot -p'S3cretPa55' r.io", "docker login -u bot --password-stdin r.io", "oras login -p \"S3cretPa55\" r.io"),  # pragma: allowlist secret
    ("index-assign", "config['password'] = 's3cr3t-Value-99'", "config['password'] = os.environ['PW']", "headers['Authorization'] = 'Bearer abc123def456ghi789'"),  # pragma: allowlist secret
    ("typed-assign", "password: str = 's3cr3t-Value-99'", "password: str", "const password: string = 's3cr3t-Value-99';"),  # pragma: allowlist secret
    ("prefixed-string", "password = b's3cr3t-Value-99'", "token = f'{settings.api_token_value}'", "api_key = r'a1b2c3d4e5f6g7h8i9'"),  # pragma: allowlist secret
    ("screaming-name", "GITHUB_TOKEN: a1B2c3D4e5F6g7H8i9J0k1", "MY_TOKEN_TTL=360000000000000000", "DB_PASS=a1B2c3D4e5F6g7H8i9J0k1"),  # pragma: allowlist secret
    ("more-names", "webhook_secret: 'Wh9-a1B2c3D4e5F6g7'", "webhook_secret_name: 'Wh9-a1B2c3D4e5F6g7'", "SECRET_KEY_BASE=a1B2c3D4e5F6g7H8i9J0k1"),  # pragma: allowlist secret
    ("placeholder-boundary", "\"password\": \"Enterprise2024!Pass\"", "\"password\": \"your-password\"", "\"password\": \"Samples2024!Qz\""),  # pragma: allowlist secret
    ("prefixed-value", "client_secret: \"cs_8f3a9b2c1d4e5f60718293a4b5c6d7e8\"", "access_key = 'AWS_ACCESS_KEY_ID_2'", "private_key: pk_8f3a9b2c1d4e5f60718293a4b5c6d7e8"),  # pragma: allowlist secret
    ("long-value", "access_token: \"Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+Ab3+\"", "access_token: \"<access-token-2>\"", "AWS_SESSION_TOKEN=FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1FwoGZXIvYXdzE1"),  # pragma: allowlist secret
    ("snake-password", "\"password\": \"summer_2024_prod_x\"", "\"password\": \"your-password-here\"", "\"password\": \"ADMIN_2024_SECRET\""),  # pragma: allowlist secret
    ("placeholder-digits", "\"password\": \"My_Pass_2024!\"", "\"password\": \"changeme\"", "\"password\": \"example-Real-99\""),  # pragma: allowlist secret
]
# fmt: on


@pytest.mark.parametrize(("rule", "line"), [(r[0], r[1]) for r in RULES] + [(r[0], r[3]) for r in RULES])
def test_the_pattern_refuses(rule: str, line: str) -> None:
    assert PATTERN.search(line), f"{rule}: {line!r}"


@pytest.mark.parametrize(("rule", "line"), [(r[0], r[2]) for r in RULES])
def test_the_pattern_is_silent_on_a_look_alike(rule: str, line: str) -> None:
    assert not PATTERN.search(line), f"{rule}: {line!r}"


@pytest.mark.parametrize(
    "line",
    [
        "password: ENC[AES256_GCM,data:abc123def456ghi789=,iv:xyz0,tag:abc0,type:str]",
        "password: vault:secret/data/db#password",
        'password = os.environ.get("DB_PASSWORD")',
        "password = process.env.DB_PASSWORD_2",
        'apiKey: "{{ .Values.apiKey }}"',
        '"private_key": "/etc/ssl/private/server1.key"',
        "def sign(private_key: Ed25519PrivateKey, password_min_length: int = 12):",
        '"static_access_key": "struts.ognl.allowStaticMethodAccess",',
        'token = "AWS_ACCESS_KEY_ID"',
        "amqp://guest:guest@rabbit:5672/",
        "git+ssh://git@github.com/org/repo.git",
        "private_key=private_key_pem2,",
        "access_key = 'AWS_ACCESS_KEY_ID_2'",
        "private_key: 'secrets/prod-key2.pem'",
        "Authorization: Bearer ACCESS_TOKEN_2",
        "access_token: get_access_token_v2(client)",
        "access_token=oauth2_access_token.value,",
        'headers = {"Authorization": f"Bearer {token}"}',
    ],
)
def test_references_and_ordinary_code_are_silent(line: str) -> None:
    assert not PATTERN.search(line), line


@pytest.mark.parametrize(
    "line",
    [
        "client_secret:",  # the value on the next line is a documented miss: one line at a time
        "data: Z2xwYXQtRVhBTVBMRTBOT1RBUkVBTDBUT0tFTg==",  # base64-wrapped token: documented miss
        '"password": "your-password-plus-letters"',  # a placeholder word followed by digitless text: documented miss
    ],
)
def test_documented_misses_stay_documented(line: str) -> None:
    assert not PATTERN.search(line), line


@pytest.mark.parametrize(
    ("path", "blocked"),
    [
        (".env", True),
        ("app/.env.local", True),
        (".env.production", True),
        (".env.example.local", True),
        ("config.env", True),
        ("deploy/server.pem", True),
        (".env.example", False),
        (".env.local.example", False),
        ("web/.env.production.sample", False),
        (".env.staging.template", False),
        (".envrc", False),
    ],
)
def test_forbidden_paths(path: str, blocked: bool) -> None:
    assert bool(PATH.search(path)) is blocked, path


@pytest.mark.parametrize(
    "line",
    [
        "curl " * 20000,
        "mysql -" * 15000,
        "docker login " * 10000,
        ("authorization: bearer " + "a" * 100 + "!") * 1000,
        "apikey=" * 15000 + "1!",
        "eyJ" * 33000,
        "A" * 200000,
        "P_" * 100000,
        ("_TOKEN=" + "1" * 40) * 4300,
        ("API_TOKEN=" + "1" * 8) * 11000,
        ("A_TOKEN:" + "A_" * 40) * 2300,
    ],
    ids=lambda line: f"{line[:12]!r}x{len(line)}",
)
def test_a_hostile_line_is_judged_in_linear_time(line: str) -> None:
    # Unbounded scans took 10 to 76 s on lines like these; every scan-ahead in the pattern is bounded.
    start = time.perf_counter()
    PATTERN.search(line)
    assert time.perf_counter() - start < LINEAR_BUDGET_S
