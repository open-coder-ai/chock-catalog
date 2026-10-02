"""scan-secrets-entropy detectors: which keyword-adjacent values, vendor tokens and card numbers are reported."""

from __future__ import annotations

import base64
import string

import pytest
from chock_scan.libmods import rng
from policies import entropykit as kit

gate = kit.load()
shapes = gate.values.shapes
V = kit.secret(1)
HEX40 = kit.draw(2, "0123456789abcdef", 40)


def rules(text: str, path: str = "config.txt") -> list[str]:
    return [row["rule"] for row in gate.judge(path, text, waivable=False)]


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("app.json", f'{{"client_secret": "{V}"}}\n'),
        ("config.yaml", f"accessKey: {V}\n"),
        (".env", f"DB_PASSWD={V}\n"),
        ("main.tf", f'master_key = "{V}"\n'),
        ("main.go", f'token := "{V}"\n'),
        ("app.rb", f':auth_token => "{V}"\n'),
        ("App.java", f'String signingKey = "{V}";\n'),
        ("app.js", f'headers: {{ Authorization: "Bearer {V}" }}\n'),
        ("deploy.sh", f'curl "https://hooks.example.invalid/cb?token={V}"\n'),
        ("settings.py", f"SECRET_KEY = '{HEX40}'\n"),
        ("k8s.yaml", f"  password: {base64.b64encode(V.encode()).decode()}\n"),
        ("crlf.ini", f"[db]\r\napi_key = {V}\r\n"),
        ("old-mac.properties", f"x=1\rspring.datasource.password={V}\r"),
    ],
)
def test_a_high_entropy_value_beside_a_secret_key_is_reported(path: str, text: str) -> None:
    assert rules(text, path) == ["entropy"]


@pytest.mark.parametrize(
    ("value", "shape"),
    [
        ("${PAYMENTS_API_KEY", "reference"),
        ("$(cat /run/secrets/db-password)", "reference"),
        ("correct horse battery staple", "text"),
        (r"\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}", "regex"),
        ("sk-live-abcdef1234567890", "filler"),
        (".allowCredentials(true)", "code-name"),
        ("quarkus.http.cors.access-control-allow-credentials", "code-name"),
        ("contextvars.Token[AppContext", "code-name"),
        ("CreationOptional<string", "code-name"),
        ("{vendors.repo_root_token(v", "code-name"),
        ("GITHUB_CLIENT_SECRET_NAME", "variable-name"),
        ("https://oauth2.googleapis.com/token", "url"),
        ("/usr/local/certificates/key", "words"),
        ("foo/restricted-psp-users", "words"),
        ("allow-credentials-header", "words"),
        ("SecretManagerServiceClient", "words"),
        ("0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13", "eth-address"),
        ("โปรดระบุรหัสผ่าน", "non-ascii"),
    ],
)
def test_a_value_written_as_code_text_or_a_path_is_explained(value: str, shape: str) -> None:
    assert shapes.explain(value, "client_secret") == shape


def test_a_hex_digest_beside_a_file_name_is_explained_but_not_beside_a_secret_name() -> None:
    digest = kit.draw(3, "0123456789abcdef", 64)
    assert shapes.explain(digest, "token-efficiency-gate.py") == "file-digest"
    assert shapes.explain(digest, "client_secret") is None
    assert rules(f'"token-efficiency-gate.py": "{digest}"\n') == []


@pytest.mark.parametrize("key", ["BeeTokenAddress", "token_url", "secret_name", "password_file"])
def test_a_key_that_names_something_about_a_secret_is_explained(key: str) -> None:
    assert shapes.explain(V, key) == "key-names-no-secret"


@pytest.mark.parametrize(
    "value",
    [
        "aB3dE6gH9jK2mN5pQ8rS1tU4",
        "/aB3dE6gH9jK2mN5/pQ8rS1tU4vW7",
        "k3jd9s2mx8qwe7zt",
        "plain-words-then-12345",
        "k3jd-9s2m-x8qw-e7zt",
        "rhythms-strength-scythe",
    ],
)
def test_values_that_only_look_structured_are_not_explained(value: str) -> None:
    assert shapes.explain(value, "client_secret") is None


@pytest.mark.parametrize(
    ("alphabet", "most"),
    [
        (string.digits + string.ascii_letters, 8),
        (string.digits + string.ascii_letters + "+/", 12),
        (string.hexdigits[:16], 2),
        (string.ascii_lowercase + string.digits, 2),
        (string.ascii_uppercase + string.digits, 2),
    ],
)
def test_random_credentials_are_almost_never_explained(alphabet: str, most: int) -> None:
    draws = rng(7)
    drawn = ["".join(draws.choice(alphabet) for _ in range(draws.randint(16, 64))) for _ in range(4000)]
    assert sum(shapes.explain(v, "client_secret") is not None for v in drawn) <= most


@pytest.mark.parametrize(
    "text",
    [
        "service_key: 123e4567-e89b-12d3-a456-426614174000\n",
        "client_secret: ${API_KEY}\n",
        "client_secret: your-client-secret-goes-here-0042\n",
        'secret_hash: "sha256:' + "ab" * 32 + '"\n',
        "db_passwd: aaaaaaaaaaaaaaaaaaaaaaaa\n",
        "db_passwd: short\n",
        f"client_secret: {kit.secret(4, 151)}\n",
        '    "integrity": "sha512-' + base64.b64encode(bytes(range(64))).decode() + '",\n',
        f'  token: "{V[:10]}\\nnext-value-is-here"\n',
    ],
)
def test_ordinary_config_lines_are_not_reported(text: str) -> None:
    assert rules(text, "config.yaml") == []


@pytest.mark.parametrize(
    "text",
    ["token = request.headers.get(AUTH_HEADER)\n", f"config = {{'name': '{V}'}}\n", f"secret = {V}\n"],
)
def test_ordinary_code_lines_are_not_reported(text: str) -> None:
    assert rules(text, "app.py") == []


def test_in_source_code_only_quoted_values_are_judged() -> None:
    assert rules(f"secret = {V}\n", "app.sh") == ["entropy"]
    assert rules(f"// signing_key: {V}\n", "App.java") == []
    assert rules(f'auth = "Basic {V}"\n', "client.py") == ["entropy"]


def test_an_escaped_newline_ends_the_judged_value() -> None:
    assert rules(f'"client_secret={V}\\npath=/x"\n') == ["entropy"]
    assert shapes.trim("abc\\tdef") == "abc"


def test_a_value_is_reported_once_per_line_however_often_it_repeats() -> None:
    assert rules(f"db_passwd={V} secret={V}\ndb_passwd={V}\n") == ["entropy", "entropy"]


def test_a_checksum_valid_token_is_reported_anywhere_on_a_line() -> None:
    for seed, prefix in enumerate(["ghp", "gho", "ghu", "ghs", "ghr", "npm"]):
        assert rules(f"see {kit.crc_token(seed, prefix)} in the logs\n") == ["checksum"]


def test_a_token_whose_checksum_fails_is_left_to_scan_secrets() -> None:
    token = kit.crc_token(1)
    broken = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert rules(f"see {broken}\n") == []


def test_a_token_in_a_keyword_assignment_is_reported_once_by_its_vendor_rule() -> None:
    assert rules(f"GITHUB_TOKEN={kit.crc_token(2)}\n") == ["checksum"]


@pytest.mark.parametrize(
    ("token", "rule"),
    [
        ("sk_test_" + kit.secret(5, 24), "stripe-test"),
        ("rk_test_" + kit.secret(6, 99), "stripe-test"),
        ("sk_live_" + kit.secret(7, 24), "vendor-format"),
        ("xapp-1-" + kit.secret(8, 11) + "-" + kit.secret(9, 24), "vendor-format"),
        ("xoxe.xoxp-1-" + kit.secret(10, 40), "vendor-format"),
        ("ABIA" + kit.draw(11, string.ascii_uppercase + string.digits, 16), "vendor-format"),
        ("ACCA" + kit.draw(12, string.ascii_uppercase + string.digits, 16), "vendor-format"),
    ],
)
def test_vendor_shapes_scan_secrets_misses_are_reported(token: str, rule: str) -> None:
    assert rules(f"value {token} end\n") == [rule]


@pytest.mark.parametrize(
    "token",
    [
        "pk_test_" + kit.secret(13, 24),
        "sk_test_" + "x" * 24,
        "AKIA" + "IOSFODNN7" + "EXAMPLE",
        "sk_test_" + kit.secret(14, 23),
        "github_pat_" + kit.secret(15, 22) + "_" + kit.secret(16, 59),
    ],
)
def test_public_placeholder_and_unvalidated_shapes_are_not_reported(token: str) -> None:
    assert rules(f"value {token} end\n") == []


def test_a_luhn_valid_card_number_is_reported_grouped_or_beside_a_card_word() -> None:
    card = kit.luhn_number(1)
    assert rules(f"pay with {kit.grouped(card)}\n") == ["card-number"]
    assert rules(f"pay with {kit.grouped(card, '-')}\n") == ["card-number"]
    assert rules(f"cardNum: {card}\n") == ["card-number"]
    amex = kit.luhn_number(2, "37", 15)
    assert rules(f"amex {amex[:4]} {amex[4:10]} {amex[10:]}\n") == ["card-number"]


def test_card_shapes_that_are_tests_bare_failing_or_off_network_are_not_reported() -> None:
    card = kit.luhn_number(3)
    failing = card[:-1] + str((int(card[-1]) + 1) % 10)
    assert rules("order " + kit.grouped("4242" * 4) + " is the documented test card\n") == []
    assert rules(f"id {card} is a bare number\n") == []
    assert rules(f"card {failing}\n") == []
    assert rules(f"card {kit.grouped(card)}x\n") == []
    assert rules(f"card {kit.luhn_number(4, '9')}\n") == []
