"""scan-secrets-entropy: the shapes the adversarial review showed hiding real credentials, now reported."""

from __future__ import annotations

import base64
import string
import time

import pytest
from chock_scan.libmods import rng
from policies import entropykit as kit

gate = kit.load()
shapes = gate.values.shapes
V = kit.secret(41)
URLSAFE = string.ascii_letters + string.digits + "-_"
PRINTABLE = string.ascii_letters + string.digits + "!@#$%^&*()[]<>{}-_=+;:,.?/|~"


def rules(text: str, path: str = "config.env") -> list[str]:
    return [row["rule"] for row in gate.judge(path, text, waivable=False)]


@pytest.mark.parametrize("key", ["AUTH_HEADER", "authorization_header", "api_key_header"])
def test_a_header_key_holds_the_credential_itself(key: str) -> None:
    assert rules(f'{key}="Bearer {V}"\n') == ["entropy"]


@pytest.mark.parametrize(
    "parts",
    [(24, 6, 27), (2, 2, 3, 40), (2, 22, 43)],
    ids=["discord-bot-style", "doppler-style", "sendgrid-style"],
)
def test_dotted_tokens_of_random_segments_are_not_taken_for_code(parts: tuple[int, ...]) -> None:
    missed = 0
    for seed in range(200):
        draws = rng(seed)
        token = ".".join("".join(draws.choice(URLSAFE) for _ in range(n)) for n in parts)
        missed += rules(f"CLIENT_SECRET={token}\n") != ["entropy"]
    assert missed <= 4


def test_symbol_passwords_are_not_taken_for_code_regex_or_references() -> None:
    missed = 0
    for seed in range(400):
        draws = rng(seed)
        value = "".join(draws.choice(PRINTABLE) for _ in range(draws.randint(20, 40))).replace('"', "")
        value = value.replace("\\", "").replace("#", "").replace(" ", "")
        if shapes.explain(value, "client_secret") is not None:
            missed += 1
    assert missed <= 8


@pytest.mark.parametrize(
    ("value", "shape"),
    [
        ("settings.STRIPE_API_KEY_V2", "code-name"),
        ("self._session_token_cache", "code-name"),
        ("secrets_manager.get_secret_value(", "code-name"),
        ("ConfigAttribute[str", "code-name"),
        (r"^\w+\s*=\s*(\d+)$", "regex"),
    ],
)
def test_code_and_regex_written_as_code_are_still_explained(value: str, shape: str) -> None:
    assert shapes.explain(value, "client_secret") == shape


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("db.cs", f'var cs = "Server=db;User Id=app;Password={V};";'),
        ("cb.py", f'url = "https://api.example.invalid/x?access_token={V}"'),
        ("cb.js", f"const u = `https://api.example.invalid/x?client_secret={V}`;"),
        ("cfg.py", f'blob = "{{\\"client_secret\\": \\"{V}\\"}}"'),
        ("nb.ipynb", f'    "client_secret = \\"{V}\\"\\n",'),
        ("app.py", f'client_secret = f"{V}"'),
        ("app.py", f'signing_key = b"{V}"'),
        ("App.cs", f'string clientSecret = @"{V}";'),
        ("svc.ts", f'private apiKey: string = "{V}";'),
        ("main.rs", f'let api_key: &str = "{V}";'),
        ("main.go", f'var apiKey string = "{V}"'),
        ("keys.h", f'#define API_KEY "{V}"'),
        ("Keys.cs", f'public const string ApiKey = "{V}";'),
        ("Keys.cs", f'const string ApiKey = "{V}";'),
        ("keys.rs", f'const API_KEY: &\'static str = "{V}";'),
        ("cfg.py", f'api_key: str | None = "{V}"'),
        ("svc.ts", f'apiKey: string | undefined = "{V}";'),
        ("greet.py", f'token = f"{V}{{user.name}}"'),
        ("login.ts", f"  password: '{base64.b64encode(V.encode()).decode()}'"),  # pragma: allowlist secret
        ("auth.py", f'headers = {{"Authorization": "SSWS {V}"}}'),
        ("auth.js", f'h.Authorization = "Token token={V}"'),
    ],
)
def test_source_and_embedded_string_forms_are_read(path: str, line: str) -> None:
    assert rules(line + "\n", path) == ["entropy"]


@pytest.mark.parametrize(
    "line",
    [
        'client_secret = load(name="x")',
        "client_secret: Optional[str] = None",
        'f(a="x", secret=other_value)',
        "log(f'Secret(secret_id={self._secret_id!r}, version={self.version_label})')",
        "_token = rf'(?:[{_punct}]+|{_core_token_pattern})'",
    ],
)
def test_code_outside_a_literal_stays_unjudged(line: str) -> None:
    assert rules(line + "\n", "app.py") == []


def test_only_the_token_itself_absorbs_an_entropy_finding() -> None:
    token = kit.crc_token(5)
    assert rules(f"GITHUB_TOKEN={token}\n") == ["checksum"]
    assert rules(f"client_secret={token}-{V}\n") == ["checksum", "entropy"]


@pytest.mark.parametrize("value", ["sha256=" + "ab" * 32, "md5=" + "cd" * 16])
def test_a_named_digest_stays_a_digest(value: str) -> None:
    assert rules(f"password_digest: {value}\n", "users.yaml") == []


def test_an_annotation_needs_a_statement_start_so_a_case_label_keeps_its_key() -> None:
    assert gate.values.source.rewrite(f'case token: x = "{V}"', language="ts") == f'case token: x = "{V}"'
    assert gate.values.source.rewrite(f'  api_key: str = "{V}"', language="py") == f'  api_key = "{V}"'


def test_a_long_line_of_annotation_lookalikes_is_rewritten_in_linear_time() -> None:
    line = ("a:" + " " * 998) * 1000
    start = time.perf_counter()
    gate.values.source.rewrite(line, language="ts")
    assert time.perf_counter() - start < 5


def test_legacy_encoded_text_is_judged_and_replacement_characters_hide_nothing() -> None:
    text = f"# R\u00e9glage de la base de donn\u00e9es\n# Pr\u00fcfung\ndb.password={V}\n"
    decoded = text.encode("cp1252").decode("utf-8", "replace")
    assert rules(decoded, "app.properties") == ["entropy"]
    assert rules(f"# \ufffd\ufffd\nCLIENT_SECRET={V}\n") == ["entropy"]


def test_utf16_is_told_by_parity_and_zero_filled_binaries_are_skipped() -> None:
    cjk = f"# \u8a2d\u5b9a\nclient_secret={V}\n".encode("utf-16-le").decode("latin-1")
    assert rules(cjk) == ["entropy"]
    zero_filled = "\x00" * 4000 + f"client_secret={V}\n" + "\x00\x01" * 50
    assert rules(zero_filled, "lib.so") == []


def test_a_binary_with_nuls_on_one_parity_is_still_binary() -> None:
    blob = "\x00\x01" * 4000 + f"client_secret={V}\n"
    assert rules(blob, "fw.bin") == []
