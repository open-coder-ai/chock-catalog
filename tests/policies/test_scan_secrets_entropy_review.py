"""scan-secrets-entropy: the shapes the adversarial review showed hiding real credentials, now reported."""

from __future__ import annotations

import string

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
        ("auth.py", f'headers = {{"Authorization": "SSWS {V}"}}'),
        ("auth.js", f'h.Authorization = "Token token={V}"'),
    ],
)
def test_source_and_embedded_string_forms_are_read(path: str, line: str) -> None:
    assert rules(line + "\n", path) == ["entropy"]


@pytest.mark.parametrize(
    "line",
    ['client_secret = load(name="x")', "client_secret: Optional[str] = None", 'f(a="x", secret=other_value)'],
)
def test_code_outside_a_literal_stays_unjudged(line: str) -> None:
    assert rules(line + "\n", "app.py") == []


def test_only_the_token_itself_absorbs_an_entropy_finding() -> None:
    token = kit.crc_token(5)
    assert rules(f"GITHUB_TOKEN={token}\n") == ["checksum"]
    assert rules(f"client_secret={token}-{V}\n") == ["checksum", "entropy"]
