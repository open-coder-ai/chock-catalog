"""chock_scan.keyword_values: values assigned to secret-like keys, and the forms a consumer must not lose.

Lines are composed per case from a key, a form and a neutral value, so the cases read as the
assignments they model without a credential-shaped literal in this file.
"""

from __future__ import annotations

import string
import time
from types import ModuleType

import pytest
from chock_scan import tokens
from chock_scan.libmods import ids, load, rng, sources, stdlib_only

SOURCES = sources("keyword_values")
VALUE = "Qz8pL2wXy7Kd3mNv9"
SECRET_KEYS = [
    "password", "db_password", "PASSWORD", "passwd", "pwd", "passphrase", "apiKey", "API_KEY", "api-key",
    "apikey", "client_secret", "clientSecret", "accessToken", "GITHUB_TOKEN", "awsSecretAccessKey",
    "private_key", "privateKey", "signingKey", "secretKey", "credentials", "x-auth-token", "Auth",
    "SENTRY_DSN", "masterKey", "app.secret", "oauth2Token", "s3_secret", "APIKey",
]  # fmt: skip
PLAIN_KEYS = [
    "author", "authority", "tokenizer", "keyboard", "monkey", "primary_key", "key", "id", "hash",
    "integrity", "checksum", "resolved", "passage", "secretary", "keys", "sha512", "url", "name",
]  # fmt: skip
FORMS = [
    "{k}={v}", "{k}: {v}", '"{k}": "{v}"', "'{k}' => '{v}'", '{k} := "{v}"', "export {k}={v}",
    "  {k}:\t{v}  # trailing comment", "--{k}={v}", "{k}=`{v}`", "url=https://h/?{k}={v}&x=1",
    "cfg.{k} = '{v}'", "{{{k}: {v}}}", "[{k}={v}]", "f({k}={v}, y)", "\ufeff{k}={v}", "{k} =  \t {v};",
]  # fmt: skip


@pytest.fixture(params=SOURCES, ids=ids(SOURCES))
def kv(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param, "keyword_values")


@pytest.mark.parametrize("key", SECRET_KEYS)
def test_secret_keys(kv: ModuleType, key: str) -> None:
    assert kv.secret_key(key)


@pytest.mark.parametrize("key", PLAIN_KEYS)
def test_plain_keys(kv: ModuleType, key: str) -> None:
    assert not kv.secret_key(key)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("key", SECRET_KEYS[::3])
def test_every_form_yields_the_value_once(kv: ModuleType, form: str, key: str) -> None:
    line = form.format(k=key, v=VALUE)
    found = list(kv.candidates(line))
    assert [(c.line, c.value) for c in found] == [(1, VALUE)], line
    assert line[found[0].column :].startswith(VALUE)
    assert kv.secret_key(found[0].key)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("key", PLAIN_KEYS[::3])
def test_plain_keys_yield_nothing(kv: ModuleType, form: str, key: str) -> None:
    assert list(kv.candidates(form.format(k=key, v=VALUE))) == []


@pytest.mark.parametrize(("size", "found"), [(15, False), (16, True), (150, True), (151, False), (500, False)])
def test_only_judged_lengths_are_yielded(kv: ModuleType, size: int, found: bool) -> None:
    value = (VALUE * 40)[:size]
    assert bool(list(kv.candidates(f'token = "{value}"'))) is found
    assert bool(list(kv.candidates(f"token={value}"))) is found


def test_line_endings_and_numbering(kv: ModuleType) -> None:
    text = f"a=1\r\npassword={VALUE}\rtoken: {VALUE}\n\nsecret='{VALUE}'"
    assert [(c.line, c.key) for c in kv.candidates(text)] == [(2, "password"), (3, "token"), (5, "secret")]


def test_two_assignments_on_one_line_and_a_value_named_twice(kv: ModuleType) -> None:
    line = f"password={VALUE} token={VALUE[::-1]}"
    assert [c.value for c in kv.candidates(line)] == [VALUE, VALUE[::-1]]
    assert [c.key for c in kv.candidates(f"cfg.my-api-key = '{VALUE}'")] == ["cfg.my-api-key"]


def test_a_key_hidden_in_another_value_is_still_found(kv: ModuleType) -> None:
    line = f"endpoint: https://user@host/path?x=1&access_token={VALUE}#frag"
    assert [(c.key, c.value) for c in kv.candidates(line)] == [("access_token", VALUE)]


def test_documented_misses(kv: ModuleType) -> None:
    assert list(kv.candidates(f"password:\n  {VALUE}")) == []  # value on the next line
    assert list(kv.candidates(f"p\u00e4ssword={VALUE}")) == []  # keys are ASCII words
    escaped = list(kv.candidates(f'password = "ab\\"{VALUE}"'))
    assert escaped == []  # an escaped quote ends the value early; the 3-character prefix is too short
    assert [c.key for c in kv.candidates("x" * 200 + f"_token={VALUE}")] == []  # a key over 128 chars
    assert [c.key for c in kv.candidates("x" * 200 + f"-token={VALUE}")] == ["token"]


def test_too_large_raises_instead_of_judging_part(kv: ModuleType) -> None:
    assert list(kv.candidates("a" * kv.MAX_CHARS)) == []
    with pytest.raises(kv.TooLargeError):
        list(kv.candidates("a" * (kv.MAX_CHARS + 1)))


@pytest.mark.parametrize("seed", range(200))
def test_arbitrary_text_never_raises_and_every_candidate_is_real(kv: ModuleType, seed: int) -> None:
    r = rng(seed)
    pool = string.printable + "\u00e9\u200b\ufeff\0=:\"'`"
    parts = [tokens.draw(r, pool, r.randrange(0, 40)) for _ in range(r.randrange(1, 12))]
    keys = [r.choice(SECRET_KEYS + PLAIN_KEYS) for _ in parts]
    text = "".join(
        f"{p}{k}{r.choice(['=', ': ', ' => ', ':='])}{tokens.draw(r, tokens.BASE62, 20)}"
        for p, k in zip(parts, keys, strict=True)
    )
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    for c in kv.candidates(text):
        assert lines[c.line - 1][c.column :].startswith(c.value)
        assert kv.MIN_LEN <= len(c.value) <= kv.MAX_LEN
        assert kv.secret_key(c.key)


@pytest.mark.parametrize(
    "text",
    [
        "a-" * 500_000,
        "a" * 1_000_000 + "=x",
        "password=" * 100_000,
        '"' * 1_000_000,
        "token: " + "x" * 1_000_000,
        ("k" * 127 + "=") * 7_000,
        "=" * 1_000_000,
        " " * 1_000_000 + "token",
    ],
    ids=["dashes", "long-word", "repeated-key", "quotes", "long-value", "max-keys", "operators", "blanks"],
)
def test_pathological_lines_are_linear(kv: ModuleType, text: str) -> None:
    started = time.perf_counter()
    list(kv.candidates(text))
    assert time.perf_counter() - started < 3.0


def test_stdlib_only() -> None:
    assert stdlib_only("keyword_values")


@pytest.mark.parametrize(
    "form",
    [
        'password = """{v}"""',
        "password = '''{v}'''",
        "password: !!str {v}",
        "password: &anchor {v}",
        "password: !vault &a {v}",
        "Authorization: Bearer {v}",
        "token=Basic {v}",
        "headers.authorization = 'Token {v}'",
    ],
)
def test_review_forms_are_found(kv: ModuleType, form: str) -> None:
    assert [c.value for c in kv.candidates(form.format(v=VALUE))] == [VALUE]


@pytest.mark.parametrize(
    "form",
    [
        "password = !{v} # prod",
        "password: !{v}  // c",
        "password = !{v} x",
        "password = &{v} x",
        "password: !!str !{v} # c",
    ],
)
def test_a_value_starting_with_a_tag_character_is_not_taken_for_a_tag(kv: ModuleType, form: str) -> None:
    # round-2 review: a possessive tag group swallowed `!secret` and then lost it to trailing text
    found = [c.value for c in kv.candidates(form.format(v=VALUE))]
    assert len(found) == 1
    assert found[0] in {"!" + VALUE, "&" + VALUE}


def test_a_bare_value_may_start_with_an_ampersand(kv: ModuleType) -> None:
    assert [c.value for c in kv.candidates(f"PASSWORD=&{VALUE}")] == ["&" + VALUE]
    assert [c.value for c in kv.candidates(f"a=1&token={VALUE}&b=2")] == [VALUE]


def test_an_empty_quoted_value_reports_nothing_after_it(kv: ModuleType) -> None:
    assert list(kv.candidates(f'password = "" # {VALUE}')) == []


@pytest.mark.parametrize(
    "form",
    [
        "<password>{v}</password>",  # XML element text
        '<add key="password" value="{v}"/>',  # XML attribute pair
        "password\u00a0= {v}",  # a no-break space is not a blank
        "password" + " " * 17 + "= {v}",  # a gap wider than 16 blanks
        "PW=abc#{v}",  # `#` ends a bare value; the 3-character prefix is too short
    ],
)
def test_documented_form_misses(kv: ModuleType, form: str) -> None:
    assert list(kv.candidates(form.format(v=VALUE))) == []
