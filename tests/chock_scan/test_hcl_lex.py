"""chock_scan.hcl_lex: tokens, string and heredoc decoding, comments, and every refusal, named."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


def kinds(m: SimpleNamespace, text: str) -> list[tuple[str, str]]:
    return [(t.kind, t.text) for t in m.hcl_lex.tokens(text)]


def value(m: SimpleNamespace, text: str) -> object:
    (tok, eof) = m.hcl_lex.tokens(text)
    assert eof.kind == "EOF"
    return tok.value


def test_tokens_carry_kind_text_and_offsets_and_lines_maps_offsets(m: SimpleNamespace) -> None:
    src = 'a = 1.5e3\n  b-c_2 = "x" # c\r\nfoo.bar[0]...'
    toks = m.hcl_lex.tokens(src)
    line = m.hcl_lex.Lines(src)
    assert [(t.kind, t.text, line(t.start)) for t in toks] == [
        ("IDENT", "a", 1), ("PUNCT", "=", 1), ("NUMBER", "1.5e3", 1), ("NL", "\n", 1),
        ("IDENT", "b-c_2", 2), ("PUNCT", "=", 2), ("STRING", '"x"', 2), ("NL", "\r\n", 2),
        ("IDENT", "foo", 3), ("PUNCT", ".", 3), ("IDENT", "bar", 3), ("PUNCT", "[", 3),
        ("NUMBER", "0", 3), ("PUNCT", "]", 3), ("PUNCT", "...", 3), ("EOF", "", 3),
    ]  # fmt: skip
    assert toks[2].start == 4
    assert toks[2].end == 9
    assert all(src[t.start : t.end] == t.text for t in toks)


@pytest.mark.parametrize("op", ["==", "!=", "<=", ">=", "&&", "||", "=>", "...", *"+-*/%<>!?:.,=()[]{}~"])
def test_every_operator_is_one_token(m: SimpleNamespace, op: str) -> None:
    assert kinds(m, op) == [("PUNCT", op), ("EOF", "")]


def test_identifiers_take_unicode_letters_underscore_and_dashes(m: SimpleNamespace) -> None:
    assert kinds(m, "_x \u00e9-ü9 ж") == [("IDENT", "_x"), ("IDENT", "\u00e9-ü9"), ("IDENT", "ж"), ("EOF", "")]


@pytest.mark.parametrize(
    ("src", "want"),
    [
        (r'"a\nb\t\"\\\r"', 'a\nb\t"\\\r'),
        (r'"\u00e9\U0001F600"', "\u00e9\U0001f600"),
        ('"$${x} %%{y} $$ %% $x %x"', "${x} %{y} $$ %% $x %x"),
        ('"it\'s"', "it's"),
        ('""', ""),
    ],
    ids=["escapes", "unicode", "template-escapes", "single-quote", "empty"],
)
def test_quoted_strings_decode(m: SimpleNamespace, src: str, want: str) -> None:
    assert value(m, src) == want


@pytest.mark.parametrize(
    "src",
    ['"${var.x}"', '"a-${b}"', '"%{ if x }y%{ endif }"', '"${ {a = "}"}["a"] }"', '"${"${x}"}"', '"${\nx\n}"'],
    ids=["interp", "prefix", "directive", "brace-in-string", "nested", "multiline-interp"],
)
def test_a_template_is_computed_and_ends_at_its_own_quote(m: SimpleNamespace, src: str) -> None:
    toks = m.hcl_lex.tokens(src + " z")
    assert toks[0].value is m.hcl_lex.COMPUTED
    assert toks[0].text == src
    assert toks[1].text == "z"


@pytest.mark.parametrize(
    ("src", "message"),
    [
        ('"abc', "unterminated string"),
        ('"ab\nc"', "unterminated string"),
        ('"a\r\nb"', "unterminated string"),
        ('"a\rb"', "unterminated string"),
        (r'"\x"', r"invalid escape '\\\\x'"),
        (r'"\u12"', "invalid escape"),
        (r'"\uD800"', "invalid escape"),
        (r'"\U00110000"', "invalid escape"),
        (r'"\u00g0"', "invalid escape"),
        ('"a\\', "invalid escape"),
        ('"${x', r"unterminated \$\{ or %\{"),
        ('"${ {x }', r"unterminated \$\{ or %\{"),
        ('"${x"', "unterminated string"),
    ],
)
def test_a_bad_string_is_refused(m: SimpleNamespace, src: str, message: str) -> None:
    with pytest.raises(m.hcl_lex.HclError, match=message):
        m.hcl_lex.tokens(src)


def test_templates_nest_only_to_the_depth_cap(m: SimpleNamespace) -> None:
    cap = m.hcl_lex.MAX_DEPTH
    deep = '"${' * cap + "x" + '}"' * cap
    assert value(m, deep) is m.hcl_lex.COMPUTED
    with pytest.raises(m.hcl_lex.HclError, match="templates nested deeper than 64"):
        m.hcl_lex.tokens('"${' * (cap + 1) + "x" + '}"' * (cap + 1))


@pytest.mark.parametrize(
    ("src", "want"),
    [
        ("<<EOT\nFoo\n  Bar\nEOT\n", "Foo\n  Bar\n"),
        ("<<EOT\nEOT\n", ""),
        ("<<EOT\r\nA\r\n  EOT  \r\n", "A\r\n"),
        ("<<EOT\n  NOT EOT\n EOTX\nEOT\n", "  NOT EOT\n EOTX\n"),
        ("<<EOT\n$${x} %%{y}\nEOT\n", "${x} %{y}\n"),
        ("<<-EOT\n    Foo\n      Bar\n\n    Baz\n  EOT\n", "Foo\n  Bar\n\nBaz\n"),
        ("<<-EOT\n\tFoo\n  Bar\n  EOT\n", "Foo\n Bar\n"),
        ("<<-EOT\n   \u2003\u2003Foo\n    Bar\n  EOT\n", "\u2003Foo\nBar\n"),
        ("<<-EOT\n  a\n      \n  b\n  EOT\n", "a\n      \nb\n"),
        ('<<EOT\n"quoted" # not a comment\nEOT\n', '"quoted" # not a comment\n'),
        ("<<my-doc_1\nx\nmy-doc_1\n", "x\n"),
    ],
    ids=["basic", "empty", "crlf-indented-marker", "marker-suffix", "escapes", "flush", "flush-tab",
         "flush-unicode-space", "flush-keeps-blank-line", "no-comments-inside", "marker-chars"],
)  # fmt: skip
def test_heredocs_decode_as_hcl_does(m: SimpleNamespace, src: str, want: str) -> None:
    toks = m.hcl_lex.tokens(src)
    assert toks[0].kind == "HEREDOC"
    assert toks[1].kind in ("NL", "EOF")
    assert toks[0].value == want


def test_a_heredoc_with_a_template_is_computed(m: SimpleNamespace) -> None:
    toks = m.hcl_lex.tokens("<<EOT\na ${b} c\n${\n}\nEOT\nx")
    assert toks[0].value is m.hcl_lex.COMPUTED
    assert [t.text for t in toks[1:]] == ["\n", "x", ""]
    assert m.hcl_lex.Lines("<<EOT\na ${b} c\n${\n}\nEOT\nx")(toks[2].start) == 6


@pytest.mark.parametrize(
    "src",
    [
        "<<EOT\nx\n",
        "<<EOT\nx\nEOT",
        "<<EOT",
        "<< EOT\nx\nEOT",
        "<<EOT x\nEOT",
        "<<\nx",
        "<<-\nx",
        "<<1A\nx\n1A",
        "<<EOT\n${x\nEOT\n",
    ],
    ids=[
        "never-closed",
        "marker-at-eof",
        "no-newline",
        "space",
        "trailing",
        "no-marker",
        "flush-no-marker",
        "digit",
        "open-template",
    ],
)
def test_a_bad_heredoc_is_refused(m: SimpleNamespace, src: str) -> None:
    with pytest.raises(m.hcl_lex.HclError, match=r"heredoc|\$\{"):
        m.hcl_lex.tokens(src)


def test_comments_are_dropped_and_line_comments_keep_their_newline(m: SimpleNamespace) -> None:
    src = "a # x = 1\nb // y = 2\r\nc /* z = 3\n w = 4 */ d\n/**/e#"
    assert kinds(m, src) == [
        ("IDENT", "a"), ("NL", "\n"), ("IDENT", "b"), ("NL", "\r\n"), ("IDENT", "c"), ("IDENT", "d"),
        ("NL", "\n"), ("IDENT", "e"), ("EOF", ""),
    ]  # fmt: skip
    assert m.hcl_lex.Lines(src)(m.hcl_lex.tokens(src)[5].start) == 4
    assert kinds(m, "#\r\n") == [("NL", "\r\n"), ("EOF", "")]
    assert kinds(m, "# a\rb\n") == [("NL", "\n"), ("EOF", "")]


@pytest.mark.parametrize(
    ("src", "message"),
    [
        ("a /* b", r"unterminated /\* comment"),
        ("a\rb", "carriage return not followed by a newline"),
        ("a ; b", "unexpected character ';'"),
        ("a = 'x'", 'unexpected character "\'"'),
        ("a\fb", "unexpected character"),
        ("a\u00a0b", "unexpected character"),
        ("x\ufeff", "unexpected character"),
        ("9" * 4001, "number too long"),
        ("a & b", "unexpected character '&'"),
        ("`x`", "unexpected character '`'"),
    ],
    ids=["comment", "lone-cr", "semicolon", "single-quotes", "form-feed", "nbsp", "inner-bom", "number", "amp", "tick"],
)
def test_anything_else_is_refused_with_its_line(m: SimpleNamespace, src: str, message: str) -> None:
    with pytest.raises(m.hcl_lex.HclError, match=f"^line 1: {message}"):
        m.hcl_lex.tokens(src)


def test_errors_name_the_line_they_are_on(m: SimpleNamespace) -> None:
    with pytest.raises(m.hcl_lex.HclError) as caught:
        m.hcl_lex.tokens('a = 1\nb = 2\nc = "open\n')
    assert caught.value.line == 3
    assert str(caught.value) == "line 3: unterminated string"
    assert isinstance(caught.value, ValueError)


def test_numbers_up_to_the_cap_lex(m: SimpleNamespace) -> None:
    assert kinds(m, "9" * 4000) == [("NUMBER", "9" * 4000), ("EOF", "")]
    assert kinds(m, "1.") == [("NUMBER", "1"), ("PUNCT", "."), ("EOF", "")]


def test_the_size_cap_is_checked_before_lexing(m: SimpleNamespace) -> None:
    with pytest.raises(m.hcl_lex.HclError, match="larger than 1048576 characters"):
        m.hcl_lex.tokens("#" * (m.hcl_lex.MAX_CHARS + 1))
    assert m.hcl_lex.tokens("#" * m.hcl_lex.MAX_CHARS)[-1].kind == "EOF"


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("plain", "plain"),
        ("$${x}", "${x}"),
        ("%%{x}", "%{x}"),
        ("a ${b}", None),
        ("%{ if x }y%{ endif }", None),
        ("", ""),
    ],
)
def test_template_reads_a_json_string(m: SimpleNamespace, text: str, want: str | None) -> None:
    got = m.hcl_lex.template(text)
    assert got == want if want is not None else got is m.hcl_lex.COMPUTED


def test_template_refuses_an_unclosed_interpolation(m: SimpleNamespace) -> None:
    with pytest.raises(m.hcl_lex.HclError, match="unterminated"):
        m.hcl_lex.template("${x")


def test_computed_prints_as_its_name(m: SimpleNamespace) -> None:
    assert repr(m.hcl_lex.COMPUTED) == "COMPUTED"
