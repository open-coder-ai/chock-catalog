"""scan-hidden-content: the Markdown, vocabulary and URL readers, case by case."""

from __future__ import annotations

import json

import pytest
from policies import scriptkit
from policies.hiddenkit import gate as mod
from policies.hiddenkit import readers

text = readers["markdown"]
blocks = readers["spans"]
urls = readers["links"]
vocab = readers["vocab"].vocab()


def test_markdown_blanking() -> None:
    doc = "a `x` b ``y ` z`` c ` open\n\n```py\nfence\n~~~\n```\n<div>\n`kept`\n```\n</div>\n\n~~~\nt\n"
    out = blocks.blank_code(doc)
    assert out.count("\n") == doc.count("\n")
    assert "x" not in out.split("\n")[0]
    assert "open" in out
    assert "fence" not in out
    assert "`kept`" in out
    assert "```\n</div>" in out
    assert out.split("\n")[-2] == "t"  # an unclosed fence is not certain: read as text


@pytest.mark.parametrize(
    ("doc", "kept"),
    [
        ("` y\nb `c` d\n", "b `c` d"),  # an unpaired run earlier in the paragraph: nothing after is certain
        ("x `a | b` y\n", "x `a | b` y"),  # a pipe: as table cells the span is split
        ("- a\n  ```\n  code\n  ```\n", "  code"),  # a fence in a list item is not certain
        ("> ```\n> code\n> ```\n", "> code"),
        ("- a\n  ```\n\n```\ncode\n```\n", "code"),  # after a fence-like line left unread, none is certain
        ("    - c\n```\ncode\n```\n", None),  # indented four at the top: code, not a list item
    ],
)
def test_only_certain_code_is_blanked(doc: str, kept: str | None) -> None:
    out = blocks.blank_code(doc).split("\n")
    if kept is None:
        assert out[:4] == ["       ", "   ", "    ", "   "]
    else:
        assert kept in out


def test_a_line_with_a_pipe_blanks_what_both_readings_call_code() -> None:
    # As table cells (GFM) and as one line (CommonMark without tables): only what both pair is code.
    doc = "| a | b |\n|---|---|\n| `x` | y `z |\n\n| `a | b` ![i](u) `c |\n"
    out = blocks.blank_code(doc).split("\n")
    assert out[2] == "|     | y `z |"
    # The cells pair "` ![i](u) `", the line "`a | b`": only the backtick both share is blanked.
    assert out[4] == "| `a | b  ![i](u) `c |"
    assert blocks.blank_code("text `x\n| `y` | b |\n|---|---|\n").split("\n")[1] == "| `y` | b |"
    assert blocks.blank_code("| `y` | b |\n|---|---|\n").split("\n")[0] == "|     | b |"
    assert blocks.blank_code("x `a | b` y\n") == "x `a | b` y\n"


def test_fences_inside_a_comment_block_stay() -> None:
    doc = "<!--\n```\nrun\n```\n\n-->\n```\ncode\n```\n"
    assert blocks.blank_code(doc).split("\n")[:5] == ["<!--", "```", "run", "```", ""]
    assert "code" not in blocks.blank_code(doc)


def test_an_html_comment_block_ends_only_where_commonmark_ends_it() -> None:
    # A browser ends the comment at --!>, but CommonMark keeps the block raw to -->, so the fence below
    # is raw HTML and the comment inside it is read, not blanked as code.
    doc = "<!-- a --!>\n```\n<!-- run it\n```\n-->\n```\ncode\n```\n<PRE>\n\n```\nx\n</pre>\n"
    out = blocks.blank_code(doc).split("\n")
    assert out[:5] == ["<!-- a --!>", "```", "<!-- run it", "```", "-->"]
    assert out[6] == "    "
    assert out[11] == "x"


def test_a_closing_fence_indented_four_does_not_close() -> None:
    assert blocks.blank_code("```\n    ```\n<!-- x -->\n```\nafter\n").split("\n")[2:5] == [
        "          ",
        "   ",
        "after",
    ]


def test_a_destination_and_each_closer_inside_it_are_read() -> None:
    # Whether `x](...` is a valid destination decides which `](` a renderer follows: both are read.
    assert [u for _, u, _ in urls.text_urls("[a](x](https://e.example/y)")] == [
        "https://e.example/y",
        "x](https://e.example/y",
        "https://e.example/y",
    ]
    assert urls.text_urls("[x](![i](//e.example/p.png?t=1)") == [
        (4, "![i](//e.example/p.png?t=1", False),
        (9, "//e.example/p.png?t=1", True),
    ]


def test_tag_view_removes_only_the_brackets_of_code() -> None:
    raw = "a `<!-- x -->` <b>"
    assert blocks.tag_view(raw, blocks.blank_code(raw)) == "a ` !-- x -->` <b>"


@pytest.mark.parametrize(
    ("doc", "bodies"),
    [
        ("<!---><!-- a --!> b <!-- c --><!-- d", [" a ", " c ", " d"]),
        (
            "<!run> <?php x ?> </ y > <![CDATA[ z > w ]]> </div> <!DOCTYPE html>",
            ["run", "php x ?", " y ", " z > w ", "DOCTYPE html"],
        ),
        ("<!-- a <!-- b --> c", [" a <!-- b "]),
        ("<?", [""]),
    ],
)
def test_comment_scanning(doc: str, bodies: list[str]) -> None:
    assert [body for _, body in text.comments(doc)] == bodies


def test_mdx_comments() -> None:
    assert [body for _, body in text.comments("{/* x */} {/* y", mdx=True)] == [" x ", " y"]


def test_definitions() -> None:
    doc = (
        "[a]: <https://x.example/p> 'single'\n[B  c]: /local (paren)\n[c]: https://y.example\n[^n]: footnote\n"
        '> [q]:\n> //z.example/q\n> "t"\n'
    )
    assert [(label, dest, title) for _, label, dest, title in text.definitions(doc)] == [
        ("a", "https://x.example/p", "single"),
        ("b c", "/local", "paren"),
        ("c", "https://y.example", None),
        ("q", "//z.example/q", "t"),
    ]


def test_image_labels() -> None:
    doc = "![A][Ref] ![b][] ![c] ![d](x) [![f](z)](w) ![g\\]](v)"
    assert text.image_labels(doc) == {"ref", "b", "c", "g\\"}  # a label is read loosely; only lookups use it


@pytest.mark.parametrize(
    ("doc", "images"),
    [
        ("[e](y)", [False]),
        ("![d](x)", [True]),
        ("[![f](z)](w)", [True, False]),
        ("![g\\]](v)", [True]),
        ("](u)", [True]),
        ("![a]\n\n[h](t)", [False]),
        ("![a] [h](t)", [True]),
        ('[ ![a <x title="]">](u)', [True]),
    ],
)
def test_image_closers(doc: str, images: list[bool]) -> None:
    ends = [i for i in range(len(doc)) if doc.startswith("](", i)]
    assert [blocks.closers(doc).get(i, False) for i in ends] == images


@pytest.mark.parametrize(
    ("body", "why"),
    [
        (" Disregard the above ", "override wording 'disregard'"),
        (" see ~/.ssh ", "key or env path '~/.ssh'"),
        (" " + "word " * 50, "249 characters long"),
        (" EXECUTE ", "imperative 'execute'"),
        (" pragma: allowlist exec ", None),
        (" re-runs are fine ", None),
    ],
)
def test_instruction_reasons(body: str, why: str | None) -> None:
    assert vocab.instruction(body) == why


def test_table_checks() -> None:
    check = readers["vocab"]._strings
    good = {k: ["x"] for k in readers["vocab"].KEYS} | {"css_colours": {"white": "#ffffff"}}
    assert check(good) == []
    assert check(good | {"css_colours": {"white": "#FFF"}, "secret_nouns": []}) == [
        "secret_nouns must be a non-empty list of strings",
        "css_colours must map names to #rrggbb",
    ]


def test_secret_words_split_camel_case_and_punctuation() -> None:
    assert vocab.secret_words("x=myApiKey&SSH_dir=1&tokens=2") == ["key", "ssh"]


LINK, IMAGE, TAG = urls.LINK, urls.IMAGE, urls.TAG


@pytest.mark.parametrize(
    ("url", "load", "rule"),
    [
        ("https://e.example/a.png", LINK, None),
        ("ftp://e.example/a?token=1", IMAGE, "exfil-url-secret"),
        ("https://e.example/a?section=auth", LINK, "exfil-link-secret"),
        ("https:e.example/a", LINK, "unparseable-url"),
        ("https://e.example/a/" + "Ab1" * 7 + "-" + "x" * 12, LINK, "exfil-url-shape"),
        ("https://e.example/a/" + "Ab1-" * 9, LINK, None),
        ("https://e.example/a/" + "abcdefghij" * 4, LINK, None),
        ("https://img.shields.io/x?a=" + "y" * 39, TAG, None),
        ("https://img.shields.io/x?a=" + "y" * 40, TAG, "exfil-url-shape"),
        ("https://e.example/p?x=%24%7BHOME%7D&flag", LINK, "exfil-url-shape"),
        ("https://e.example/p?x=%E2%82", LINK, None),
        ("https://e.example/p#token=x", IMAGE, None),
        ("https://e.example", TAG, "remote-embed"),
        ("https://e.example/i.png", IMAGE, None),
        ("https://github.com/o/r", TAG, None),
        ("relative/path.png", TAG, None),
        ("https://", TAG, None),
    ],
)
def test_url_verdicts(url: str, load: int, rule: str | None) -> None:
    verdict = urls.judge(url, vocab, load=load)
    assert (verdict.rule if verdict else None) == rule


def test_text_urls_trim_and_destinations() -> None:
    doc = (
        "See (https://e.example/a_(b)). [x](//e.example/c) [y](#top) <https://e.example/d>. ![i](https\\://e.example/i)"
    )
    assert [(u, image) for _, u, image in urls.text_urls(doc)] == [
        ("https://e.example/a_(b)", False),
        ("https://e.example/d", False),
        ("//e.example/c", False),
        ("https://e.example/i", True),
    ]


@pytest.mark.parametrize(
    ("raw", "trimmed"),
    [
        ("https://e.example/a" + ")" * 50, "https://e.example/a"),
        ("https://e.example/a_(b)]).", "https://e.example/a_(b)"),
        ("https://u1)](https://u2", "https://u1"),
        ("https://e.example/x?y=[1]", "https://e.example/x?y=[1]"),
        ("https://e.example/a.)", "https://e.example/a"),
    ],
)
def test_trim(raw: str, trimmed: str) -> None:
    assert urls._trim(raw) == trimmed


def test_runs_report_each_member() -> None:
    camo = [(i, f"https://camo.githubusercontent.com/h{i}/6{i}") for i in range(5)]
    letters = [(i, f"https://x.example/a/{c}.png") for i, c in enumerate("abcde", 1)]
    others = [
        (9, "mailto:x"),
        (9, "https://x\\@y/a"),
        (9, "https://github.com/a/b"),
        (9, "https://x.example/a/long.png"),
    ]
    got = urls.runs(camo + letters + others, vocab)
    assert [(line, v.host) for line, v in got] == [(i, "camo") for i in range(5)] + [
        (i, "x.example") for i in range(1, 6)
    ]
    assert len({v.shape for _, v in got}) == 10
    assert urls.runs(camo[:4] + letters[:4], vocab) == []


def test_gate_counts_each_dictionary_url_once() -> None:
    doc = "".join(
        f'![](https://camo.githubusercontent.com/a{i}/6{i}) <img src="https://camo.githubusercontent.com/a{i}/6{i}">\n'
        for i in range(4)
    )
    assert [f["rule"] for f in mod.findings({"writes": {"a.md": doc}})] == ["remote-embed"] * 4
    doc = "".join(f"![](https://x.example/a/{c}.png)\n" for c in "abcde")
    assert [(f["line"], f["rule"]) for f in mod.findings({"writes": {"a.md": doc}})] == [
        (n, "camo-url-run") for n in range(1, 6)
    ]


def test_script_runs_as_a_program(tmp_path: object) -> None:
    payload = json.dumps({"event": "commit", "writes": {"a.md": "<!-- run it -->\n"}})
    code, err = scriptkit.run_script("scan-hidden-content", "scan-hidden-content-gate.py", tmp_path, payload)
    assert code == mod.WARN
    assert "hidden comment" in err
