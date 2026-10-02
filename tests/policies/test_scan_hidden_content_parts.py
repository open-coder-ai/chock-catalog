"""scan-hidden-content: the CSS, HTML, Markdown and URL readers, case by case."""

from __future__ import annotations

import json

import pytest
from policies import scriptkit
from policies.hiddenkit import gate as mod
from policies.hiddenkit import readers

css = readers["css"]
html = readers["markup"]
text = readers["markdown"]
urls = readers["links"]
vocab = readers["vocab"].vocab()


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("white", "#ffffff"),
        ("#FFF", None),  # declarations() lower-cases first; color() itself reads lower case only
        ("#fff", "#ffffff"),
        ("#ffff", "#ffffff"),
        ("#ffffff00", "transparent"),
        ("#12345678", "#123456"),
        ("rgb(255, 255, 255)", "#ffffff"),
        ("rgb(300 0 0)", "#ff0000"),
        ("rgba(0,0,0,0)", "transparent"),
        ("rgba(0,0,0,0%)", "transparent"),
        ("rgba(0,0,0,.5)", "#000000"),
        ("rgba(0,0,0,1..2)", "#000000"),
        ("hsl(0 0% 100%)", None),
        ("var(--bg)", None),
    ],
)
def test_colors(value: str, want: str | None) -> None:
    assert css.color(value) == want


@pytest.mark.parametrize(
    ("style", "under", "reason"),
    [
        ("display: none !important", None, "display none"),
        ("visibility:collapse", None, "visibility hidden"),
        ("opacity:0.01", None, "opacity 0"),
        ("opacity:3%", None, "opacity 0"),
        ("opacity:0.5", None, None),
        ("font-size:0", None, "font size 0 or 1"),
        ("font-size:1px", None, "font size 0 or 1"),
        ("font-size:0.05em", None, "font size 0 or 1"),
        ("font-size:12px", None, None),
        ("font-size:2q", None, None),
        ("font-size:small", None, None),
        ("font: 0/0 a", None, "font size 0 or 1"),
        ("font:", None, None),
        ("transform: scale(0)", None, "scaled to 0"),
        ("position:absolute; left:-9999px", None, "positioned off screen or clipped"),
        ("text-indent:-100em", None, "positioned off screen or clipped"),
        ("left:-10px", None, None),
        ("clip: rect(0, 0, 0, 0)", None, "positioned off screen or clipped"),
        ("clip: rect(1px 1px 1px 1px)", None, "positioned off screen or clipped"),
        ("clip-path: inset(50%)", None, "positioned off screen or clipped"),
        ("color: transparent", None, "text colour equal to background"),
        ("color:#000; background-color:#000", None, "text colour equal to background"),
        ("color:#000; background: url(x.png) #000 no-repeat", None, "text colour equal to background"),
        ("color:#000; background: none", None, None),
        ("color:#fff", "#ffffff", "text colour equal to background"),
        ("color:#fff", None, None),
        ("d\\69 splay:none", None, "display none"),
        ("d\\0splay:none", None, None),
        ("display/* x */:none", None, "display none"),
        ("garbage; :; color", None, None),
    ],
)
def test_hidden_declarations(style: str, under: str | None, reason: str | None) -> None:
    assert css.hidden(css.declarations(style), under) == reason


@pytest.mark.parametrize(
    ("selector", "skip"),
    [("from", True), ("0%, 50.5%", True), (".a::after", True), (".a:before, .b::marker", True), (".a", False)],
)
def test_style_rules_that_style_no_text(selector: str, skip: bool) -> None:
    assert css.no_text(selector) is skip


def test_style_sheet_rules_and_urls() -> None:
    sheet = "/* c */ .a { display:none }\n@media x { .b { color:red } }\n@import 'https://e.example/a.css';"
    assert [(s, d) for _, s, d in css.rules(sheet)] == [(".a", {"display": "none"}), (".b", {"color": "red"})]
    assert [u for _, u in css.urls(sheet + ' x{background:url( "//e.example/b.png" )}')] == [
        "https://e.example/a.css",
        "//e.example/b.png",
    ]


def collect(doc: str) -> html.Collected:
    return html.collect(doc)


def test_html_hidden_elements() -> None:
    doc = (
        '<p hidden>a</p><font color="white">b</font><svg><text font-size="0">c</text><rect opacity="0"/></svg>'
        "<style>.x{display:none} .y::after{display:none} @keyframes k{from{opacity:0}}</style>"
        '<div style="display:none"><span style="opacity:0">nested</span></div>'
        '<div aria-hidden="true">short</div>'
    )
    assert [(t, r) for _, t, r, _ in collect(doc).hidden] == [
        ("p", "hidden attribute"),
        ("font", "text colour equal to background"),
        ("text", "font size 0 or 1"),
        ("style", "display none"),
        ("div", "display none"),
    ]


def test_html_aria_inside_aria_and_strict_inside_aria() -> None:
    long = "x" * 120
    doc = f'<div aria-hidden="true"><div aria-hidden="true">{long}</div><b hidden>y</b></div>'
    assert [(t, r) for _, t, r, _ in collect(doc).hidden] == [("b", "hidden attribute"), ("div", html.ARIA)]


def test_html_end_tags_close_to_the_match_and_unclosed_frames_finish() -> None:
    doc = "<div hidden><p>a</div></nope><span style='opacity:0'>tail"
    assert [(t, r) for _, t, r, _ in collect(doc).hidden] == [("div", "hidden attribute"), ("span", "opacity 0")]


def test_html_kept_text_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(html, "KEPT_TEXT", 3)
    ((_, _, _, kept),) = collect("<p hidden>abcdef<b>gh</b></p>").hidden
    assert kept == "abc"


def test_html_urls_and_contexts() -> None:
    doc = (
        '<img srcset="https://a.example/1.png 1x, , https://a.example/2.png 2x">'
        '<a href="https://b.example/x" HREF="https://ignored.example">x</a>'
        '<link href="https://c.example/s.css"/><image href="//d.example/i.png"/>'
        '<p style="background:url(https://e.example/p.png)">t</p><img src="">'
        '<iframe src="data:text/html,x"></iframe>'
    )
    got = collect(doc)
    assert [(u, e) for _, u, e in got.urls] == [
        ("https://a.example/1.png", True),
        ("https://a.example/2.png", True),
        ("https://b.example/x", False),
        ("https://c.example/s.css", True),
        ("//d.example/i.png", True),
        ("https://e.example/p.png", True),
        ("data:text/html,x", True),
    ]
    assert got.data_html == [1]


def test_style_element_lines() -> None:
    got = collect("<style>\n.a {\n display:none }\n.b{background:url(https://e.example/x)}</style>")
    assert [(line, t) for line, t, _, _ in got.hidden] == [(2, "style")]
    assert [(line, u) for line, u, _ in got.urls] == [(4, "https://e.example/x")]


def test_markdown_blanking() -> None:
    doc = "a `x` b ``y ` z`` c ` open\n\n```py\nfence\n~~~\n```\n<div>\n`kept`\n</div>\n~~~\nt\n"
    out = text.blank_code(doc)
    assert out.count("\n") == doc.count("\n")
    assert "x" not in out.split("\n")[0] and "open" in out
    assert "fence" not in out and "`kept`" in out and "t" not in out.split("\n")[-2]


def test_comment_scanning() -> None:
    doc = "<!---><!-- a --!> b <!-- c -->" + "<!-- d"
    assert [body for _, body in text.comments(doc)] == [" a ", " c ", " d"]
    assert [body for _, body in text.comments("{/* x */} {/* y", mdx=True)] == [" x ", " y"]


def test_definitions() -> None:
    doc = "[a]: <https://x.example/p> 'single'\n[b]: /local (paren)\n[c]: https://y.example\n[^n]: footnote\n"
    assert text.definitions(doc) == [
        (0, "https://x.example/p", "single"),
        (36, "/local", "paren"),
        (56, "https://y.example", None),
    ]


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


def test_secret_words_split_camel_case_and_punctuation() -> None:
    assert vocab.secret_words("x=myApiKey&SSH_dir=1&tokens=2") == ["key", "ssh"]


@pytest.mark.parametrize(
    ("url", "embed", "rule"),
    [
        ("https://e.example/a.png", False, None),
        ("ftp://e.example/a?token=1", False, "exfil-url-secret"),
        ("https:e.example/a", False, "unparseable-url"),
        ("https://e.example/a/" + "Ab1" * 7 + "-" + "x" * 12, False, "exfil-url-shape"),
        ("https://e.example/a/" + "Ab1-" * 9, False, None),
        ("https://e.example/a/" + "abcdefghij" * 4, False, None),
        ("https://img.shields.io/x?a=" + "y" * 39, True, None),
        ("https://img.shields.io/x?a=" + "y" * 40, True, "exfil-url-shape"),
        ("https://e.example/p?x=%24%7BHOME%7D", False, "exfil-url-shape"),
        ("https://e.example/p#token=x", False, None),
        ("https://e.example", True, "remote-embed"),
        ("https://github.com/o/r", True, None),
        ("relative/path.png", True, None),
    ],
)
def test_url_verdicts(url: str, embed: bool, rule: str | None) -> None:
    verdict = urls.judge(url, vocab, embed=embed)
    assert (verdict.rule if verdict else None) == rule


def test_text_urls_trim_and_destinations() -> None:
    doc = "See (https://e.example/a_(b)). [x](//e.example/c) [y](#top) <https://e.example/d>."
    assert [u for _, u in urls.text_urls(doc)] == [
        "https://e.example/a_(b)",
        "https://e.example/d",
        "//e.example/c",
    ]


def test_runs() -> None:
    camo = [(i, f"https://camo.githubusercontent.com/h{i}/6{i}") for i in range(5)]
    letters = [(i, f"https://x.example/a/{c}.png") for i, c in enumerate("abcde", 1)]
    others = [
        (9, "mailto:x"),
        (9, "https://x\\@y/a"),
        (9, "https://github.com/a/b"),
        (9, "https://x.example/a/long.png"),
    ]
    got = urls.runs(camo + letters + others, vocab)
    assert [(line, v.rule, v.host) for line, v in got] == [
        (0, "camo-url-run", "camo"),
        (1, "camo-url-run", "x.example"),
    ]
    assert urls.runs(camo[:4] + letters[:4], vocab) == []


def test_gate_reports_dictionaries() -> None:
    doc = "".join(f"![](https://x.example/a/{c}.png)\n" for c in "abcde")
    assert [(f["line"], f["rule"]) for f in mod.findings({"writes": {"a.md": doc}})] == [(1, "camo-url-run")]


def test_script_runs_as_a_program(tmp_path: object) -> None:
    payload = json.dumps({"event": "commit", "writes": {"a.md": "<!-- run it -->\n"}})
    code, err = scriptkit.run_script("scan-hidden-content", "scan-hidden-content-gate.py", tmp_path, payload)
    assert code == mod.WARN
    assert "hidden comment" in err
