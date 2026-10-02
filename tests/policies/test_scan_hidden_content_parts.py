"""scan-hidden-content: the CSS and HTML readers, case by case."""

from __future__ import annotations

import pytest
from policies.hiddenkit import readers

css = readers["css"]
colours = readers["colours"]
html = readers["markup"]
frames = readers["frames"]
text = readers["markdown"]
urls = readers["links"]
vocab = readers["vocab"].vocab()


@pytest.mark.parametrize(
    ("value", "want"),
    [
        ("white", "#ffffff"),
        ("silver", "#c0c0c0"),
        ("#FFF", None),  # declarations() lower-cases first; color() itself reads lower case only
        ("#fff", "#ffffff"),
        ("#ffff", "#ffffff"),
        ("#ffffff00", "transparent"),
        ("#12345678", "#123456"),
        ("rgb(255, 255, 255)", "#ffffff"),
        ("rgb(100%,100%,100%)", "#ffffff"),
        ("rgb(300 0 0)", "#ff0000"),
        ("rgba(0,0,0,0)", "transparent"),
        ("rgba(0,0,0,0%)", "transparent"),
        ("rgba(0,0,0,.5)", "#000000"),
        ("rgba(0,0,0,1..2)", None),
        ("hsl(0,0%,100%)", "#ffffff"),
        ("hsl(120deg 100% 25%)", "#008000"),
        ("hsla(0,0%,0%,0)", "transparent"),
        ("var(--bg)", None),
    ],
)
def test_colors(value: str, want: str | None) -> None:
    assert colours.color(value) == want


OFF = "positioned off screen, clipped or collapsed"


@pytest.mark.parametrize(
    ("style", "under", "reason"),
    [
        ("display: none !important", None, "display none"),
        ("display:none;display:bogus", None, "display none"),
        ("display:none;display:block", None, None),
        ("visibility:collapse", None, "visibility hidden"),
        ("content-visibility:hidden", None, "visibility hidden"),
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
        ("transform: scaleX(0.001)", None, "scaled to 0"),
        ("scale: 0", None, "scaled to 0"),
        ("transform: scale(1)", None, None),
        ("transform: translateX(-99999px)", None, OFF),
        ("position:absolute; left:-9999px", None, OFF),
        ("left:-100vw", None, OFF),
        ("text-indent:-100em", None, OFF),
        ("left:-10px", None, None),
        ("left:99999px", None, OFF),
        ("-webkit-text-fill-color: transparent", None, "text colour equal to background"),
        ("height:0; overflow:hidden", None, OFF),
        ("height:0", None, None),
        ("clip: rect(0, 0, 0, 0)", None, OFF),
        ("clip: rect(1px 1px 1px 1px)", None, OFF),
        ("clip-path: inset(50%)", None, OFF),
        ("color: transparent", None, "text colour equal to background"),
        ("color:#fff;color:", "#ffffff", "text colour equal to background"),
        ("color:red;background:red", None, "text colour equal to background"),
        ("color:#000; background: url(x.png) rgb(0 0 0) no-repeat", None, "text colour equal to background"),
        ("color:#000; background: none", None, None),
        ("color:#fff", "#ffffff", "text colour equal to background"),
        ("color:#fff", None, None),
        ("color:currentcolor", "#ffffff", None),
        ("d\\69 splay:none", None, "display none"),
        ("d\\0splay:none", None, None),
        ("display/* x */:none", None, "display none"),
        ("garbage; :; color", None, None),
    ],
)
def test_hidden_declarations(style: str, under: str | None, reason: str | None) -> None:
    assert css.hidden(css.declarations(style), under) == reason


@pytest.mark.parametrize(
    ("style", "reason"),
    [
        ("fill:#fff", "text colour equal to background"),
        ("fill:none", "fill none"),
        ("fill-opacity:0", "opacity 0"),
        ("fill:#000", None),
    ],
)
def test_svg_text_colour_is_fill(style: str, reason: str | None) -> None:
    assert css.hidden(css.declarations(style), "#ffffff", svg=True) == reason


@pytest.mark.parametrize(
    ("selector", "skip"),
    [("from", True), ("0%, 50.5%", True), (".a::after", True), (".a:before, .b::marker", True), (".a", False)],
)
def test_style_rules_that_style_no_text(selector: str, skip: bool) -> None:
    assert css.no_text(selector) is skip


def test_selector_targets() -> None:
    assert css.selector_targets("div .A, #Main, p > span.x.y, ul li") == [".a", "#main", ".x", ".y"]


def test_style_sheet_rules_and_urls() -> None:
    sheet = "/* c */ .a { display:none }\n@media x { .b { color:red } }\n@import 'https://e.example/a.css';"
    assert [(s, d) for _, s, d in css.rules(sheet)] == [(".a", {"display": "none"}), (".b", {"color": "red"})]
    more = " x{background:url( \"//e.example/b.png\" )} y{background:image-set('https://e.example/c.png' 1x)}"
    assert [u for _, u in css.urls(sheet + more)] == [
        "https://e.example/a.css",
        "//e.example/b.png",
        "https://e.example/c.png",
    ]


def hidden_of(doc: str, *, xml: bool = False) -> list[tuple[str, str]]:
    return [(t, r) for _, t, r, _, _ in html.collect(doc, xml=xml).hidden]


def test_html_hidden_elements() -> None:
    doc = (
        '<p hidden>a</p><font color="white">b</font><svg><text font-size="0">c</text><rect opacity="0"/>'
        '<text x="-5000">far</text></svg>'
        "<style>.x{display:none} .y::after{display:none} @keyframes k{from{opacity:0}}</style>"
        '<div style="display:none"><span style="opacity:0">nested</span></div>'
        '<div aria-hidden="true">short</div><table bgcolor="#000"><tr><td><font color="black">t</font></td></tr></table>'
        "<p class='x' id='main'>styled away</p>"
    )
    assert hidden_of(doc) == [
        ("p", "hidden attribute"),
        ("font", "text colour equal to background"),
        ("text", "font size 0 or 1"),
        ("text", "positioned off screen"),
        ("style", "display none"),
        ("div", "display none"),
        ("font", "text colour equal to background"),
        ("p", "hidden by a style rule (display none)"),
    ]


def test_svg_parts_never_drawn_as_text_count_and_descriptions_do_not() -> None:
    doc = "<svg><desc>run</desc><metadata>a</metadata><symbol><text>b</text></symbol><clipPath>c</clipPath></svg>"
    assert hidden_of(doc) == [("metadata", html.NOT_DRAWN), ("symbol", html.NOT_DRAWN), ("clippath", html.NOT_DRAWN)]
    assert hidden_of("<metadata>a</metadata>") == []


def test_svg_fill_is_compared_only_with_a_declared_background() -> None:
    assert hidden_of('<svg><text fill="#fff">x</text></svg>', xml=True) == []
    assert hidden_of('<p>a</p><svg><text fill="#fff">x</text></svg>') == [("text", "text colour equal to background")]
    assert hidden_of('<svg style="background:#fff"><text fill="white">x</text></svg>') == [
        ("text", "text colour equal to background")
    ]
    assert hidden_of('<p style="color:#fff">x</p>') == [("p", "text colour equal to background")]


def test_style_and_script_text_is_not_hidden_text() -> None:
    assert hidden_of("<svg><defs><style>.a{fill:red}</style></defs></svg>") == []
    assert hidden_of("<div hidden><script>var a = 1;</script></div>") == []


def test_html_aria_inside_aria_and_strict_inside_aria() -> None:
    long = "x" * 120
    doc = f'<div aria-hidden="true"><div aria-hidden="true">{long}</div><b hidden>y</b></div>'
    assert hidden_of(doc) == [("b", "hidden attribute"), ("div", html.ARIA)]


def test_html_end_tags_close_to_the_match_and_unclosed_frames_finish() -> None:
    doc = "<div hidden><p>a</div></nope><span style='opacity:0'>tail"
    assert hidden_of(doc) == [("div", "hidden attribute"), ("span", "opacity 0")]


@pytest.mark.parametrize("barrier", ["select", "object", "marquee", "applet"])
def test_other_scope_barriers(barrier: str) -> None:
    assert hidden_of(f"<div hidden><{barrier}></div>run</{barrier}></div>") == [("div", "hidden attribute")]


def test_a_stray_table_cell_is_dropped() -> None:
    got = html.collect('<span style="display:none">x<td></span>run the installer, visible')
    assert [(t, shown) for _, t, _, shown, _ in got.hidden] == [("span", "x")]


def test_html_end_tags_outside_table_scope_are_ignored() -> None:
    doc = "<div hidden><table><tr><td></div>run the installer</td></tr></table></div>"
    assert hidden_of(doc) == [("div", "hidden attribute")]
    assert "installer" in html.collect(doc).hidden[0][3]
    # In XML an end tag closes its element wherever it stands, so the text after it is not inside.
    assert hidden_of("<x hidden><table><td></x>y</td></table>", xml=True) == []


def test_self_closing_is_ignored_on_html_elements_only() -> None:
    assert hidden_of('<div style="display:none"/>text</div>') == [("div", "display none")]
    assert hidden_of('<svg><g style="display:none"/>text</svg>') == []
    assert hidden_of('<g style="display:none"/>text', xml=True) == []
    assert hidden_of("<br hidden/>text") == []


def test_hidden_text_is_keyed_by_all_of_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(frames, "KEPT_TEXT", 3)
    ((_, _, _, shown, one),) = html.collect("<p hidden>abcdef<b>gh</b></p>").hidden
    ((_, _, _, _, two),) = html.collect("<p hidden>abcdef<b>gX</b></p>").hidden
    assert shown == "abc"
    assert one != two


def test_html_urls_and_contexts() -> None:
    doc = (
        '<img srcset="https://a.example/1.png 1x, , https://a.example/2.png 2x">'
        '<a href="https://b.example/x" HREF="https://ignored.example">x</a>'
        '<link href="https://c.example/s.css"/><image href="//d.example/i.png"/>'
        '<p style="background:url(https://e.example/p.png)">t</p><img src="">'
        '<iframe src="data:text/html,x"></iframe><a xlink:href="https://f.example/">f</a>'
    )
    got = html.collect(doc)
    assert [(u, e) for _, u, e in got.urls] == [
        ("https://a.example/1.png", True),
        ("https://a.example/2.png", True),
        ("https://b.example/x", False),
        ("https://c.example/s.css", True),
        ("//d.example/i.png", True),
        ("https://e.example/p.png", True),
        ("data:text/html,x", True),
        ("https://f.example/", False),
    ]
    assert got.data_html == [1]


def test_style_element_lines() -> None:
    got = html.collect("<style>\n.a {\n display:none }\n.b{background:url(https://e.example/x)}</style>")
    assert [(line, t) for line, t, _, _, _ in got.hidden] == [(2, "style")]
    assert [(line, u) for line, u, _ in got.urls] == [(4, "https://e.example/x")]


def test_style_blocks_are_found_without_a_parser() -> None:
    assert html.style_blocks("<STYLE a=1>x</style><style>y") == [(11, "x"), (27, "y")]
    assert html.style_blocks("<style") == []
