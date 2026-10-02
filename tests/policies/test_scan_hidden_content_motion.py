"""scan-hidden-content: CSS animations, which hide text only when no keyframe of the file shows it."""

from __future__ import annotations

from policies.hiddenkit import readers

css = readers["css"]
html = readers["markup"]


def hidden_of(doc: str) -> list[tuple[str, str]]:
    return [(t, r) for _, t, r, _, _ in html.collect(doc).hidden]


motion = readers["motion"]


def test_a_keyframe_counts_only_when_it_shows_what_hides() -> None:
    sheet = (
        "@keyframes show { from { opacity: 0 } to { opacity: 1 } } @keyframes keep { to { opacity: 0 } }"
        " @keyframes tint { to { background-color: red } } /* @keyframes ghost { to { opacity: 1 } } */"
        " @-webkit-keyframes unfold { 50% { display: block; font-size: 12px; visibility: visible } }"
    )
    seen = motion.Motion([sheet], "")
    assert seen.shows == {
        "show": {"opacity"},
        "keep": set(),
        "tint": {"background-color"},
        "unfold": {"display", "font-size", "visibility"},
    }
    hide = css.declarations("opacity:0; animation: show 2s forwards")
    assert css.hidden(hide, None, motion=seen) is None
    assert css.hidden(hide, None) == "opacity 0"
    assert css.hidden(css.declarations("display:none; animation: tint 1s"), None, motion=seen) == "display none"
    for style in (
        "opacity:0; animation: keep 1s",
        "opacity:0; animation: ghost 1s",
        "opacity:0; animation: show 1s paused",
        "opacity:0; animation: show 0s",
        "opacity:0; animation: show 1s 99999s",
        "opacity:0; animation-name: show; animation-duration: 0ms",
        "opacity:0; animation-name: show; animation-delay: 10s",
        "opacity:0; animation-name: show; animation-play-state: paused",
        "opacity:0",
    ):
        assert css.hidden(css.declarations(style), None, motion=seen) == "opacity 0", style
    assert css.hidden(css.declarations("display:none; animation: unfold 1s"), None, motion=seen) is None
    assert css.hidden(css.declarations("font-size:0; animation: unfold 1s"), None, motion=seen) is None
    assert motion.Motion(["}} @keyframes x { a { b {"], "").shows == {}


def test_an_unnamed_animation_counts_when_the_file_applies_a_showing_keyframe() -> None:
    sheet = "@keyframes k1 { to { opacity: 1 } }"
    hide = css.declarations("opacity:0; animation: 22s linear infinite")
    assert css.hidden(hide, None, motion=motion.Motion([sheet], "<p style='animation-name:k1'>")) is None
    assert css.hidden(hide, None, motion=motion.Motion([sheet], "")) == "opacity 0"
    doc = "<style>@keyframes show{to{opacity:1}} .l{opacity:0;animation:show 1s}</style><p class=l>hello</p>"
    assert hidden_of(doc) == []
    inline = "<style>@keyframes k1{to{opacity:1}} .l{opacity:0}</style><text class=l style='animation-name:k1'>a</text>"
    assert hidden_of(inline) == [("style", "opacity 0")]
    assert hidden_of(inline.replace("k1'", "k2'")) == [
        ("style", "opacity 0"),
        ("text", "hidden by a style rule (opacity 0)"),
    ]
