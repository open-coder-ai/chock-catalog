"""What the guard reads as a name: framework-bound attributes, wrapping labels, and JSX expressions."""

from __future__ import annotations

import check_a11y_rules as rules
import pytest

GUARD = rules.load_guard()
NAMED_BY_LABEL = ("input", "select", "textarea", "meter", "progress")


def _states(markup: str) -> list[str]:
    return [state for state, _, _ in GUARD.scan(markup)[0].values()]


def _actions(before: str, after: str) -> list[str]:
    return [row["action"] for row in GUARD.evaluate(before, after)]


@pytest.mark.parametrize(
    "spelling",
    [":alt", "v-bind:alt", "[alt]", "[attr.alt]", "th:alt"],
)
def test_a_bound_attribute_is_the_attribute_it_binds(spelling: str) -> None:
    bound = f'<img src="/a.png" {spelling}="logoText">'
    assert _states(bound) == [GUARD.SATISFIED]
    assert _actions('<img src="/a.png" alt="Logo">', bound) == [GUARD.SILENT]
    assert _actions(bound, '<img src="/a.png">') == [GUARD.DENY]


@pytest.mark.parametrize("spelling", [":aria-label", "v-bind:aria-label", "[attr.aria-label]", "th:aria-label"])
def test_a_bound_aria_label_names_a_control(spelling: str) -> None:
    bound = f'<button type="button" {spelling}="closeLabel"></button>'
    assert _states(bound) == [GUARD.SATISFIED]


def test_th_lang_is_the_lang_of_the_page() -> None:
    assert _states('<html th:lang="${#locale.language}">') == [GUARD.SATISFIED]


def test_a_bound_value_is_never_judged_for_quality() -> None:
    assert _actions('<img src="/a.png">', '<img src="/a.png" :alt="x">') == [GUARD.RECORD]
    assert _actions('<img src="/a.png" alt="A real description">', '<img src="/a.png" :alt="img">') == [GUARD.SILENT]


def test_a_literal_attribute_wins_over_a_bound_one_of_the_same_name() -> None:
    assert _states('<img src="/a.png" alt="Logo" :alt="other">') == [GUARD.SATISFIED]


def test_html_for_is_for() -> None:
    markup = '<label htmlFor="email">Email address</label><input type="email" id="email" />'
    assert _states(markup) == [GUARD.SATISFIED]
    assert _actions(markup, '<input type="email" id="email" />') == [GUARD.DENY]


@pytest.mark.parametrize("tag", NAMED_BY_LABEL)
def test_a_wrapping_label_with_text_names_its_control(tag: str) -> None:
    named = f'<label>Email address <{tag} name="x"></{tag}></label>'
    assert _states(named) == [GUARD.SATISFIED]
    assert _actions(named, f'<{tag} name="x"></{tag}>') == [GUARD.DENY]


def test_a_wrapping_label_names_a_control_from_text_after_it() -> None:
    assert _states('<label><input type="checkbox" name="tos"> I accept the terms</label>') == [GUARD.SATISFIED]


def test_a_wrapping_label_with_a_name_bearing_child_names_its_control() -> None:
    assert _states('<label><img src="/i.png" alt="Email"><input name="e"></label>') == [
        GUARD.SATISFIED,
        GUARD.SATISFIED,
    ]


def test_a_wrapping_label_with_no_text_names_nothing() -> None:
    assert _states('<label><input name="e"></label>') == [GUARD.MISSING]


def test_a_control_outside_a_closed_label_is_not_named_by_it() -> None:
    assert _states('<label>Email</label><input name="e">') == [GUARD.MISSING]


def test_text_in_a_label_after_a_closed_one_names_nothing() -> None:
    assert _states('<label>Email <input name="a"></label><input name="b">') == [GUARD.SATISFIED, GUARD.MISSING]


@pytest.mark.parametrize(
    ("tag", "state", "action"),
    [
        ("<img onClick={() => onZoom(photo)} src={photo.url} alt={photo.caption} />", GUARD.SATISFIED, GUARD.DENY),
        ("<img onClick={(e) => { if (a > b) go(e); }} src={u} alt={photo.caption} />", GUARD.SATISFIED, GUARD.DENY),
        ('<img data-x={a > b ? "x>y}" : `}>`} src={u} alt={photo.caption} />', GUARD.SATISFIED, GUARD.DENY),
        ("<img {...(a > b ? one : two)} src={u} alt={photo.caption} />", GUARD.UNEVALUATED, GUARD.SILENT),
    ],
)
def test_a_gt_inside_a_brace_expression_does_not_end_the_tag(tag: str, state: str, action: str) -> None:
    assert _states(tag) == [state]
    assert _actions(tag, tag.replace(" alt={photo.caption}", "")) == [action]


def test_a_gt_in_a_jsx_expression_keeps_the_alt_that_follows_it() -> None:
    tag = "<img onClick={() => onZoom(photo)} src={photo.url} alt={photo.caption} />"
    assert _actions(tag, tag.replace(" alt={photo.caption}", "")) == [GUARD.DENY]


def test_an_unclosed_brace_does_not_swallow_the_rest_of_the_file() -> None:
    markup = '<div class={"a">x</div>\n<img src="/a.png">'
    assert _states(markup) == [GUARD.MISSING]


def test_a_gt_outside_braces_still_ends_the_tag() -> None:
    assert _states('<img src="/a.png" alt="x">{a > b}') == [GUARD.SATISFIED]


def test_a_tag_inside_an_expression_is_read_with_the_tag_around_it() -> None:
    markup = '<Row render={() => <b>x</b>} data-testid="r" />'
    assert _states(markup) == [GUARD.NAMELESS]


def test_a_self_closed_label_wraps_nothing() -> None:
    assert _states('<label /><input name="e">') == [GUARD.MISSING]


def test_a_stray_closing_label_is_ignored() -> None:
    assert _states('</label><input name="e">') == [GUARD.MISSING]
