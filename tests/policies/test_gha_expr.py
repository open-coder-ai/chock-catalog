"""ci-github-actions-security: how expressions are found and which contexts count as attacker-written."""

from __future__ import annotations

import pytest
from policies.ghakit import expr


@pytest.mark.parametrize(
    ("text", "bodies"),
    [
        ("echo ${{ a }} and ${{b}}", [" a ", "b"]),
        ("${{ format('}}', x) }}", [" format('}}', x) "]),
        ("${{ 'it''s }}' }}", [" 'it''s }}' "]),
        ("${{ 'open", [" 'open"]),
        ("${{ a", [" a"]),
        ("no expression", []),
    ],
)
def test_expressions_end_at_the_first_close_outside_a_string(text: str, bodies: list[str]) -> None:
    assert expr.expressions(text) == bodies


@pytest.mark.parametrize(
    ("body", "paths"),
    [
        ("github.event.issue.title", [("github", "event", "issue", "title")]),
        ("GITHUB.Event.Issue.TITLE", [("github", "event", "issue", "title")]),
        ("github.event['issue'][\"x\"]", [("github", "event", "issue", "?"), ("x",)]),
        ("github['event']['pull_request']['title']", [("github", "event", "pull_request", "title")]),
        ("github.event.commits[0].message", [("github", "event", "commits", "*", "message")]),
        ("github.event.commits.*.message", [("github", "event", "commits", "*", "message")]),
        ("github.event.commits[*].message", [("github", "event", "commits", "*", "message")]),
        ("secrets[format('{0}', inputs.n)]", [("secrets", "?"), ("inputs", "n")]),
        ("toJSON(github.event)", [("github", "event")]),
        ("true && null || false", []),
        ("x.", [("x",)]),
        ("x[", [("x", "?")]),
        ("a [ 'b' ] .c", [("a", "b", "c")]),
        ("x[1", [("x", "?")]),
    ],
)
def test_context_paths(body: str, paths: list[tuple[str, ...]]) -> None:
    assert expr.contexts(body) == paths


@pytest.mark.parametrize(
    "path",
    [
        ("github",),
        ("github", "?"),
        ("github", "head_ref"),
        ("github", "event"),
        ("github", "event", "?"),
        ("github", "event", "issue", "title"),
        ("github", "event", "pull_request", "body"),
        ("github", "event", "comment", "body"),
        ("github", "event", "pull_request", "head", "ref"),
        ("github", "event", "pull_request", "head", "label"),
        ("github", "event", "pull_request", "head", "repo", "default_branch"),
        ("github", "event", "head_commit", "message"),
        ("github", "event", "head_commit", "author", "name"),
        ("github", "event", "commits", "*", "message"),
        ("github", "event", "commits"),
        ("github", "event", "workflow_run", "head_branch"),
        ("github", "event", "inputs", "number"),
        ("github", "event", "client_payload", "id"),
        ("github", "event", "label", "name"),
        ("github", "event", "release", "tag_name"),
        ("github", "event", "pages", "*", "page_name"),
        ("github", "event", "*"),
        ("inputs", "title"),
        ("env", "title"),
        ("env",),
        ("env", "?"),
        ("matrix", "title"),
        ("matrix",),
        ("matrix", "?"),
    ],
)
def test_untrusted_contexts(path: tuple[str, ...]) -> None:
    taint = frozenset({"env.title", "matrix.title"})
    assert expr.untrusted(path, taint)


@pytest.mark.parametrize(
    "path",
    [
        ("github", "sha"),
        ("github", "ref_name"),
        ("github", "base_ref"),
        ("github", "event", "ref"),
        ("github", "event", "number"),
        ("github", "event", "pull_request", "number"),
        ("github", "event", "pull_request", "head", "sha"),
        ("github", "event", "pull_request", "base", "ref"),
        ("github", "event", "pull_request", "merged_at"),
        ("github", "event", "pull_request", "html_url"),
        ("github", "event", "pull_request", "user", "login"),
        ("github", "event", "pull_request", "head", "repo", "full_name"),
        ("github", "event", "repository", "name"),
        ("github", "event", "repository", "default_branch"),
        ("github", "event", "comment", "author_association"),
        ("github", "event", "workflow_run", "id"),
        ("env", "OTHER"),
        ("steps", "x", "outputs", "y"),
        ("matrix", "os"),
        ("matrix",),
        ("secrets", "TOKEN"),
    ],
)
def test_trusted_contexts(path: tuple[str, ...]) -> None:
    assert not expr.untrusted(path, frozenset({"env.title"}))


@pytest.mark.parametrize(
    ("body", "boolean"),
    [
        ("contains(github.event.issue.body, 'x')", True),
        ("startsWith(github.head_ref, 'dependabot/')", True),
        ("github.event.issue.title == 'x'", True),
        ("!github.event.issue.title", True),
        ("contains(a, b) && github.event.issue.title", False),
        ("github.event.issue.title || 'x'", False),
        ("contains(a, b) || 'x'", False),
        ("contains(a, b) ) (", False),
        ("contains(a, b) x", False),
        ("contains", False),
        ("format('{0}', github.event.issue.title)", False),
        ("contains(a, (b)", False),
        ("", False),
        ("'x'", False),
        ("format('{0}{1}', github.event.issue.title, 1 == 1)", False),
        ("format('{0}', github.event.issue.body, 0 < 1)", False),
        ("join(x[a == b], ',')", False),
        ("!format('{0}', x)", True),
    ],
)
def test_boolean_only(body: str, boolean: bool) -> None:
    assert expr.boolean_only(body) is boolean


def test_injected_normalizes_whitespace_and_skips_booleans() -> None:
    text = "echo ${{   github.event.issue.title }} ${{ contains(github.event.issue.body, 'x') }} ${{ github.sha }}"
    assert expr.injected(text) == ["github.event.issue.title"]


def test_string_literals_unquote() -> None:
    assert expr.string_literals("a == 'dependabot[bot]' || b == 'it''s'") == ["dependabot[bot]", "it's"]
