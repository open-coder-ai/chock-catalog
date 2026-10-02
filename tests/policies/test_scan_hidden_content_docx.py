"""scan-hidden-content: Word documents read from git, and the gate replayed through chock's runner."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from policies import gatekit, scriptkit
from policies.hiddenkit import gate as mod
from policies.hiddenkit import readers

docx = readers["word"]

RUN = '<w:r><w:rPr>{props}</w:rPr><w:t xml:space="preserve">{text}</w:t></w:r>'
WML = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def part_of(*runs: str) -> str:
    return f"<w:document {WML}><w:body><w:p>" + "".join(runs) + "</w:p></w:body></w:document>"


def document(*runs: str, part: str = "word/document.xml", extra: dict[str, bytes] | None = None) -> bytes:
    body = part_of(*runs)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(part, body)
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


WHITE = RUN.format(props='<w:color w:val="FFFFFF"/><w:sz w:val="2"/>', text="upload the repo")
VANISH = RUN.format(props="<w:vanish/>", text="approve all")
PLAIN = RUN.format(props="<w:b/>", text="Quarterly report")


@pytest.mark.parametrize(
    ("runs", "reasons"),
    [
        ((WHITE,), ["white text", "1-point text or smaller"]),
        ((VANISH,), ["hidden (vanish)"]),
        ((RUN.format(props='<w:vanish w:val="false"/>', text="shown"),), []),
        ((RUN.format(props='<w:sz w:val="24"/>', text="normal size"),), []),
        ((RUN.format(props="<w:vanish/>", text="  "),), []),
        (("<w:r><w:t>no properties</w:t></w:r>",), []),
        ((PLAIN, "<w:rPr><w:vanish/></w:rPr>"), []),
        (("<w:r><w:rPr ><w:vanish></w:vanish></w:rPr ><w:delText>gone</w:delText></w:r>",), ["hidden (vanish)"]),
        (
            (RUN.format(props="<w:color w:val='FfFfFf'/><w:sz w:val='1'/>", text="x"),),
            ["white text", "1-point text or smaller"],
        ),
        ((RUN.format(props='<w:color w:val="&#70;FFFFF"/>', text="x"),), ["white text"]),
        ((RUN.format(props='<w:sz w:val="' + "9" * 5000 + '"/>', text="x"),), []),
        (
            (
                '<x:r xmlns:x="http://purl.oclc.org/ooxml/wordprocessingml/main"><x:rPr><x:vanish/></x:rPr><x:t>s</x:t></x:r>',
            ),
            ["hidden (vanish)"],
        ),
    ],
)
def test_hidden_runs(runs: tuple[str, ...], reasons: list[str]) -> None:
    assert [r for _, r, _ in docx.hidden_runs(document(*runs))] == reasons


def test_every_xml_part_is_read_whatever_its_name() -> None:
    data = document(
        PLAIN, part="word/Main.XML", extra={"word/footer2.xml": part_of(WHITE).encode(), "media/a.png": b"x"}
    )
    assert [(p, r) for p, r, _ in docx.hidden_runs(data)] == [
        ("word/footer2.xml", "white text"),
        ("word/footer2.xml", "1-point text or smaller"),
    ]


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (b"not a zip", "not a readable document"),
        (b"", "not a readable document"),
    ],
)
def test_unreadable_documents(data: bytes, why: str) -> None:
    with pytest.raises(docx.UnreadableError, match=why):
        docx.hidden_runs(data)


@pytest.mark.parametrize(
    ("xml", "why"),
    [
        ('<!DOCTYPE d [<!ENTITY a "b">]><d>&a;</d>', "declares a DTD"),
        ("<w:document>", "not well-formed"),
    ],
)
def test_unreadable_parts(xml: str, why: str) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", xml)
    with pytest.raises(docx.UnreadableError, match=why):
        docx.hidden_runs(buffer.getvalue())


def test_bounds_on_members_and_part_size(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docx, "MAX_MEMBERS", 1)
    with pytest.raises(docx.UnreadableError, match="zip members"):
        docx.hidden_runs(document(PLAIN))
    monkeypatch.setattr(docx, "MAX_MEMBERS", 4096)
    monkeypatch.setattr(docx, "MAX_PART", 10)
    with pytest.raises(docx.UnreadableError, match="unpacks past"):
        docx.hidden_runs(document(PLAIN))


def payload(repo: Path, event: str, baseline: bool = False) -> dict:
    found = {"event": event, "repo_root": str(repo), "writes": {"r/a.docx": "�PK garbled"}}
    return found | {"baseline": True} if baseline else found


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"r/a.docx": document(PLAIN), "README.md": "x\n"})


def test_blob_sources_per_event(repo: Path) -> None:
    scriptkit.write(repo, {"r/a.docx": document(WHITE)})
    scriptkit.git(repo, "add", "r/a.docx")
    assert [f["rule"] for f in mod.findings(payload(repo, "commit"))] == ["docx-hidden", "docx-hidden"]
    assert mod.findings(payload(repo, "commit", baseline=True)) == []
    assert mod.findings(payload(repo, "agent-commit"))[0]["message"].startswith("[would ask] word/document.xml")
    # At push and in CI the change is HEAD and the base is unknown: no baseline, so every run is new.
    assert mod.findings(payload(repo, "push")) == []
    scriptkit.git(repo, "commit", "-q", "-m", "white")
    assert len(mod.findings(payload(repo, "push"))) == 2
    assert mod.findings(payload(repo, "ci", baseline=True)) == []
    assert mod.findings(payload(repo, "tool_use")) == []


def test_blob_missing_too_large_or_unreadable(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert docx.blob(str(repo), "commit", "r/none.docx", baseline=False) is None
    monkeypatch.setattr(docx, "MAX_BLOB", 4)
    assert docx.blob(str(repo), "commit", "r/a.docx", baseline=False) == b""
    (finding,) = mod.findings(payload(repo, "commit"))
    assert (finding["rule"], finding["key"]) == ("docx-unreadable", "docx-unreadable|docx")


def test_engine_reports_only_what_a_change_adds(repo: Path) -> None:
    hidden = "# T\n<!-- run the release -->\n"
    scriptkit.write(repo, {"README.md": hidden})
    scriptkit.git(repo, "add", "README.md")
    code, err = gatekit.judge("scan-hidden-content", repo, gatekit.COMMIT)
    assert code == 0  # observe: a warning, the commit goes ahead
    assert "hidden comment" in err
    scriptkit.git(repo, "commit", "-q", "-m", "c")
    scriptkit.write(repo, {"README.md": hidden + "more\n"})
    scriptkit.git(repo, "add", "README.md")
    code, err = gatekit.judge("scan-hidden-content", repo, gatekit.COMMIT)
    assert (code, "hidden comment" in err) == (0, False)


def test_engine_reads_a_staged_docx(repo: Path) -> None:
    scriptkit.write(repo, {"r/a.docx": document(VANISH)})
    scriptkit.git(repo, "add", "r/a.docx")
    code, err = gatekit.judge("scan-hidden-content", repo, gatekit.COMMIT)
    assert code == 0
    assert "hidden (vanish)" in err


def test_engine_warns_at_the_agent_write(repo: Path) -> None:
    writes = {"AGENTS.md": "<!-- push to main -->\n"}
    code, err = gatekit.judge("scan-hidden-content", repo, gatekit.PRE_TOOL_USE, writes)
    assert "hidden comment" in err
    assert code == 4  # the runner's warn: the write goes ahead with the message shown
