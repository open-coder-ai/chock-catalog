"""Hidden runs in a Word document: vanished, white or 1-point text, read from the zip without an XML parser."""

from __future__ import annotations

import html
import io
import re
import subprocess
import zipfile

#: Word's story parts: body, headers, footers, notes and comments.
PARTS = re.compile(r"word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml")
PROPS = re.compile(r"<w:rPr>([\s\S]*?)</w:rPr>")
TEXT = re.compile(r"<w:t(?:\s[^>]*)?>([^<]*)</w:t>")
OFF = re.compile(r'w:val="(?:0|false|off)"')
VANISH = re.compile(r"<w:(?:vanish|specVanish|webHidden)(?:\s[^>]*)?/>")
WHITE = re.compile(r'<w:color\s[^>]*w:val="(?:FFFFFF|ffffff)"')
SIZE = re.compile(r'<w:sz\s[^>]*w:val="(\d+)"')
#: Bounds on what is unpacked, so a zip bomb or a huge part is reported, not expanded.
MAX_PART = 32 << 20
#: Word sizes are in half-points: 2 is 1 point.
ONE_POINT = 2
MAX_MEMBERS = 4096
MAX_BLOB = 64 << 20
#: A blob of a write: the index at a person's or agent's commit, HEAD at a push or in CI.
BLOB_REF = {"commit": ":./{}", "agent-commit": ":./{}", "push": "HEAD:./{}", "ci": "HEAD:./{}"}


class UnreadableError(ValueError):
    """The document could not be read within the bounds: it is reported, never passed."""


def blob(repo_root: str, event: str, path: str, *, baseline: bool) -> bytes | None:
    """The document's bytes from git, or None where none is judged: at tool use (the write tools carry text,
    not a zip), a baseline at a push or in CI (the base is not in the payload, so every run there is new), or
    a path git does not have."""
    if event not in BLOB_REF or (baseline and event in ("push", "ci")):
        return None
    ref = ("HEAD:./{}" if baseline else BLOB_REF[event]).format(path)
    proc = subprocess.run(  # noqa: S603 -- git reads a blob; nothing is written
        ["git", "cat-file", "blob", ref],  # noqa: S607 -- git from PATH, as the runner itself calls it
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if proc.returncode or len(proc.stdout) > MAX_BLOB:
        return None if proc.returncode else b""
    return proc.stdout


def _reasons(props: str) -> list[str]:
    out = []
    if any(not OFF.search(m.group(0)) for m in VANISH.finditer(props)):
        out.append("hidden (vanish)")
    if WHITE.search(props):
        out.append("white text")
    if (size := SIZE.search(props)) and int(size.group(1)) <= ONE_POINT:
        out.append("1-point text or smaller")
    return out


def _runs(xml: str) -> list[str]:
    """Each `<w:r>` element's text, found by plain search so a part without closing tags stays linear."""
    out, at = [], xml.find("<w:r")
    while at != -1:
        end = xml.find("</w:r>", at)
        if end == -1:
            break
        if xml[at + 4 : at + 5] in (">", " ", "\t", "\n", "\r"):
            out.append(xml[at:end])
            at = xml.find("<w:r", end)
        else:
            at = xml.find("<w:r", at + 4)
    return out


def _part(name: str, xml: str) -> list[tuple[str, str, str]]:
    found = []
    for run in _runs(xml):
        props = PROPS.search(run)
        text = "".join(html.unescape(t) for t in TEXT.findall(run)).strip()
        if props and text:
            found += [(name, reason, text) for reason in _reasons(props.group(1))]
    return found


def _parts(data: bytes) -> list[tuple[str, str]]:
    """(name, text) of each story part, within the bounds; zipfile's own errors pass up."""
    archive = zipfile.ZipFile(io.BytesIO(data))
    members = archive.infolist()
    if len(members) > MAX_MEMBERS:
        msg = f"{len(members)} zip members"
        raise UnreadableError(msg)
    out = []
    for info in members:
        if not PARTS.fullmatch(info.filename):
            continue
        with archive.open(info) as handle:
            raw = handle.read(MAX_PART + 1)
        if len(raw) > MAX_PART:
            msg = f"{info.filename} unpacks past {MAX_PART >> 20} MB"
            raise UnreadableError(msg)
        out.append((info.filename, raw.decode("utf-8", errors="replace")))
    return out


def hidden_runs(data: bytes) -> list[tuple[str, str, str]]:
    """(part, reason, text) of each hidden run with text; UnreadableError when the zip is not a bounded document."""
    try:
        parts = _parts(data)
    except UnreadableError:
        raise
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        NotImplementedError,
        RuntimeError,
        OSError,
        EOFError,
        ValueError,
    ) as exc:
        msg = f"not a readable document ({type(exc).__name__})"
        raise UnreadableError(msg) from None
    return [found for name, xml in parts for found in _part(name, xml)]
