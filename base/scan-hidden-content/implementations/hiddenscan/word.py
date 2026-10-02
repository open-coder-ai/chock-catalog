"""Hidden runs in a Word document: vanished, white or 1-point text, read namespace-aware from every XML part."""

from __future__ import annotations

import io
import re
import subprocess
import zipfile
from xml.etree import ElementTree as ET

#: WordprocessingML, transitional and strict: a run is found by namespace, whatever its prefix.
NAMESPACES = (
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "http://purl.oclc.org/ooxml/wordprocessingml/main",
)
HIDING = ("vanish", "specVanish", "webHidden")
OFF = {"0", "false", "off"}
SIZE = re.compile(r"\d{1,6}")
#: A DTD can expand entities without bound; no Word part carries one, so a part with one is refused.
DTD = re.compile(rb"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)
#: Bounds on what is unpacked, so a zip bomb or a huge part is reported, not expanded.
MAX_PART = 32 << 20
#: Word sizes are in half-points: 2 is 1 point.
ONE_POINT = 2
MAX_MEMBERS = 4096
MAX_TOTAL = 64 << 20
MAX_ELEMENTS = 1_000_000
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


def _reasons(props: ET.Element, ns: str) -> list[str]:
    out = []
    if any(props.find(f"{{{ns}}}{tag}") is not None and _val(props, tag, ns) not in OFF for tag in HIDING):
        out.append("hidden (vanish)")
    if (_val(props, "color", ns) or "").upper() == "FFFFFF":
        out.append("white text")
    size = _val(props, "sz", ns) or ""
    if SIZE.fullmatch(size) and int(size) <= ONE_POINT:
        out.append("1-point text or smaller")
    return out


def _val(props: ET.Element, tag: str, ns: str) -> str | None:
    found = props.find(f"{{{ns}}}{tag}")
    return None if found is None else (found.get(f"{{{ns}}}val") or "").strip()


def _local(tag: str) -> tuple[str, str]:
    namespace, _, local = tag[1:].partition("}") if tag.startswith("{") else ("", "", tag)
    return namespace, local


def _part(name: str, raw: bytes, budget: list[int]) -> list[tuple[str, str, str]]:
    """Hidden runs of one part, parsed as a stream: each run is judged and dropped as it closes, and the
    document's element budget is shared across parts."""
    if DTD.search(raw):
        msg = f"{name} declares a DTD"
        raise UnreadableError(msg)
    found, depth, root = [], 0, None
    try:
        for event, elem in ET.iterparse(io.BytesIO(raw), events=("start", "end")):  # noqa: S314 -- no DTD
            namespace, local = _local(elem.tag)
            run = local == "r" and namespace in NAMESPACES
            if event == "start":
                root = elem if root is None else root
                depth += run
                budget[0] -= 1
                if budget[0] < 0:
                    msg = f"more than {MAX_ELEMENTS} XML elements"
                    raise UnreadableError(msg)
                continue
            if run:
                depth -= 1
                found += _judge(name, elem, namespace)
            if not depth:
                elem.clear()
                if budget[0] % 4096 == 0:
                    root.clear()
    except ET.ParseError:
        msg = f"{name} is not well-formed XML"
        raise UnreadableError(msg) from None
    return found


def _judge(name: str, run: ET.Element, ns: str) -> list[tuple[str, str, str]]:
    props = run.find(f"{{{ns}}}rPr")
    text = "".join(t.text or "" for t in run.iter() if t.tag in (f"{{{ns}}}t", f"{{{ns}}}delText")).strip()
    return [(name, reason, text) for reason in _reasons(props, ns)] if props is not None and text else []


def _parts(data: bytes) -> list[tuple[str, bytes]]:
    """(name, bytes) of every member that reads as XML, within the bounds: Word finds its parts through
    relationships, so a part under any name is read. zipfile's own errors pass up."""
    archive = zipfile.ZipFile(io.BytesIO(data))
    members = archive.infolist()
    if len(members) > MAX_MEMBERS:
        msg = f"{len(members)} zip members"
        raise UnreadableError(msg)
    out, total = [], 0
    for info in members:
        with archive.open(info) as handle:
            raw = handle.read(MAX_PART + 1)
        total += len(raw)
        if len(raw) > MAX_PART or total > MAX_TOTAL:
            msg = f"{info.filename} unpacks past {MAX_PART >> 20} MB, or the document past {MAX_TOTAL >> 20} MB"
            raise UnreadableError(msg)
        head = raw[:64].lstrip(b"\xef\xbb\xbf \t\r\n")
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or head.startswith(b"<\x00"):
            msg = f"{info.filename} is XML in UTF-16, which this reader does not judge"
            raise UnreadableError(msg)
        if head.startswith(b"<"):
            out.append((info.filename, raw))
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
    budget = [MAX_ELEMENTS]
    return [found for name, raw in parts for found in _part(name, raw, budget)]
