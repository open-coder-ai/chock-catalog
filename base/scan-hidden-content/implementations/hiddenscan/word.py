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
DTD = re.compile(r"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)
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


def _part(name: str, xml: str) -> list[tuple[str, str, str]]:
    if DTD.search(xml):
        msg = f"{name} declares a DTD"
        raise UnreadableError(msg)
    try:
        root = ET.fromstring(xml)  # noqa: S314 -- no DTD (refused above), so no entity expansion
    except ET.ParseError:
        msg = f"{name} is not well-formed XML"
        raise UnreadableError(msg) from None
    found = []
    for ns in NAMESPACES:
        for run in root.iter(f"{{{ns}}}r"):
            props = run.find(f"{{{ns}}}rPr")
            text = "".join(t.text or "" for t in run.iter() if t.tag in (f"{{{ns}}}t", f"{{{ns}}}delText")).strip()
            if props is not None and text:
                found += [(name, reason, text) for reason in _reasons(props, ns)]
    return found


def _parts(data: bytes) -> list[tuple[str, str]]:
    """(name, text) of every XML part, within the bounds: Word finds its parts through relationships, so a
    renamed main part is still read. zipfile's own errors pass up."""
    archive = zipfile.ZipFile(io.BytesIO(data))
    members = archive.infolist()
    if len(members) > MAX_MEMBERS:
        msg = f"{len(members)} zip members"
        raise UnreadableError(msg)
    out = []
    for info in members:
        if not info.filename.lower().endswith(".xml"):
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
