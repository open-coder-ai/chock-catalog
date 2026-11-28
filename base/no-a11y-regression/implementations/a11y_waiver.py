"""The waiver sidecar: a closed schema, read from HEAD on an agent's surface and from the change for a person."""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

FACTS = json.loads(
    (Path(__file__).resolve().parent / "data" / "element_requirements.json").read_text(encoding="utf-8")
)["waiver"]
PATH = FACTS["path"]
AGENT_ENV = tuple(FACTS["agent_env"])
EXIT_ASK, EXIT_WARN = FACTS["exit"]["ask"], FACTS["exit"]["warn"]
_FALSY = frozenset({"", "0", "false", "no", "off"})
#: Each kind of entry and its keys, in the order an entry stores them.
_KINDS = {"waive": ("file", "element", "reason"), "exempt": ("path", "reason")}

#: ("waive", file, element, reason) or ("exempt", path glob, reason)
Entry = tuple[str, ...]


class SidecarError(ValueError):
    """The sidecar is not the closed schema, so none of it is honoured."""


def _norm(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./")


def is_sidecar(path: str) -> bool:
    """Whether `path` names the sidecar, ignoring case and separators (a file system may fold either)."""
    return _norm(path).casefold() == PATH.casefold()


def by_person() -> bool:
    """False when the environment marks an agent's commit; a person's shell clears these markers."""
    return not any(os.environ.get(name, "").strip().lower() not in _FALSY for name in AGENT_ENV)


def _object(pairs: list[tuple[str, object]]) -> dict:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        msg = "a repeated key"
        raise SidecarError(msg)
    return dict(pairs)


def entries(text: str) -> frozenset[Entry]:
    """The entries of a sidecar; SidecarError on any text that breaks the closed schema."""
    try:
        value = json.loads(text, object_pairs_hook=_object)
    except json.JSONDecodeError as exc:
        msg = f"not JSON: {exc.msg}"
        raise SidecarError(msg) from None
    if not isinstance(value, dict) or not set(value) <= set(_KINDS):
        msg = "not an object with only the keys `waive` and `exempt`"
        raise SidecarError(msg)
    found: set[Entry] = set()
    for kind, order in _KINDS.items():
        listed = value.get(kind, [])
        if not isinstance(listed, list):
            msg = f"`{kind}` is not a list"
            raise SidecarError(msg)
        for item in listed:
            if (
                not isinstance(item, dict)
                or set(item) != set(order)
                or not all(isinstance(v, str) and v.strip() for v in item.values())
            ):
                msg = f"a `{kind}` entry is not exactly {{{', '.join(order)}}}, all non-empty text"
                raise SidecarError(msg)
            fields = [_norm(item[k]) if k in ("file", "path") else item[k] for k in order]
            if kind == "exempt" and not fields[0].strip("*/"):
                msg = "an exemption that covers every file"
                raise SidecarError(msg)
            found.add((kind, *fields))
    return frozenset(found)


def show(spec: str, root: Path) -> str | None:
    """The text of a git object (`HEAD:./path`, or `:./path` for the index), or None when git cannot say."""
    try:
        proc = subprocess.run(  # noqa: S603 -- a fixed git argv; the spec is built from the manifest's own path
            ["git", "show", spec],  # noqa: S607 -- git from PATH, as the runner's own
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else None


@dataclass
class Honoured:
    """What a run honours: the waivers and exemptions in force, and what the change adds."""

    waived: dict[tuple[str, str], str] = field(default_factory=dict)
    exempt: list[tuple[str, str]] = field(default_factory=list)
    added: list[Entry] = field(default_factory=list)  # entries the change holds that HEAD does not
    problems: list[str] = field(default_factory=list)  # one line per copy that breaks the schema

    def reason(self, path: str, element: str) -> str | None:
        """Why this finding is recorded as intended, or None."""
        name = _norm(path)
        if (name, element) in self.waived:
            return self.waived[name, element]
        return next((why for glob, why in self.exempt if fnmatch.fnmatchcase(name, glob)), None)


def read(head: str | None, written: str | None, *, person: bool) -> Honoured:
    """Honour HEAD's entries, and the change's own only for a person; a copy that breaks the schema honours none."""
    honoured = Honoured()
    held: frozenset[Entry] = frozenset()
    new: frozenset[Entry] = frozenset()
    for label, text in (("HEAD", head), ("this change", written)):
        if text is None:
            continue
        try:
            parsed = entries(text)
        except SidecarError as exc:
            honoured.problems.append(f"{PATH} ({label}) breaks its closed schema ({exc}); no waiver in it counts")
            continue
        if label == "HEAD":
            held = parsed
        else:
            new = parsed
    honoured.added = sorted(new - held)
    for entry in sorted(held | new if person else held):
        if entry[0] == "waive":
            honoured.waived[entry[1], entry[2]] = entry[3]
        else:
            honoured.exempt.append((entry[1], entry[2]))
    return honoured
