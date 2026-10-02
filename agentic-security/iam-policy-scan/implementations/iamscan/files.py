"""Which files are judged, how each is read, and what is reported when one cannot be."""

from __future__ import annotations

import bisect
import hashlib
import json
import re
from pathlib import PurePosixPath

from chock_scan import hcl, jsonc, yamlpath
from chock_scan.hcl_json import parse_json

from iamscan import azure, hclread, tree
from iamscan.access import LINE_BREAK, unescaped
from iamscan.model import BLOCK, Finding, signature
from iamscan.walk import LOCATABLE, Scan, Spot, number

#: A file this gate never opens unless its text mentions something a grant is made of.
PREFILTER = re.compile(
    r"(?i)effect|principal|notaction|\bstatement\b|\bverbs\b|rolebinding|clusterrole|roleassignment|azurerm_role"
)
MAX_CHARS = 1 << 20  # the readers refuse more; a file this big that mentions a grant is refused, not skipped
MAX_FINDINGS = 1000  # past this, judging and placing each one is itself a way to stall the hook
LOCKFILE = re.compile(r"(?i)(?:^|/)[^/]*(?:-lock\.(?:json|ya?ml)|\.lock|\.lockb)$")
STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
COLON = re.compile(r"\s*:")
TEMPLATE = re.compile(r"\{\{|\{%")
DIRECTIVE_LINE = re.compile(r"\s*(?:\{\{.*\}\}|\{%.*%\})\s*")
HCL = frozenset({".tf", ".tfvars", ".hcl", ".tofu"})
YAML = frozenset({".yaml", ".yml"})
JSON = frozenset({".json", ".jsonc"})
BICEP = frozenset({".bicep"})
READ_ERRORS = (ValueError, RecursionError)  # JsoncError, HclError and ParseError are ValueErrors


def kind_of(path: str) -> str | None:
    """json, yaml, hcl, tfjson or bicep by file name; None for a file this gate does not judge."""
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    if name.endswith((".tf.json", ".tfvars.json")):
        return "tfjson"
    suffix = PurePosixPath(name).suffix
    if suffix == ".template":
        return "template"
    for kind, suffixes in (("hcl", HCL), ("yaml", YAML), ("json", JSON), ("bicep", BICEP)):
        if suffix in suffixes:
            return kind
    return None


def scan_file(path: str, text: str) -> list[Finding]:
    """Every broad grant in one file, or a single `iam-unreadable` finding when a file that mentions grants cannot be read."""
    kind = kind_of(path)
    if kind is None or not PREFILTER.search(unescaped(text)):
        return []
    if kind == "template":  # a CloudFormation .template is JSON or YAML
        kind = "json" if text.lstrip("\ufeff \t\r\n").startswith("{") else "yaml"
    scan = Scan(path)
    try:
        if len(text) > MAX_CHARS:
            msg = f"larger than {MAX_CHARS} characters"
            raise ValueError(msg)
        _READERS[kind](text, scan)
        if len(scan.found) > MAX_FINDINGS:
            msg = f"more than {MAX_FINDINGS} grants in one file"
            raise ValueError(msg)
    except READ_ERRORS as exc:
        if len(text) > MAX_CHARS and LOCKFILE.search(path):
            return []
        found = [] if len(scan.found) > MAX_FINDINGS else [f for f in scan.found if f.rule != "iam-unreadable"]
        # The id holds the text, so any change to a file that cannot be read is new: an old refusal never excuses an edit.
        sig = signature([kind, hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()])
        return [*found, Finding("iam-unreadable", BLOCK, path, getattr(exc, "line", None) or 1, sig, (1,))]
    return scan.found


def neutralize(text: str) -> str:
    """Template text with each line that is only a directive dropped and each inline `{{ }}` made a plain word."""
    kept = (line for line in text.splitlines() if not DIRECTIVE_LINE.fullmatch(line))
    return "\n".join(re.sub(r"\{\{.*?\}\}|\{%.*?%\}", "TPL", line) for line in kept) + "\n"


def _json(text: str, scan: Scan) -> None:
    document = jsonc.loads(text)
    root = document.value
    schema = next((v for k, v in root.items() if str(k).lower() == "$schema"), "") if isinstance(root, dict) else ""
    scan.subscription_deployment = isinstance(schema, str) and azure.BROAD_SCHEMA.search(schema) is not None
    for dup in document.duplicates:
        scan.duplicate(str(dup.path[-1]), 1)
    scan.numbering = number(root)
    scan.walk(root)
    _locate(scan, text)


def _tfjson(text: str, scan: Scan) -> None:
    try:
        hclread.scan_block(parse_json(text), scan, nested=False)
    except hcl.HclError:
        _json(text, scan)


def _yaml(text: str, scan: Scan) -> None:
    try:
        trees, repeats = tree.docs(text)
    except yamlpath.ParseError:
        if not TEMPLATE.search(text):
            raise
        # Helm and Jinja text is not YAML until its directives are gone; what still does not read is not judged.
        try:
            trees, repeats = tree.docs(neutralize(text))
        except yamlpath.ParseError:
            return
    for name, line in repeats:
        scan.duplicate(name, line)
    for document in trees:
        scan.walk(document)


def _hcl(text: str, scan: Scan) -> None:
    hclread.scan_block(hcl.parse(text), scan)


def _bicep(text: str, scan: Scan) -> None:
    lines = azure.bicep_assignments(text)
    if len(lines) > azure.MAX_BICEP_RESOURCES:
        msg = "more role assignments than the gate reads"
        raise ValueError(msg)
    for line in lines:
        scan.add("azure-subscription-owner", BLOCK, ["bicep", line], Spot(line, "roleDefinitionId", (line,)))


def _key_spots(text: str) -> dict[str, list[int]]:
    """Offsets of each locatable key in document order: every string with a colon after it, comments blanked first."""
    clean = jsonc.strip(text)
    spots: dict[str, list[int]] = {}
    for match in STRING.finditer(clean):
        if not COLON.match(clean, match.end()):
            continue
        name = json.loads(match.group()).lower()  # the file parsed, so every string in it is valid
        if name in LOCATABLE:
            spots.setdefault(name, []).append(match.start())
    return spots


def _locate(scan: Scan, text: str) -> None:
    """Give JSON findings the line of the key they are about: the n-th such key in the file, as the walk counted it."""
    if not any(f.nth >= 0 for f in scan.found):
        return
    spots = _key_spots(text)
    starts = [m.end() for m in LINE_BREAK.finditer(text)]
    located = []
    for found in scan.found:
        where = spots.get(found.hint.lower(), [])
        if found.nth >= 0 and found.nth < len(where):
            line = bisect.bisect_right(starts, where[found.nth]) + 1
            found = Finding(found.rule, found.tier, found.path, line, found.sig, (line,), found.hint, found.nth)  # noqa: PLW2901
        located.append(found)
    scan.found = located


_READERS = {"json": _json, "tfjson": _tfjson, "yaml": _yaml, "hcl": _hcl, "bicep": _bicep}
