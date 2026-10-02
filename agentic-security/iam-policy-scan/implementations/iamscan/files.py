"""Which files are judged, how each is read, and what is reported when one cannot be."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from chock_scan import hcl, jsonc, yamlpath
from chock_scan.hcl_json import parse_json

from iamscan import azure, hclread, tree
from iamscan.model import BLOCK, Finding, signature
from iamscan.walk import Scan, Spot

#: A file this gate never opens unless its text mentions something a grant is made of.
#: What a file must say before failing to parse counts as hiding a grant, rather than being some other file.
GRANT_SHAPED = re.compile(
    r"(?is)\beffect[\"']?\s*[:=]?\s*[\"']?\s*allow|\bkind\b[\"']?\s*[:=]\s*[\"']?(?:cluster)?role|roleassignments"
    r"|azurerm_role_assignment|\bnotaction\b|\bprincipal\b[\"']?\s*[:=]"
)
PREFILTER = re.compile(
    r"(?i)effect|principal|notaction|\bstatement\b|\bverbs\b|rolebinding|clusterrole|roleassignment|azurerm_role"
)
TEMPLATE = re.compile(r"\{\{|\{%")
DIRECTIVE_LINE = re.compile(r"\s*(?:\{\{.*\}\}|\{%.*%\})\s*")
HCL = frozenset({".tf", ".tfvars", ".hcl"})
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
    if kind is None or not PREFILTER.search(text):
        return []
    if kind == "template":  # a CloudFormation .template is JSON or YAML
        kind = "json" if text.lstrip("\ufeff \t\r\n").startswith("{") else "yaml"
    scan = Scan(path)
    try:
        _READERS[kind](text, scan)
    except READ_ERRORS as exc:
        if not GRANT_SHAPED.search(text):
            return scan.found
        found = [f for f in scan.found if f.rule != "iam-unreadable"]
        return [*found, Finding("iam-unreadable", BLOCK, path, getattr(exc, "line", None) or 1, signature(kind), (1,))]
    return scan.found


def neutralize(text: str) -> str:
    """Template text with each line that is only a directive dropped and each inline `{{ }}` made a plain word."""
    kept = (line for line in text.splitlines() if not DIRECTIVE_LINE.fullmatch(line))
    return "\n".join(re.sub(r"\{\{.*?\}\}|\{%.*?%\}", "TPL", line) for line in kept) + "\n"


def _json(text: str, scan: Scan) -> None:
    document = jsonc.loads(text)
    root = document.value
    schema = next((v for k, v in root.items() if k == "$schema"), "") if isinstance(root, dict) else ""
    scan.subscription_deployment = isinstance(schema, str) and azure.SUBSCRIPTION_SCHEMA in schema.lower()
    for dup in document.duplicates:
        scan.duplicate(str(dup.path[-1]), 1)
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
    for line in azure.bicep_assignments(text):
        scan.add("azure-subscription-owner", BLOCK, ["bicep", line], Spot(line, "roleDefinitionId", (line,)))


def _locate(scan: Scan, text: str) -> None:
    """Give JSON findings the line of the key they are about: the n-th such key in the file, in the order found."""
    seen: dict[str, int] = {}
    located = []
    for found in scan.found:
        if found.hint and found.line == 1:
            spots = [m.start() for m in re.finditer(rf'"{re.escape(found.hint)}"\s*:', text, re.I)]
            index = seen[found.hint] = seen.get(found.hint, -1) + 1
            if index < len(spots):
                line = text.count("\n", 0, spots[index]) + 1
                found = Finding(found.rule, found.tier, found.path, line, found.sig, (line,), found.hint)  # noqa: PLW2901
        located.append(found)
    scan.found = located


_READERS = {"json": _json, "tfjson": _tfjson, "yaml": _yaml, "hcl": _hcl, "bicep": _bicep}
