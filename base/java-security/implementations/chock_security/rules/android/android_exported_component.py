"""An exported component with no permission attribute answers whatever any app on the device sends it."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath
from xml.etree import ElementTree
from xml.parsers import expat

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "android-exported-component"

_FACTS = facts("android")["exported_component"]
_NS = _FACTS["ns"]


def _attr(element: ElementTree.Element, name: str) -> str | None:
    return element.get(f"{{{_NS}}}{name}")


def _clark(name: str) -> str:
    """expat's own namespace-separated form (`uri}local`) into ElementTree's `{uri}local`."""
    return f"{{{name}" if "}" in name else name


def _parse(xml_text: str) -> tuple[ElementTree.Element, dict[int, int]] | None:
    """The root element and a line number per element, or None on anything this cannot parse --
    a malformed manifest is exactly the case this rule must stay silent on, never guess at.

    Built directly on `xml.parsers.expat` (namespace-aware) rather than `ElementTree.XMLParser`:
    the accelerated C implementation `XMLParser` wraps gives no way back to the expat parser's
    own line counter, and a finding with no line number is not a finding this pack can render.
    """
    try:
        parser = expat.ParserCreate(namespace_separator="}")
        builder = ElementTree.TreeBuilder()
        lines: dict[int, int] = {}

        def start(name: str, attrs: dict[str, str]) -> None:
            element = builder.start(_clark(name), {_clark(k): v for k, v in attrs.items()})
            lines[id(element)] = parser.CurrentLineNumber

        def end(name: str) -> None:
            builder.end(_clark(name))

        parser.StartElementHandler = start
        parser.EndElementHandler = end
        parser.CharacterDataHandler = builder.data
        parser.Parse(xml_text, True)  # noqa: FBT003 -- expat's C API takes isfinal positionally only
        root = builder.close()
    except Exception:  # noqa: BLE001 -- any parse failure is silence, not a crash
        return None
    return root, lines


def _is_launcher_activity(element: ElementTree.Element) -> bool:
    for intent_filter in element.findall("intent-filter"):
        actions = {_attr(child, "name") for child in intent_filter.findall("action")}
        categories = {_attr(child, "name") for child in intent_filter.findall("category")}
        if _FACTS["launcher_action"] in actions and _FACTS["launcher_category"] in categories:
            return True
    return False


def _message(tag: str) -> str:
    return (
        f'This <{tag}> is exported (android:exported="true") with no android:permission '
        "guarding it, so any app on the device -- including one holding no permissions of its "
        "own -- can start, bind to or query it directly. Add android:permission naming a "
        'signature-level permission only this app holds, or set android:exported="false" if '
        "nothing outside this app ever calls it. The one exception is the launcher activity, "
        "whose own MAIN/LAUNCHER intent-filter is what the system uses to reach it, and needs no "
        f"permission of its own. A component that genuinely must accept any caller needs 'chock: "
        f"allow {RULE_ID}' on this line."
    )


def scan(text: FileText) -> Iterator[Finding]:
    if PurePosixPath(text.path).name != "AndroidManifest.xml":
        return
    parsed = _parse(text.text)
    if parsed is None:
        return
    root, lines = parsed
    for tag in _FACTS["tags"]:
        for element in root.iter(tag):
            if _attr(element, "exported") != "true" or _attr(element, "permission") is not None:
                continue
            if tag == "activity" and _is_launcher_activity(element):
                continue
            line_no = lines.get(id(element))
            if line_no is None:
                continue
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _message(tag))


RULE = Rule(
    id=RULE_ID,
    pack="android",
    title="Exported component with no permission",
    suffixes=(".xml",),
    scan=scan,
    constraint=(
        'never(export): activity|service|receiver|provider with android:exported="true" and no '
        'android:permission -- name a permission, or set exported="false"; the launcher '
        "activity's own MAIN/LAUNCHER intent-filter is the one exception"
    ),
    refuses="an exported activity/service/receiver/provider with no `android:permission`",
    silent_on='`android:permission` present; `exported="false"` or the attribute omitted; the launcher activity',
    cwe=("CWE-926", "CWE-862"),
    references=(
        "https://developer.android.com/privacy-and-security/risks/access-control-to-exported-components",
        "https://developer.android.com/privacy-and-security/risks/android-exported",
    ),
)
