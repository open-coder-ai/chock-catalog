"""pom.xml: dependency, plugin, extension and parent coordinates as `group:artifact`."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from depnames import xmlsafe

_ELEMENTS = frozenset({"dependency", "plugin", "extension", "parent"})
_PLUGIN_GROUP = "org.apache.maven.plugins"


def _child(element: ET.Element, name: str) -> str:
    for child in element:
        if xmlsafe.local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def pom_names(text: str) -> list[str]:
    """Coordinates of everything a POM pulls in; `${...}` placeholders are kept as written, not resolved."""
    names: list[str] = []
    for element in xmlsafe.parse(text).iter():
        tag = xmlsafe.local(element.tag)
        if tag not in _ELEMENTS:
            continue
        artifact = _child(element, "artifactId")
        group = _child(element, "groupId") or (_PLUGIN_GROUP if tag == "plugin" else "")
        if artifact and group:
            names.append(f"{group}:{artifact}")
    return names
