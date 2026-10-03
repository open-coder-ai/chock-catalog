"""MSBuild project files, central package versions and packages.config: NuGet package ids."""

from __future__ import annotations

from depnames import xmlsafe

_ITEMS = frozenset(
    {"packagereference", "packageversion", "globalpackagereference", "dotnetclitoolreference", "packagedownload"}
)


def dotnet_names(text: str) -> list[str]:
    """Package ids from PackageReference-style items (Include, any case: MSBuild ignores it) and packages.config entries (id)."""
    root = xmlsafe.parse(text)
    legacy = xmlsafe.local(root.tag) == "packages"
    names: list[str] = []
    for element in root.iter():
        tag = xmlsafe.local(element.tag).lower()
        attrs = {key.lower(): value for key, value in element.attrib.items()}
        name = attrs.get("id") if legacy and tag == "package" else attrs.get("include") if tag in _ITEMS else None
        names += [part.strip() for part in (name or "").split(";") if part.strip()]
    return names
