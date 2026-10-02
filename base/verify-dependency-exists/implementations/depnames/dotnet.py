"""MSBuild project files, central package versions and packages.config: NuGet package ids."""

from __future__ import annotations

from depnames import xmlsafe

_ITEMS = frozenset(
    {"PackageReference", "PackageVersion", "GlobalPackageReference", "DotNetCliToolReference", "PackageDownload"}
)


def dotnet_names(text: str) -> list[str]:
    """Package ids from PackageReference-style items (Include) and packages.config entries (id)."""
    root = xmlsafe.parse(text)
    legacy = xmlsafe.local(root.tag) == "packages"
    names: list[str] = []
    for element in root.iter():
        tag = xmlsafe.local(element.tag)
        name = element.get("id") if legacy and tag == "package" else element.get("Include") if tag in _ITEMS else None
        names += [part.strip() for part in (name or "").split(";") if part.strip()]
    return names
