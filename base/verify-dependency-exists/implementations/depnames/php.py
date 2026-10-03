"""composer.json: require and require-dev; platform requirements (no vendor) are not packages."""

from __future__ import annotations

import json


def composer_names(text: str) -> list[str]:
    """Package names of `require` and `require-dev`, minus php, ext-* and the other platform entries."""
    data = json.loads(text.removeprefix("\ufeff"))
    names: list[str] = []
    for key in ("require", "require-dev") if isinstance(data, dict) else ():
        table = data.get(key)
        names += [name for name in table if "/" in name] if isinstance(table, dict) else []
    return names
