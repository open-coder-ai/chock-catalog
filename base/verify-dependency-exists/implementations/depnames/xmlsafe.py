"""XML parsing for manifests: a DOCTYPE or ENTITY declaration is refused before the parser sees the text."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_DECLARATION = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)


class RefusedError(ValueError):
    """The text declares a DOCTYPE or ENTITY; a build manifest has no use for either."""


def parse(text: str) -> ET.Element:
    """The root element; RefusedError for a DOCTYPE or ENTITY declaration, ParseError when the XML is malformed."""
    if _DECLARATION.search(text):
        msg = "declares a DOCTYPE or ENTITY"
        raise RefusedError(msg)
    return ET.fromstring(text.removeprefix("\ufeff"))  # noqa: S314 -- DOCTYPE and ENTITY are refused above, so nothing expands


def local(tag: str) -> str:
    """An element name without its namespace."""
    return tag.rsplit("}", 1)[-1]
