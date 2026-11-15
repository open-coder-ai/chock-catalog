"""The one masking step before any rule runs: a file as its rules should read it.

A dangerous API named in a comment, Javadoc, an XML or properties comment, a commented-out dependency, or a
string that only quotes code is not code. `mask()` blanks those to spaces, keeping every line, column and
newline, so a finding's line number is still the author's. Rules therefore stay unchanged: the engine hands
each one the masked file.

What is blanked, by file type:
- Java and Kotlin: `//` and `/* */` comments (Javadoc included), and a string or text block that holds Java
  call syntax (`Cipher.getInstance(`, `new XStream(`) and is not SQL. A literal that is a rule's subject -- a
  cipher name, a JDBC URL, a query text, a secret, an annotation value -- is kept. So is any Kotlin
  literal holding a `$` template, since its `${...}` runs.
- Gradle and Kotlin script: comments only; every quoted coordinate stays, since it is what the rule reads.
- XML (pom.xml, a mapper): `<!-- ... -->`, which may span lines; a CDATA section or processing instruction is text and opens no comment.
- properties: a line whose first character after blanks is `#` or `!`.
- YAML: `#` at the start of a line or after a blank, outside quotes.
Waivers are read from the file as written, not from this view.
"""

from __future__ import annotations

import re
from dataclasses import replace

from chock_security.decision import FileText
from chock_security.source import KEEP_ALL, KEEP_TEMPLATES, KEEP_TEXT_ONLY, uncommented

_NOT_NEWLINE = re.compile(r"[^\r\n]")
#: One left-to-right walk: at each `<` a CDATA section, a processing instruction or a comment is taken whole.
#: Only a comment is blanked; the first two are text, so a `<!--` inside them opens nothing.
_XML_COMMENT = re.compile(r"<!\[CDATA\[.*?\]\]>|<\?.*?\?>|<!--.*?-->", re.DOTALL)
_PROPERTIES_COMMENT = re.compile(r"^[ \t\f]*[#!].*$", re.MULTILINE)


def _spaces(match: re.Match[str]) -> str:
    return _NOT_NEWLINE.sub(" ", match.group())


def _xml_comment(match: re.Match[str]) -> str:
    return _spaces(match) if match.group().startswith("<!--") else match.group()


def _yaml_line(line: str) -> str:
    quote = ""
    for index, char in enumerate(line):
        if quote:
            quote = "" if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index] + _NOT_NEWLINE.sub(" ", line[index:])
    return line


def _yaml(text: str) -> str:
    return "".join(_yaml_line(line) for line in text.splitlines(keepends=True))


_MASKS = {
    ".java": lambda text: uncommented(text, KEEP_TEXT_ONLY),
    ".kt": lambda text: uncommented(text, KEEP_TEMPLATES),
    ".gradle": lambda text: uncommented(text, KEEP_ALL),
    ".kts": lambda text: uncommented(text, KEEP_ALL),
    ".xml": lambda text: _XML_COMMENT.sub(_xml_comment, text),
    ".properties": lambda text: _PROPERTIES_COMMENT.sub(_spaces, text),
    ".yml": _yaml,
    ".yaml": _yaml,
}


def mask(file: FileText) -> FileText:
    """`file` with the text no code runs through blanked; a file type without a mask comes back as it is."""
    step = _MASKS.get(file.suffix)
    return file if step is None else replace(file, text=step(file.text))
