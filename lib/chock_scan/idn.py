"""Internationalised domain names in ASCII form, through the stdlib IDNA2003 codec, refused wherever that
codec and the URL Standard's UTS 46 processing may disagree.

Limits: the stdlib codec is IDNA2003 on Unicode 3.2 tables. A name using a code point outside that
repertoire, a format character (Cf), or a deviation character is refused, not guessed; a name the
codec accepts but a URL Standard client rejects reaches nothing there. Flags come from an embedded
subset of lookalike letters and from unicodedata names, not from Unicode's confusables or Scripts data.
"""

from __future__ import annotations

import re
import unicodedata
from encodings import idna

#: Label separators the URL Standard maps to '.', as the stdlib codec also splits on.
DOTS = re.compile("[.\u3002\uff0e\uff61]")
#: Read as other letters by IDNA2003 (sharp s to "ss", final sigma to sigma, ZWJ/ZWNJ deleted) and kept
#: by UTS 46 nontransitional processing, which the URL Standard uses: two different hosts.
DEVIATIONS = frozenset("\u00df\u03c2\u200c\u200d")
#: Default_Ignorable_Code_Point letters and marks (the Cf ones are refused by category): UTS 46 deletes
#: them, IDNA2003 keeps some, so the two would name different hosts.
IGNORABLE = frozenset("\u034f\u115f\u1160\u17b4\u17b5\u180b\u180c\u180d\u180e\u180f\u3164\uffa0") | frozenset(
    map(chr, range(0xFE00, 0xFE10))
)
MAX_LABEL = 63
#: Categories no valid label holds (controls, surrogates, format, unassigned): UTS 46 rejects them.
UNNAMED = frozenset({"Cc", "Cs", "Cf", "Cn"})
UCD_3_2 = unicodedata.ucd_3_2_0

IDN = "idn"
MIXED_SCRIPT = "mixed-script"
CONFUSABLE = "confusable"

#: Letters other scripts draw like a Latin letter: a small subset of Unicode's confusables data,
#: lowercase only (labels are case-folded before this is consulted).
LOOKALIKES = frozenset(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u04bb\u04cf\u04af\u0501\u051b\u051d"  # Cyrillic
    "\u03b1\u03b5\u03b9\u03ba\u03bd\u03bf\u03c1\u03c4\u03c5\u03c7"  # Greek
    "\u0570\u0578\u057d\u0585"  # Armenian
    "\u0131\u0251\u0261\u026a\u1d0f"  # Latin letters outside ASCII drawn like ASCII ones
)
#: Script sets that legitimately share one label: Japanese and Korean writing mix Han with kana or hangul.
SHARED_SCRIPTS = (frozenset({"CJK", "HIRAGANA", "KATAKANA"}), frozenset({"CJK", "HANGUL"}))


class UnparseableError(ValueError):
    """No single host can be read from this input; callers fail closed (refuse, never allow)."""


def to_ascii(name: str) -> str:
    """`name` with every label in ASCII (A-label for non-ASCII), lowercase, joined by '.'.

    Labels are not validated beyond what the conversion needs; the caller checks the result.
    """
    return ".".join(_label(label) for label in DOTS.split(name))


def _label(label: str) -> str:
    if label.isascii():
        return label.lower()
    if len(label) > MAX_LABEL:
        msg = f"label longer than {MAX_LABEL} characters"
        raise UnparseableError(msg)
    for char in label:
        if (
            char in DEVIATIONS
            or char in IGNORABLE
            or unicodedata.category(char) == "Cf"
            or UCD_3_2.category(char) == "Cn"
        ):
            msg = f"U+{ord(char):04X}: the stdlib IDNA2003 codec and the URL Standard may read it differently"
            raise UnparseableError(msg)
    try:
        mapped = idna.nameprep(label)
        ascii_label = idna.ToASCII(label).decode("ascii")
    except UnicodeError as exc:
        msg = f"not a valid internationalised label ({exc})"
        raise UnparseableError(msg) from None
    # Unicode 3.2 mappings that later versions changed (corrected compatibility ideographs, case pairs
    # added since) give a different host than the URL Standard's current tables: refuse those, and a
    # label that maps to a dot or starts with a combining mark, which UTS 46 rejects.
    current = unicodedata.normalize("NFKC", unicodedata.normalize("NFKD", label).casefold())
    if mapped != current or "." in mapped or unicodedata.category(mapped[:1] or "a").startswith("M"):
        msg = f"{label!r}: Unicode 3.2 and current Unicode tables map this label differently"
        raise UnparseableError(msg)
    return ascii_label.lower()


def decode_alabel(label: str) -> str:
    """The Unicode form of an `xn--` label; invalid, ASCII-only, non-canonical or control-holding punycode raises."""
    body = label[4:]
    try:
        text = body.encode("ascii").decode("punycode")
    except UnicodeError:
        text = ""
    if (
        not text
        or text.isascii()
        or text.encode("punycode") != body.encode("ascii")
        or any(unicodedata.category(char) in UNNAMED for char in text)
    ):
        msg = f"'{label}' is not canonical punycode for a non-ASCII label"
        raise UnparseableError(msg)
    return text


def flags(labels: list[str]) -> frozenset[str]:
    """IDN for any `xn--` label, plus MIXED_SCRIPT and CONFUSABLE judged on each label's Unicode form."""
    found: set[str] = set()
    for label in labels:
        if not label.startswith("xn--"):
            continue
        text = decode_alabel(label)
        found.add(IDN)
        scripts = {_script(char) for char in text if unicodedata.category(char).startswith("L")}
        if len(scripts) > 1 and not any(scripts <= shared for shared in SHARED_SCRIPTS):
            found.add(MIXED_SCRIPT)
        letters = [char for char in text if unicodedata.category(char).startswith("L")]
        if any(c in LOOKALIKES for c in letters) and all(c.isascii() or c in LOOKALIKES for c in letters):
            found.add(CONFUSABLE)
    return frozenset(found)


def _script(char: str) -> str:
    """The script a letter's Unicode name starts with (LATIN, CYRILLIC, CJK, ...): an approximation."""
    return unicodedata.name(char, "UNNAMED").split(" ", 1)[0]
