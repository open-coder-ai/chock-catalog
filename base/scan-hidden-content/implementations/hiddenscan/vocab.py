"""The policy's data table (allowlist, vocabulary, marker comments) and the text normalising its matches use."""

from __future__ import annotations

import html
import re
import unicodedata
from functools import cache
from pathlib import Path

from chock_scan.data_table import load
from chock_scan.hostmatch import matches, parse_entry

TABLE = Path(__file__).resolve().parents[1] / "data" / "hidden-content.json"
KEYS = (
    "allowed_hosts",
    "camo_hosts",
    "imperative_words",
    "override_phrases",
    "key_paths",
    "secret_nouns",
    "marker_comments",
)
HEX_COLOUR = re.compile(r"#[0-9a-f]{6}")
#: Past this, a comment counts as long whatever it says (roadmap NP01 (b)).
LONG_COMMENT = 200
SPACES = re.compile(r"\s+")
CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
WORDS = re.compile(r"[^A-Za-z0-9]+")


def _strings(doc: dict) -> list[str]:
    bad = [k for k in KEYS if not (isinstance(doc[k], list) and doc[k] and all(isinstance(v, str) for v in doc[k]))]
    out = [f"{k} must be a non-empty list of strings" for k in bad]
    colours = doc["css_colours"]
    if not isinstance(colours, dict) or not colours or not all(HEX_COLOUR.fullmatch(str(v)) for v in colours.values()):
        out.append("css_colours must map names to #rrggbb")
    return out


class Vocab:
    """The table, compiled once: a malformed table raises, which the runner reads as undecided."""

    def __init__(self, doc: dict) -> None:
        self.allowed = tuple(parse_entry(v) for v in doc["allowed_hosts"])
        self.colours: dict[str, str] = dict(doc["css_colours"])
        self.camo = tuple(parse_entry(v) for v in doc["camo_hosts"])
        self.secret_nouns = frozenset(doc["secret_nouns"])
        words = "|".join(map(re.escape, doc["imperative_words"]))
        self.imperative = re.compile(rf"(?<![a-z0-9_-])(?:{words})(?![a-z0-9_-])")
        self.override = re.compile("|".join(f"(?:{p})" for p in doc["override_phrases"]))
        self.key_paths = tuple(doc["key_paths"])
        self.marker = re.compile("|".join(f"(?:{p})" for p in doc["marker_comments"]))

    def allowed_host(self, host: object) -> bool:
        return any(matches(host, entry) for entry in self.allowed)

    def camo_host(self, host: object) -> bool:
        return any(matches(host, entry) for entry in self.camo)

    def instruction(self, body: str) -> str | None:
        """Why a comment body reads as an instruction, or None: a marker comment never does."""
        text = normalized(body)
        if self.marker.fullmatch(text):
            return None
        if hit := self.override.search(text):
            return f"override wording '{hit.group(0).strip()}'"
        if hit := self.imperative.search(text):
            return f"imperative '{hit.group(0)}'"
        if path := next((p for p in self.key_paths if p in text), None):
            return f"key or env path '{path}'"
        if len(text) > LONG_COMMENT:
            return f"{len(text)} characters long"
        return None

    def secret_words(self, text: str) -> list[str]:
        """The secret nouns among the words of `text`, split on punctuation and camelCase."""
        words = WORDS.split(CAMEL.sub(" ", text))
        return sorted({w.lower() for w in words if w.lower() in self.secret_nouns})


@cache
def vocab() -> Vocab:
    return Vocab(load(TABLE, kind="curated", schema=1, keys=(*KEYS, "css_colours"), check=_strings))


def visible(text: str) -> str:
    """`text` without format characters (Cf): zero-width joiners and the like are HP15's to report,
    and must not split a word here."""
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def normalized(text: str) -> str:
    """Entities decoded, format characters dropped, NFKC, case folded, whitespace collapsed."""
    text = unicodedata.normalize("NFKC", visible(html.unescape(text)))
    return SPACES.sub(" ", text).strip().casefold()
