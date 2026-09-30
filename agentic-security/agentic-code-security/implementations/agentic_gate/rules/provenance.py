"""The provenance pack (EU AI Act Art. 50): a change that strips the marking of AI-generated content."""

from __future__ import annotations

from collections.abc import Iterator

from agentic_gate.model import FileText, Hit, Pack, Rule

PACK = Pack(
    id="provenance",
    title="Content provenance",
    covers="C2PA, Content Credentials, SynthID and AI-generated markers a file carried at HEAD.",
)

MARKERS = (
    "c2pa",
    "content_credentials",
    "synthid",
    "ai_generated",
    "x-ai-generated",
    "digitalSourceType",
    "trainedAlgorithmicMedia",
)


def present(body: str) -> set[str]:
    """The markers a text mentions, whatever their case."""
    lowered = body.lower()
    return {marker for marker in MARKERS if marker.lower() in lowered}


def _removed(text: FileText) -> Iterator[Hit]:
    """A file that had markers at HEAD and has none now, unless another written file took them."""
    if text.head is None:
        return
    before, after = present(text.head), present(text.text)
    if not before or after:
        return
    moved = set().union(*(present(other) for other in text.others))
    if lost := sorted(before - moved):
        yield Hit(
            1,
            f"this change removes every provenance marker the file carried at HEAD ({', '.join(lost)}).",
            by_diff=True,
        )


RULES: tuple[Rule, ...] = (
    Rule(
        id="provenance-marker-removed",
        pack="provenance",
        title="Provenance marker removed",
        why="Article 50 of the EU AI Act requires machine-readable marking of AI-generated content; stripping the marker removes it without anyone deciding to.",
        kinds=("python", "js", "json", "yaml", "toml", "shell", "dockerfile", "env", "other"),
        scan=_removed,
        fix="keep the marker, or move it to the file that now does the marking in the same change; only a person waives this, in the selection file.",
        refuses="a written file whose HEAD version held c2pa, content_credentials, synthid, ai_generated, x-ai-generated, digitalSourceType or trainedAlgorithmicMedia and whose new version holds none, when no other written file carries the marker",
        silent_on="a file that keeps one marker, a marker moved to another file in the same change, a new file",
        asi=(),
        references=(
            "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
            "https://c2pa.org/specifications/specifications/2.1/index.html",
        ),
    ),
)
