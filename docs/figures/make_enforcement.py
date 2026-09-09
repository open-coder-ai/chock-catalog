"""Enforcement coverage across the catalog: one stacked bar, three tiers, real counts."""

import re
from pathlib import Path

import palette as p

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry.yaml"

W, H = 760, 246
BAR_X, BAR_Y, BAR_W, BAR_H = 40, 96, 680, 72

# registry.yaml is the checker-verified aggregation of every policy's manifest.yaml --
# tools/check_registry.py fails CI the moment its `enforces` label stops matching the
# manifest it describes. Generators here are stdlib-only (the `figures` CI job installs
# nothing beyond Python itself), so this reads registry.yaml as the flat, one-entry-per-line
# records it actually is rather than pulling in a YAML parser for one field.
IN_AGENT_WORDS = ("enforced", "enforceable", "best-effort")

TIERS = (
    # (label, enforces-classifier, enforcement colour index -- strongest last)
    ("enforced at commit", lambda w: w == "enforced-at-commit", 2),
    ("in-agent", lambda w: w.startswith(IN_AGENT_WORDS), 1),
    ("advisory", lambda w: True, 0),
)


def read_counts():
    """(count, label, colour_index) per tier, strongest first, from registry.yaml itself."""
    text = REGISTRY.read_text(encoding="utf-8")
    entries = re.findall(r"^- id: \S+.*?(?=\n- id: |\Z)", text, re.MULTILINE | re.DOTALL)
    if not entries:
        raise SystemExit(f"no policies found in {REGISTRY}")
    counts = {label: 0 for label, _, _ in TIERS}
    for entry in entries:
        found = re.search(r"^\s*enforces:\s*(.+)$", entry, re.MULTILINE)
        if not found:
            raise SystemExit(f"policy entry has no 'enforces' label:\n{entry[:80]}")
        word = found.group(1).strip()
        for label, matches, _ in TIERS:
            if matches(word):
                counts[label] += 1
                break
    return [(counts[label], label, idx) for label, _, idx in TIERS]


def render(t, name):
    counts = read_counts()
    total = sum(n for n, _, _ in counts)

    enforced_at_commit, in_agent, advisory = (n for n, _, _ in counts)
    svg = p.open_svg(
        W, H, t,
        "Chock-catalog enforcement coverage",
        f"Of {total} chock-catalog policies, {enforced_at_commit} are enforced at commit and "
        f"{in_agent} more are enforced in-agent, for {enforced_at_commit + in_agent} enforced "
        f"overall -- {advisory}, more than half, are advisory only, read by the agent but "
        "backed by no mechanism.",
    )

    svg += p.text(
        BAR_X, 40, f"{total} policies, by what actually enforces them",
        t["text"], 18, weight="600",
    )
    svg += p.text(
        BAR_X, 64,
        "strongest → weakest, left to right — colour is never the only signal",
        t["secondary"], 12,
    )

    x = BAR_X
    for count, label, colour_idx in counts:
        seg_w = round(BAR_W * count / total)
        fill = t["enforcement"][colour_idx]
        svg += p.box(x, BAR_Y, seg_w - p.GAP, BAR_H, fill, rx=p.CORNER)

        # Advisory is the lightest fill, so its label reads in dark text; the two
        # enforced/in-agent fills are dark enough that the label has to be the surface
        # colour instead. Colour never carries the count or the tier name alone.
        on_fill = t["text"] if colour_idx == 0 else t["surface"]
        cx = x + (seg_w - p.GAP) / 2
        svg += p.text(cx, BAR_Y + 30, str(count), on_fill, 26, weight="700", anchor="middle")
        for i, line in enumerate(p.wrap(label.upper(), max(6, int((seg_w - 16) / 6.6)))):
            svg += p.text(
                cx, BAR_Y + 48 + i * 13, line, on_fill, 11, weight="600", anchor="middle",
            )
        x += seg_w

    legend_y = BAR_Y + BAR_H + 34
    svg += p.text(
        BAR_X, legend_y,
        f"{enforced_at_commit + in_agent} enforced ({enforced_at_commit} at commit + "
        f"{in_agent} in-agent) — {advisory} advisory, the largest slice",
        t["secondary"], 13,
    )
    svg += p.text(
        BAR_X, legend_y + 22,
        "counts read from registry.yaml at generation time; the CI job below fails if this "
        "ever drifts from it",
        t["secondary"], 11,
    )

    return svg + p.close_svg()


if __name__ == "__main__":
    for path in p.write_pair("enforcement", render):
        print("wrote", path)
