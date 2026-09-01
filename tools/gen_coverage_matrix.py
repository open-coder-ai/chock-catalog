#!/usr/bin/env python3
"""Generate docs/assets/coverage-matrix.svg from registry.yaml."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "docs" / "assets" / "coverage-matrix.svg"

BG = "#0f1420"
GRID = "#1a2130"
CREAM = "#f2ead8"
TEAL = "#3fd0b6"
GOLD = "#e0b34c"
DIM = "#8a93a6"
FAINT = "#5c6577"

SERIF = "Georgia, 'Times New Roman', serif"
MONO = "'Cascadia Code', Consolas, 'Courier New', monospace"

WORDS = {
    3: "Three", 5: "Five", 7: "Seven", 10: "Ten", 12: "Twelve", 15: "Fifteen",
    20: "Twenty",
}

COLUMNS = [
    ("ENFORCED-AT-COMMIT", TEAL, "the command exits non-zero — the commit does not happen"),
    ("IN-AGENT", TEAL, "the tool call is refused before it runs, if the hook itself runs"),
    ("ADVISORY", GOLD, "text an agent reads and may or may not follow"),
]

IN_AGENT_WORDS = {"enforced", "enforceable", "best-effort"}


def classify() -> list[list[str]]:
    reg = yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))
    cols: list[list[str]] = [[], [], []]
    for p in reg["policies"]:
        enforces = p.get("enforces", "")
        word = enforces.split(" ", 1)[0]
        if enforces == "enforced-at-commit" or word == "enforced-at-commit":
            cols[0].append(p["id"])
        elif word in IN_AGENT_WORDS:
            cols[1].append(p["id"])
        else:
            cols[2].append(p["id"])
    return [sorted(c) for c in cols]


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render() -> str:
    cols = classify()
    total = sum(len(c) for c in cols)
    word = WORDS.get(total, str(total))

    width = 1600
    col_x = [80, 576, 1072]
    col_w = 416
    list_y0 = 400
    row_h = 30
    tallest = max(len(c) for c in cols)
    quote_y = max(700, list_y0 + tallest * row_h + 90)
    height = quote_y + 200

    s: list[str] = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" '
        f'aria-label="{word} policies: {len(cols[0])} enforced-at-commit, '
        f'{len(cols[1])} in-agent, {len(cols[2])} advisory">'
    )
    s.append(f'<rect width="{width}" height="{height}" fill="{BG}"/>')
    for y in range(0, height + 1, 96):
        s.append(f'<line x1="0" y1="{y}" x2="{width}" y2="{y}" stroke="{GRID}" stroke-width="1"/>')

    s.append(
        f'<text x="80" y="78" font-family="{MONO}" font-size="17" letter-spacing="4" '
        f'fill="{GOLD}">CHOCK CATALOG &#183; ENFORCEMENT YOU CAN VERIFY</text>'
    )
    s.append(
        f'<text x="80" y="140" font-family="{SERIF}" font-size="46" font-weight="bold" '
        f'fill="{CREAM}">{word} policies. Only what&#8217;s actually true.</text>'
    )
    s.append(f'<line x1="80" y1="180" x2="{width - 80}" y2="180" stroke="{FAINT}" stroke-width="1"/>')

    for i, ((label, accent, blurb), ids) in enumerate(zip(COLUMNS, cols)):
        x = col_x[i]
        if i:
            s.append(
                f'<line x1="{x - 28}" y1="220" x2="{x - 28}" y2="{list_y0 + tallest * row_h}" '
                f'stroke="{FAINT}" stroke-width="1"/>'
            )
        s.append(
            f'<text x="{x}" y="278" font-family="{SERIF}" font-size="58" font-weight="bold" '
            f'fill="{accent}">{len(ids)}</text>'
        )
        s.append(
            f'<text x="{x + 58}" y="258" font-family="{MONO}" font-size="17" letter-spacing="3" '
            f'fill="{CREAM}">{label}</text>'
        )
        words, lines, line = blurb.split(), [], ""
        for w in words:
            if len(line) + len(w) + 1 > 46:
                lines.append(line)
                line = w
            else:
                line = f"{line} {w}".strip()
        lines.append(line)
        for j, text in enumerate(lines):
            s.append(
                f'<text x="{x}" y="{330 + j * 24}" font-family="{SERIF}" font-size="17" '
                f'fill="{DIM}">{_esc(text)}</text>'
            )
        s.append(
            f'<line x1="{x}" y1="{list_y0 - 22}" x2="{x + col_w}" y2="{list_y0 - 22}" '
            f'stroke="{FAINT}" stroke-width="1"/>'
        )
        for j, policy_id in enumerate(ids):
            y = list_y0 + j * row_h
            s.append(f'<rect x="{x}" y="{y - 11}" width="6" height="6" fill="{accent}"/>')
            s.append(
                f'<text x="{x + 18}" y="{y}" font-family="{MONO}" font-size="17" '
                f'fill="{CREAM}">{_esc(policy_id)}</text>'
            )

    s.append(
        f'<text x="80" y="{quote_y}" font-family="{SERIF}" font-size="30" '
        f'fill="{CREAM}">&#8220;A rule an agent reads is advice.</text>'
    )
    s.append(
        f'<text x="80" y="{quote_y + 44}" font-family="{SERIF}" font-size="30" '
        f'fill="{CREAM}">A hook that exits non-zero is a control.&#8221;</text>'
    )
    s.append(
        f'<text x="80" y="{height - 54}" font-family="{MONO}" font-size="15" letter-spacing="2" '
        f'fill="{FAINT}">APACHE-2.0</text>'
    )
    s.append(
        f'<text x="{width - 80}" y="{height - 54}" text-anchor="end" font-family="{MONO}" '
        f'font-size="15" letter-spacing="1" fill="{FAINT}">github.com/open-coder-ai/chock-catalog</text>'
    )
    s.append("</svg>")
    return "\n".join(s) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the coverage matrix image.")
    parser.add_argument("--check", action="store_true", help="Fail if the image is out of date.")
    args = parser.parse_args(argv)

    svg = render()
    if args.check:
        if not DEST.exists() or DEST.read_text(encoding="utf-8") != svg:
            print(f"{DEST.relative_to(ROOT).as_posix()} is out of date.")
            print("Run `python tools/gen_coverage_matrix.py` and commit the result.")
            return 1
        print("Coverage matrix matches the registry.")
        return 0

    DEST.write_text(svg, encoding="utf-8", newline="\n")
    print(f"Wrote {DEST.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
