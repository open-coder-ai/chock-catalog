"""GitHub social preview card: name, one line, one true number. Light theme only."""

import palette as p
from make_enforcement import read_counts

W, H = 1280, 640
DEST_SVG = "social-card.svg"
DEST_PNG = "social-card.png"


def render():
    t = p.theme("light")
    counts = read_counts()
    total = sum(n for n, _, _ in counts)
    enforced = counts[0][0] + counts[1][0]

    svg = p.open_svg(
        W,
        H,
        t,
        "chock-catalog",
        f"chock-catalog: the policy catalog for chock. {enforced} of {total} policies are "
        "enforced, not just advised.",
    )
    svg += p.text(96, 280, "chock-catalog", t["text"], 76, p.MONO, "700")
    svg += p.text(
        96,
        336,
        "policies for coding agents, labelled by what actually enforces them",
        t["secondary"],
        26,
    )
    svg += p.box(96, 392, 4, 92, t["enforcement"][2], rx=0)
    svg += p.text(
        128,
        436,
        f"{enforced} of {total} policies enforced",
        t["text"],
        40,
        weight="700",
    )
    svg += p.text(128, 470, "not just advised", t["secondary"], 22)
    return svg + p.close_svg()


def main():
    svg = render()
    with open(DEST_SVG, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(svg)
    print("wrote", DEST_SVG)

    # PNG conversion needs cairosvg, which the `figures` CI job deliberately does not
    # install (see VISUAL.md: "nothing in CI may depend on it"). Locally, regenerate and
    # commit the PNG by hand after a change here; in CI this step is a silent no-op and
    # only the SVG participates in the drift check.
    try:
        import cairosvg
    except ImportError:
        print("cairosvg not installed; skipped regenerating", DEST_PNG)
        return
    cairosvg.svg2png(url=DEST_SVG, write_to=DEST_PNG, output_width=W, output_height=H)
    print("wrote", DEST_PNG)


if __name__ == "__main__":
    main()
