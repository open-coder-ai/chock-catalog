"""Render chock-catalog's logo and GitHub social preview card.

Run from this directory:

    pip install cairosvg pyyaml      # asset tooling only
    python gen_brand_assets.py

Writes logo.svg/logo-512.png (512x512) and social-preview.svg/.png (1280x640, GitHub's
social-preview size) beside this file.

Every policy id, pack name and count on the card is READ FROM registry.yaml at render
time -- the same file chock resolves against. A social preview is a claim surface, and
this catalog's whole proposition is that a policy is labelled by what it actually
enforces, so the card must not carry a second, hand-typed copy of that. Counts printed
beside each list are len() of that list, and an over-long row raises rather than running
silently out of its panel.

The mark is a policy card carrying its enforcing node, stacked on the ones behind it.
Until now this repo shipped chock's wheel-and-wedge logo byte for byte, alt text
included, so it had no identity of its own.
"""

import pathlib
import sys

import yaml
from brandkit import (
    GOLD,
    LOGO_SIZE,
    H,
    W,
    card,
    check,
    diamond,
    logo_svg,
    write,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]


def catalog_mark(cx, cy, s):
    """A stack of policy cards, the top one carrying its enforcing node.

    Widths taper downward so it reads as depth rather than three equal bars, which read
    as a menu icon.
    """
    sw = s * 0.034
    parts = []
    for dy, wf, op in ((0.20, 0.40, 0.34), (0.05, 0.48, 0.55)):
        bw, bh = s * wf, s * 0.075
        parts.append(
            f'<rect x="{cx - bw / 2:.1f}" y="{cy + s * dy - bh / 2:.1f}" width="{bw:.1f}" '
            f'height="{bh:.1f}" rx="{bh * 0.34:.1f}" fill="none" stroke="{GOLD}" '
            f'stroke-width="{sw:.2f}" stroke-opacity="{op:.2f}"/>'
        )
    bw, bh = s * 0.56, s * 0.20
    parts.append(
        f'<rect x="{cx - bw / 2:.1f}" y="{cy - s * 0.16 - bh / 2:.1f}" width="{bw:.1f}" '
        f'height="{bh:.1f}" rx="{s * 0.045:.1f}" fill="none" stroke="{GOLD}" '
        f'stroke-width="{sw * 1.5:.2f}" stroke-opacity="0.95"/>'
    )
    parts.append(diamond(cx - bw / 2 + s * 0.085, cy - s * 0.16, s * 0.048))
    for k in (0, 1):
        ly = cy - s * 0.16 - s * 0.035 + k * s * 0.07
        parts.append(
            f'<line x1="{cx - bw / 2 + s * 0.165:.1f}" y1="{ly:.1f}" '
            f'x2="{cx + bw / 2 - s * 0.055 - k * s * 0.10:.1f}" y2="{ly:.1f}" stroke="{GOLD}" '
            f'stroke-width="{sw:.2f}" stroke-opacity="0.55" stroke-linecap="round"/>'
        )
    return "\n  ".join(parts)


REGISTRY = yaml.safe_load((ROOT / "registry.yaml").read_text(encoding="utf-8"))
POLICIES = REGISTRY["policies"]
PACKS = {}
for policy in POLICIES:
    PACKS.setdefault(policy["path"].split("/")[0], []).append(policy)
BLOCKING = [p["id"] for p in POLICIES if p.get("enforcement") == "block"]
AT_COMMIT = [p for p in POLICIES if p.get("enforces") == "enforced-at-commit"]
#: The same three-word set `tools/gen_coverage_matrix.py` buckets together, for the same
#: reason: `enforced`/`enforceable`/`best-effort` are agentseam's per-agent vocabulary and all
#: three are a real, installed, in-agent pre-execution control. Matched on the FIRST WORD of
#: the `enforces` string rather than a `startswith("enforced (pre-tool-use")` prefix -- that
#: prefix silently stopped matching the moment a policy was regraded to `best-effort
#: (pre-tool-use, ...)`, dropping seven policies out of both this list and ADVISORY, which is
#: what the assertion below then caught. Two files classify the same field; they now agree.
IN_AGENT_WORDS = {"enforced", "enforceable", "best-effort"}
PRE_TOOL = [
    p
    for p in POLICIES
    if str(p.get("enforces", "")).split(" ", 1)[0] in IN_AGENT_WORDS
    and "pre-tool-use" in str(p.get("enforces", ""))
]
ADVISORY = [p for p in POLICIES if p.get("enforces") == "advisory"]
N_ENFORCED = len(AT_COMMIT) + len(PRE_TOOL)
EVAL_CASES = sum(p.get("eval_cases", 0) for p in POLICIES)
assert len(ADVISORY) + N_ENFORCED == len(POLICIES), (
    "a policy is graded with a word this card does not know"
)

# The OWASP rows drop the shared "owasp-" prefix the column header already states, and
# nothing else: these stay the ids you can pass to chock add.
OWASP = [p["id"] for p in POLICIES if p["id"].startswith("owasp-asi")]
OWASP_ROWS = [i[len("owasp-") :] for i in sorted(OWASP)]
OWASP_ROWS = [r.replace("-communication", "-comms") for r in OWASP_ROWS]

ALT = (
    "chock-catalog — the policy catalog for chock: policies you can adopt, graded by what they "
    f"actually enforce. {len(POLICIES)} policies across {len(PACKS)} packs ("
    + ", ".join(f"{name} {len(items)}" for name, items in sorted(PACKS.items()))
    + f"); {N_ENFORCED} enforced ({len(AT_COMMIT)} at commit, {len(PRE_TOOL)} at pre-tool-use) "
    f"and {len(ADVISORY)} advisory; {EVAL_CASES} eval cases. "
    f"The {len(BLOCKING)} blocking policies: " + ", ".join(sorted(BLOCKING)) + ". "
    "Full OWASP Agentic Security Initiative top ten coverage, ASI01 through ASI10. Apache-2.0."
)
#: The hero image sits in the most prominent slot on the page, and its alt text is what a
#: crawler or an LLM retriever reads there -- so it states what the project IS before it
#: describes what the mark depicts. A purely decorative label spends that slot on nothing.
LOGO_ALT = (
    "chock-catalog: the policy catalog for chock -- policies you can adopt, graded by what "
    "they actually enforce. The mark is a stack of policy cards, the top one carrying the "
    "node that marks an enforcing policy."
)

CARD = card(
    name="chock-catalog",
    repo="open-coder-ai/chock-catalog",
    pill=f"{len(POLICIES)} POLICIES · APACHE-2.0",
    badge_art=catalog_mark(64, 58, 38),
    eyebrow="— THE POLICY CATALOG",
    head1="Policies you can adopt,",
    head2="graded by what they do.",
    blurb=[
        "Every policy states the strongest control it can",
        "actually install, and carries its own eval suite.",
        f"Of these, {len(BLOCKING)} block. The rest say so.",
    ],
    api_label="ADOPT ONE",
    api_lines=["chock add owasp-asi02-tool-misuse", "chock sync"],
    extras=[
        (name.upper().replace("-", " "), f"{len(items)} policies")
        for name, items in sorted(PACKS.items(), key=lambda kv: -len(kv[1]))
    ],
    motto="A POLICY THAT ONLY ADVISES IS LABELLED ADVISORY",
    columns=[[("BLOCKING", sorted(BLOCKING))], [("OWASP ASI", OWASP_ROWS)]],
    stats=[
        (str(len(POLICIES)), "POLICIES"),
        (str(N_ENFORCED), "ENFORCED"),
        (str(EVAL_CASES), "EVAL CASES"),
        (str(len(PACKS)), "PACKS"),
    ],
    right_foot="APACHE-2.0 · open-coder-ai/chock-catalog",
    alt=ALT,
)

if __name__ == "__main__":
    LOGO = logo_svg(
        catalog_mark(LOGO_SIZE / 2, LOGO_SIZE / 2, LOGO_SIZE * 0.78), LOGO_ALT
    )
    if "--check" in sys.argv:
        problems = check(LOGO, "logo") + check(CARD, "social-preview")
        if problems:
            print("\n".join(problems))
            print(
                "\nThe card is derived from registry.yaml, so this means the catalog "
                "changed.\nRegenerate it:  python docs/assets/gen_brand_assets.py"
            )
            raise SystemExit(1)
        print("logo.svg and social-preview.svg are current")
        raise SystemExit(0)
    write(LOGO, "logo", LOGO_SIZE, LOGO_SIZE, png_stem="logo-512")
    write(CARD, "social-preview", W, H)
    print(
        f"rendered: {len(POLICIES)} policies, {N_ENFORCED} enforced, {EVAL_CASES} eval cases"
    )
