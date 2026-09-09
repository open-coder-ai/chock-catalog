"""The open-coder-ai family: what each repository is, and what feeds what."""

import palette as p

W, H = 800, 420
NAME, ROLE = 13, 11

ROLES = {
    "agentseam": "the primitives — one handler API and a verified capability matrix across 16 agents",
    "chock": "the compiler — one policy into git hooks, CI gates and native pre-tool hooks",
    "chock-catalog": "the policies — 39, each labelled enforced or advisory, with replayed evals",
    "context-report": "the evidence — a signed report of whether an agent artifact actually works",
    "chock-threat-intel": "the threat ledger the catalog's policies answer to",
    "plugins": "the catalog, packaged for each agent's plugin format (generated)",
}
PLUGINS = ["chock-claude-plugins", "chock-cursor-plugins", "chock-copilot-plugins", "chock-codex-plugins"]


def _block(x, y, w, h, name, role, t, filled, chars):
    """A repository: monospace identifier, wrapped role beneath it."""
    accent = t["enforcement"][1]
    out = p.box(x, y, w, h, accent if filled else t["surface"], None if filled else accent)
    label = t["surface"] if filled else t["text"]
    body = t["surface"] if filled else t["secondary"]
    out += p.text(x + 12, y + 22, name, label, NAME, p.MONO, "600")
    for i, line in enumerate(p.wrap(role, chars)):
        out += p.text(x + 12, y + 40 + i * 15, line, body, ROLE)
    return out


def render(t, name):
    a = t["enforcement"][1]
    svg = p.open_svg(
        W, H, t,
        "The open-coder-ai family",
        "A layered diagram. agentseam is the foundation across the bottom; chock sits on it; "
        "chock-catalog feeds chock and generates the four plugin repositories; chock-threat-intel "
        "feeds the catalog; context-report runs as a verification arm beside all of them.",
    )

    svg += _block(24, 24, 262, 72, "chock-threat-intel", ROLES["chock-threat-intel"], t, False, 34)

    svg += p.box(314, 24, 262, 72, t["surface"], t["neutral"])
    svg += p.text(326, 44, "plugin repositories", t["text"], NAME, p.MONO, "600")
    for i, line in enumerate(p.wrap(ROLES["plugins"], 34)):
        svg += p.text(326, 62 + i * 15, line, t["secondary"], ROLE)

    svg += p.arrow(155, 96, 155, 122, a)
    svg += p.arrow(445, 122, 445, 96, a)

    svg += _block(24, 124, 552, 74, "chock-catalog", ROLES["chock-catalog"], t, True, 74)
    svg += p.arrow(300, 198, 300, 224, a)
    svg += _block(24, 226, 552, 74, "chock", ROLES["chock"], t, True, 74)
    svg += p.arrow(300, 328, 300, 302, a)
    svg += _block(24, 330, 552, 74, "agentseam", ROLES["agentseam"], t, True, 74)

    svg += p.box(596, 24, 180, 380, t["surface"], a)
    svg += p.text(608, 46, "context-report", t["text"], NAME, p.MONO, "600")
    for i, line in enumerate(p.wrap(ROLES["context-report"], 22)):
        svg += p.text(608, 68 + i * 15, line, t["secondary"], ROLE)
    svg += p.text(608, 390, "measures all four", t["secondary"], ROLE)
    for y in (140, 242, 346):
        svg += p.arrow(592, y, 580, y, a)

    return svg + p.close_svg()


if __name__ == "__main__":
    for path in p.write_pair("family", render):
        print("wrote", path)
