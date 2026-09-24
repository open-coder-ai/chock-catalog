#!/usr/bin/env python3
"""Write the java-security setup contract -- the packs and rules the guided page shows -- from the registry.

The page and `references/setup-contract.json` carry each rule's own texts, and an agent reading
either decides from them, so neither is typed by hand: this renders both from the registry the
gate runs, and `--check` fails when either has drifted from it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "base" / "java-security"
SKILL = POLICY / "skill"
PAGE = SKILL / "setup.html"
REFERENCE = SKILL / "references" / "setup-contract.json"

sys.path.insert(0, str(POLICY / "implementations"))
from chock_security.rules import packs, registry  # noqa: E402

_EMBEDDED = re.compile(r'(<script type="application/json" id="contract">)(.*?)(</script>)', re.S)


def contract() -> dict:
    """The reference contract with its packs and rules replaced by the registry's own."""
    document = json.loads(REFERENCE.read_text(encoding="utf-8"))
    document["packs"] = [{"id": p.id, "title": p.title, "covers": p.covers} for p in packs().values()]
    document["rules"] = [
        {"id": r.id, "pack": r.pack, "title": r.title, "refuses": r.refuses, "silent_on": r.silent_on,
         "constraint": r.constraint}
        for r in registry().values()
    ]
    # Keys in a fixed order, so the diff a rule change produces is the rule, not a reshuffle.
    order = ["version", "agent", "layers", "packs", "rules"]
    return {k: document[k] for k in order if k in document} | {k: v for k, v in document.items() if k not in order}


def rendered() -> tuple[str, str]:
    """(reference file text, page text) as they must read."""
    document = contract()
    reference = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    embedded = json.dumps(document, ensure_ascii=False).replace("</", "<\\/")
    page = PAGE.read_text(encoding="utf-8")
    page, count = _EMBEDDED.subn(lambda m: m.group(1) + embedded + m.group(3), page, count=1)
    if count != 1:
        msg = f"{PAGE} carries no #contract element"
        raise SystemExit(msg)
    return reference, page


def main(argv: list[str]) -> int:
    reference, page = rendered()
    targets = {REFERENCE: reference, PAGE: page}
    if "--check" in argv:
        stale = [str(path.relative_to(ROOT)) for path, text in targets.items() if path.read_text(encoding="utf-8") != text]
        if stale:
            print(f"java-security contract is stale: {', '.join(stale)}; run python tools/gen_java_security_contract.py",
                  file=sys.stderr)
            return 1
        print("java-security contract matches the registry.")
        return 0
    for path, text in targets.items():
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(targets)} file(s): {len(registry())} rules in {len(packs())} packs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
