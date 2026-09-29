"""provenance pack: a change that removes the marking a file carried at HEAD."""

from __future__ import annotations

from agentic_code_security.cases.case import Case

MANIFEST_HEAD = '{"claim_generator": "acme", "digitalSourceType": "trainedAlgorithmicMedia", "title": "cover"}\n'
SIGNER_HEAD = "from c2pa import Builder\n\n\ndef sign(image):\n    return Builder(manifest).sign(image)\n"
REFUSED = [
    Case(
        "provenance-marker-removed",
        "assets/manifest.json",
        '{"claim_generator": "acme", "title": "cover"}\n',
        "drops digitalSourceType from an asset manifest",
        MANIFEST_HEAD,
    ),
    Case(
        "provenance-marker-removed",
        "media/sign.py",
        "def sign(image):\n    return image\n",
        "stops signing with C2PA",
        SIGNER_HEAD,
    ),
]
SILENT = [
    Case(
        "provenance-marker-removed",
        "assets/manifest.json",
        '{"claim_generator": "acme2", "digitalSourceType": "trainedAlgorithmicMedia", "title": "cover"}\n',
        "edits the manifest and keeps its marker",
        MANIFEST_HEAD,
    ),
    Case(
        "provenance-marker-removed",
        "media/sign.py",
        "def sign(image):\n    return image\n",
        "rewrites a file that never carried a marker",
        "def sign(image):\n    return None\n",
    ),
    Case(
        "provenance-marker-removed",
        "media/new.py",
        "def sign(image):\n    return image\n",
        "adds a file that has no HEAD version",
    ),
]
