#!/usr/bin/env bash
set -euo pipefail
# Generated from README.md's Quick start block by tools/gen_quickstart_sh.py -- do not edit by hand.

pip install "chock @ git+https://github.com/open-coder-ai/chock@992711af4cf8d4fd9c4c861f10ef6e53374d75d7"

git init -q demo && cd demo
chock init .
chock add scan-secrets --ref 9a64623e30769c49d7011ec3f559592d84e3f657 --verify-sha 47ff46faf00e86089e79b868077ac2443e75bb879af7224190477d0c65e3360f --skip-compile
chock add protect-main-branch --ref 9a64623e30769c49d7011ec3f559592d84e3f657 --verify-sha 4b95801e6c9241c4e0bf2c031a2b36079d4ce4610b3c242d3e2905fb78eec82c --skip-compile
chock sync --repo . --ci
