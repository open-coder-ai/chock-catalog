#!/usr/bin/env bash
set -euo pipefail
# Generated from README.md's Quick start block by tools/gen_quickstart_sh.py -- do not edit by hand.

pip install chock

git init -q demo && cd demo
chock init .
chock add scan-secrets
chock sync --repo .
