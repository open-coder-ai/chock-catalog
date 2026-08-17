#!/usr/bin/env bash
# Repo-local (this repo only): fast catalog conformance at commit time. CI re-runs the
# same tools on the pinned engine as the authority, plus everything too slow for a
# hook. Skips with a warning when python is absent -- the CI backstop makes that honest.
set -eu

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

py=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c "import yaml" >/dev/null 2>&1; then
        py="$c"
        break
    fi
done
if [[ -z "$py" ]]; then
    echo "[WARN] conformance: no python with pyyaml on PATH; skipping (CI will run the checks)" >&2
    exit 0
fi

fail=0
for tool in check_registry check_readme check_console check_workflows; do
    echo "== conformance: $tool"
    "$py" "tools/$tool.py" || fail=1
done

if [[ "$fail" -ne 0 ]]; then
    echo "BLOCKED: catalog conformance failed -- fix the source, never the check. CI runs the same tools on the pinned engine." >&2
fi
exit "$fail"
