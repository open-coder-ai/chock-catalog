"""Every catalog eval suite, installed as `chock add` installs it, holds no allow case that scan-secrets-prompt refuses.

`chock add` copies a policy folder verbatim, so an adopter holds each suite. The gate runs only at
prompt_submit, never at commit, so the installed suite files are not judged here; what is replayed is the
text of each case a suite says is allowed (file contents, writes, command, prompt), read as a prompt. A
credential-shaped value in an allow case would be a person's text this policy refuses.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from policies import scriptkit
from trees import policy_dirs

PATTERN = re.compile(scriptkit.manifest("scan-secrets-prompt")["hook"]["gate"]["params"]["content_pattern"])
SUITED = [d for d in policy_dirs() if (d / "evals" / "suite.yaml").is_file()]


def texts(execute: dict) -> list[str]:
    """Every string a case hands its gate as text."""
    found = [
        v for k in ("files", "writes", "added", "head_files", "repo_files") for v in (execute.get(k) or {}).values()
    ]
    found += [execute[k] for k in ("command", "prompt", "message") if isinstance(execute.get(k), str)]
    return [t for t in found if isinstance(t, str)]


def allowed_texts(policy_dir: Path) -> list[str]:
    cases = yaml.safe_load((policy_dir / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]["cases"]
    return [t for c in cases if (c.get("execute") or {}).get("expect") == "allow" for t in texts(c["execute"])]


def test_every_catalog_suite_is_replayed() -> None:
    assert len(SUITED) >= 70


@pytest.mark.parametrize("policy_dir", SUITED, ids=[d.name for d in SUITED])
def test_no_allow_case_text_is_refused_as_a_prompt(policy_dir: Path) -> None:
    refused = [t for t in allowed_texts(policy_dir) if PATTERN.search(t)]
    assert refused == []
