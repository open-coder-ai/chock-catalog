"""The rule table (id, pack, verdict tier, CWE, OWASP CI/CD risk, the tool rule it mirrors) and the file runner."""

from __future__ import annotations

import re
from typing import NamedTuple

from ghascan import r_hygiene, r_injection, r_perms, r_secrets, r_supply, r_triggers
from ghascan.model import ACTION, DEPENDABOT, WORKFLOW, Ctx, Hit, triggers, typed_inputs
from ghascan.tree import UnreadableError, documents

BLOCK, ASK = "block", "ask"
UNREADABLE = "gha-unreadable"
WORKFLOW_PATH = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE)
ACTION_PATH = re.compile(r"(?:^|/)action\.ya?ml$", re.IGNORECASE)
DEPENDABOT_PATH = re.compile(r"(?:^|/)\.github/dependabot\.ya?ml$", re.IGNORECASE)


class Rule(NamedTuple):
    pack: str
    tier: str
    cwe: str
    cicd: str
    mirrors: str


RULES = {
    "gha-unreadable": Rule("hygiene", BLOCK, "CWE-20", "CICD-SEC-1", "trap 15: an unparseable security config is refused"),
    "gha-template-injection": Rule("injection", BLOCK, "CWE-94", "CICD-SEC-4", "zizmor template-injection; actionlint expression"),
    "gha-github-env-injection": Rule("injection", BLOCK, "CWE-94", "CICD-SEC-4", "zizmor github-env"),
    "gha-insecure-commands": Rule("injection", BLOCK, "CWE-94", "CICD-SEC-7", "zizmor insecure-commands; actionlint deprecated-commands; CKV_GHA_1"),
    "gha-dangerous-trigger": Rule("triggers", ASK, "CWE-829", "CICD-SEC-4", "zizmor dangerous-triggers"),
    "gha-prt-head-checkout": Rule("triggers", BLOCK, "CWE-829", "CICD-SEC-4", "Scorecard Dangerous-Workflow"),
    "gha-workflow-run-artifact": Rule("triggers", BLOCK, "CWE-829", "CICD-SEC-9", "GitHub Security Lab, preventing pwn requests (part 1)"),
    "gha-self-hosted-pr": Rule("triggers", BLOCK, "CWE-250", "CICD-SEC-7", "zizmor self-hosted-runner"),
    "gha-bot-conditions": Rule("triggers", BLOCK, "CWE-290", "CICD-SEC-1", "zizmor bot-conditions"),
    "gha-excessive-permissions": Rule("permissions", BLOCK, "CWE-250", "CICD-SEC-5", "zizmor excessive-permissions; Scorecard Token-Permissions; CKV2_GHA_1"),
    "gha-agent-step-untrusted": Rule("agents", BLOCK, "CWE-94", "CICD-SEC-4", "roadmap I04; OWASP LLM01"),
    "gha-secrets-inherit": Rule("secrets", BLOCK, "CWE-269", "CICD-SEC-5", "zizmor secrets-inherit"),
    "gha-overprovisioned-secrets": Rule("secrets", BLOCK, "CWE-200", "CICD-SEC-6", "zizmor overprovisioned-secrets"),
    "gha-secret-echo": Rule("secrets", BLOCK, "CWE-532", "CICD-SEC-6", "GitHub secure-use guide, using secrets"),
    "gha-artipacked": Rule("secrets", ASK, "CWE-522", "CICD-SEC-6", "zizmor artipacked"),
    "gha-checkout-token-pat": Rule("secrets", ASK, "CWE-522", "CICD-SEC-6", "GitHub secure-use guide (persist-credentials)"),
    "gha-container-credentials": Rule("secrets", BLOCK, "CWE-798", "CICD-SEC-6", "zizmor hardcoded-container-credentials; actionlint credentials"),
    "gha-trusted-publishing": Rule("secrets", ASK, "CWE-522", "CICD-SEC-6", "zizmor use-trusted-publishing"),
    "gha-static-cloud-keys": Rule("secrets", ASK, "CWE-522", "CICD-SEC-6", "GitHub secure-use guide, OIDC"),
    "gha-cache-poisoning": Rule("supply", BLOCK, "CWE-349", "CICD-SEC-9", "zizmor cache-poisoning"),
    "gha-dependabot-weaken": Rule("supply", BLOCK, "CWE-829", "CICD-SEC-3", "zizmor dependabot-execution"),
    "gha-dependabot-cooldown": Rule("supply", ASK, "CWE-829", "CICD-SEC-3", "zizmor dependabot-cooldown"),
    "gha-unsound-condition": Rule("hygiene", ASK, "CWE-670", "CICD-SEC-1", "zizmor unsound-condition, unsound-contains"),
    "gha-security-step-weakened": Rule("hygiene", ASK, "CWE-693", "CICD-SEC-1", "roadmap I07"),
    "gha-obfuscation": Rule("hygiene", ASK, "CWE-506", "CICD-SEC-1", "zizmor obfuscation"),
    "gha-auto-merge-bot": Rule("hygiene", ASK, "CWE-345", "CICD-SEC-1", "roadmap I05"),
}  # fmt: skip
CHECKS = [
    check
    for module in (r_injection, r_triggers, r_perms, r_secrets, r_supply, r_hygiene)
    for check in module.RULES.values()
]
#: Which checks apply to which file kind; Dependabot files hold none of the workflow keys.
FOR_KIND = {
    WORKFLOW: [c for c in CHECKS if c is not r_supply.dependabot_weaken],
    ACTION: [c for c in CHECKS if c is not r_supply.dependabot_weaken],
    DEPENDABOT: [r_supply.dependabot_weaken],
}


def kind_of(path: str) -> str | None:
    """What a repo-relative path is judged as, or None when it is out of scope."""
    if WORKFLOW_PATH.search(path):
        return WORKFLOW
    if DEPENDABOT_PATH.search(path):
        return DEPENDABOT
    return ACTION if ACTION_PATH.search(path) else None


def hits_for(kind: str, text: str, tables: dict) -> list[Hit]:
    """Every rule's hits on one file; an unreadable file is one gha-unreadable hit."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    try:
        docs = documents(text)
    except UnreadableError as exc:
        message = f"cannot be read with certainty ({exc}); a {kind} file this gate cannot read is refused, not guessed"
        return [Hit(UNREADABLE, exc.line, "file", str(exc), message)]
    hits: list[Hit] = []
    for tree in docs:
        on = triggers(tree) if kind == WORKFLOW else set()
        ctx = Ctx(tree, kind, lines, on, tables, typed_inputs(tree) if kind == WORKFLOW else frozenset())
        for check in FOR_KIND[kind]:
            hits += check(ctx)
    return hits
