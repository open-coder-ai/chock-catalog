#!/usr/bin/env python3
"""Fail if the shipped Java security gate misjudges any construct its rules name, or passes one."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile

import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "base" / "java-security"
GATE = POLICY / "implementations" / "java-security-gate.py"
SETUP = POLICY / "skill"
#: Ordinary, correct enterprise code -- controllers, security configuration, repositories, crypto,
#: XML and archive handling, templates, build files, an Android manifest, web.xml. No rule may fire
#: on any of it: a rule that does has failed, whatever its own cases say.
CORPUS = ROOT / "tools" / "java_security_corpus"

sys.path.insert(0, str(POLICY / "implementations"))
from chock_security.decision import ALLOW, ASK, DENY, FileText  # noqa: E402
from chock_security.engine import evaluate  # noqa: E402
from chock_security.rules import packs, registry  # noqa: E402
from chock_security.selection import LEGACY_RULES  # noqa: E402

sys.path.insert(0, str(ROOT / "tools"))
from java_security_cases import CASES, FLOW_CASES  # noqa: E402

UNESCAPED = '<p th:utext="${bio}"></p>\n'
ESCAPED = '<p th:text="${bio}"></p>\n'
XSS = "java-xss-unescaped-template"
DOWNLOAD = (
    "public class C {\n"
    '  @GetMapping("/download")\n'
    "  public byte[] download(@RequestParam String file) throws Exception {\n"
    '    return Files.readAllBytes(Paths.get("/srv/files/" + file));\n'
    "  }\n}\n"
)

ALL_DENY = {rule_id: DENY for rule_id in registry()}


class Probe:
    """Runs every case and records every disagreement, not the first."""

    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checked = 0

    def expect(self, condition: bool, complaint: str) -> None:
        self.checked += 1
        if not condition:
            self.failures.append(complaint)


def check_registry(probe: Probe) -> None:
    """Every pack carries rules, and every rule carries the texts the page and the agent read."""
    rules = registry()
    for pack_id, pack in packs().items():
        probe.expect(any(r.pack == pack_id for r in rules.values()), f"pack {pack_id!r} ships no rule")
        probe.expect(bool(pack.title and pack.covers), f"pack {pack_id!r} needs a title and what it covers")
    for rule in rules.values():
        for field in ("title", "constraint", "refuses", "silent_on"):
            probe.expect(bool(getattr(rule, field)), f"{rule.id} has no {field}")
        probe.expect(rule.id in LEGACY_RULES or rule.id.startswith(f"{rule.pack}-"),
                     f"{rule.id} must be named for its pack: '{rule.pack}-...'")


def check_rules(probe: Probe) -> None:
    rules = registry()
    refusing: set[str] = set()
    silent: set[str] = set()
    for rule_id, path, text, expected in CASES:
        probe.expect(rule_id in rules, f"a case names {rule_id!r}, which no pack registers")
        if rule_id not in rules:
            continue
        rule = rules[rule_id]
        got = [f.line_no for f in rule.scan(FileText(path, text))] if rule.reads(FileText(path, text)) else []
        (refusing if expected else silent).add(rule_id)
        verb = "refused a correct change" if not expected else "missed the construct it names"
        probe.expect(got == expected, f"{rule_id} on {path}: {verb}; reported lines {got}, expected {expected}")
    for label, path, body, expected, about in FLOW_CASES:
        fired = {f.rule_id for f in evaluate([FileText(path, body)], ALL_DENY)}
        refusing.update(expected)
        silent.update(about - expected)
        probe.expect(fired == expected, f"flow: {label}: fired {sorted(fired)}, expected {sorted(expected)}")
    # A rule without a case that could have failed in each direction ships unproven.
    for rule_id in rules:
        probe.expect(rule_id in refusing, f"{rule_id} has no case showing it refuses anything")
        probe.expect(rule_id in silent, f"{rule_id} has no case showing it stays silent on correct code")
    # The engine renders the download refusal from the rule, never from the line it matched.
    rendered = [f.render() for f in evaluate([FileText("C.java", DOWNLOAD)], ALL_DENY)][0]
    probe.expect("FilenameUtils.getName" in rendered and "/srv/files/" not in rendered,
                 "the traversal refusal must say what to do instead without echoing the line")


def check_corpus(probe: Probe) -> None:
    """Every rule, over code that is correct: silence is the only passing answer."""
    files = [FileText(str(p.relative_to(CORPUS)), p.read_text(encoding="utf-8"))
             for p in sorted(CORPUS.rglob("*")) if p.is_file()]
    probe.expect(len(files) >= 10, f"the correct-code corpus holds {len(files)} files; it must not quietly empty")
    for finding in evaluate(files, ALL_DENY):
        probe.expect(False, f"corpus: {finding.rule_id} fired on correct code at {finding.path}:{finding.line_no}")


def _gate(repo: Path, writes: dict[str, str], selection: dict | str | None = None) -> tuple[int, str]:
    """Run the gate as the runner does: the writes on stdin, the repository root beside them."""
    if selection is not None:
        (repo / ".chock").mkdir(exist_ok=True)
        body = selection if isinstance(selection, str) else json.dumps(selection)
        (repo / ".chock" / "security.json").write_text(body, encoding="utf-8")
    payload = json.dumps({"event": "commit", "repo_root": str(repo), "writes": writes})
    proc = subprocess.run(
        [sys.executable, str(GATE)], cwd=repo, input=payload, capture_output=True, text=True, timeout=60,
        start_new_session=True,  # no controlling terminal, so an ask has nobody
    )
    return proc.returncode, proc.stderr


def check_evals(probe: Probe) -> int:
    """Every eval case with an executable form, replayed through the gate as a commit would run it.

    `chock check --only evals` does not replay a script gate on this engine, so without this the
    suite's executable cases would be prose that nothing runs. A case's `.chock/security.json`, when
    it carries one -- staged or already in the repository -- is written as the selection; every other
    staged file is a write.
    """
    suite = yaml.safe_load((POLICY / "evals" / "suite.yaml").read_text(encoding="utf-8"))["suite"]
    replayed = 0
    for case in suite["cases"]:
        execute = case.get("execute")
        if not execute:
            continue
        files = dict(execute.get("files") or {})
        present = dict(execute.get("repo_files") or {})
        selection = files.pop(".chock/security.json", None) or present.get(".chock/security.json")
        with tempfile.TemporaryDirectory(prefix="java-security-eval-") as tmp:
            code, err = _gate(Path(tmp), files, selection)
        want = {"block": 1, "allow": 0}[execute["expect"]]
        probe.expect(code == want, f"eval {case['id']}: expected {execute['expect']}, gate exited {code}: {err.strip()[:160]}")
        replayed += 1
    return replayed


def check_gate(probe: Probe) -> None:
    """The exit code is the verdict the runner carries; `evaluate` can be right while the gate is not."""
    with tempfile.TemporaryDirectory(prefix="java-security-") as tmp:
        repo = Path(tmp)
        code, err = _gate(repo, {"p.html": UNESCAPED})
        probe.expect(code == 1 and XSS in err, f"a violating write with no selection must refuse (exit 1); got {code}")
        code, _ = _gate(repo, {"p.html": ESCAPED})
        probe.expect(code == 0, f"clean markup must pass; got {code}")
        code, _ = _gate(repo, {})
        probe.expect(code == 0, f"nothing written is nothing to refuse; got {code}")
        code, _ = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {XSS: ALLOW}}}})
        probe.expect(code == 0, f"a rule set to allow must be honoured; got {code}")
        code, _ = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"verdict": ALLOW}}})
        probe.expect(code == 0, f"a pack set to allow must be honoured; got {code}")
        code, _ = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"java": {"verdict": ALLOW}}})
        probe.expect(code == 1, f"allowing one pack must not allow another pack's rule; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {XSS: XSS}}}})
        probe.expect(code == 1 and "program in disguise" in err, f"a verdict must be a verdict; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"java": {"rules": {XSS: ALLOW}}}})
        probe.expect(code == 1 and "does not contain" in err, f"a rule named under the wrong pack must refuse; got {code}")
        # Version 1 is read as it was written: its one `java` pack speaks for the first eight rules.
        code, _ = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"rules": {XSS: ALLOW}}}})
        probe.expect(code == 0, f"a version-1 allow for one of the first eight rules must be honoured; got {code}")
        code, _ = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"verdict": ALLOW}}})
        probe.expect(code == 0, f"a version-1 pack allow must still cover the first eight rules; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"templates": {"verdict": ALLOW}}})
        probe.expect(code == 1 and "version-1" in err, f"a version-1 file names only its own pack; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {XSS: ASK}}}})
        probe.expect(code == 1 and "no terminal to ask" in err, f"an ask with nobody to ask must refuse; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, "{not json")
        probe.expect(code == 1 and "chock-security:" in err, f"an unreadable selection must refuse in words; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {XSS: {"pattern": "x"}}}}})
        probe.expect(code == 1 and "program in disguise" in err, f"a pattern in place of a verdict must refuse; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {"no-such-rule": DENY}}}})
        probe.expect(code == 1, f"a rule the engine does not have must refuse; got {code}")


def _rows(rules: dict) -> list[dict]:
    return [{"id": r.id, "pack": r.pack, "title": r.title, "refuses": r.refuses, "silent_on": r.silent_on,
             "constraint": r.constraint} for r in rules.values()]


def check_setup_page(probe: Probe) -> None:
    """The page and the contract carry the registry's own texts; a rule change must reach them."""
    page = (SETUP / "setup.html").read_text(encoding="utf-8")
    match = re.search(r'<script type="application/json" id="contract">(.*?)</script>', page, re.S)
    probe.expect(match is not None, "setup.html carries no #contract element")
    embedded = json.loads(match.group(1).replace("<\\/", "</")) if match else {}
    reference = json.loads((SETUP / "references" / "setup-contract.json").read_text(encoding="utf-8"))
    expected = _rows(registry())
    probe.expect(embedded.get("rules") == expected, "setup.html's embedded contract does not match the shipped rules")
    probe.expect(reference.get("rules") == expected, "references/setup-contract.json does not match the shipped rules")
    probe.expect(embedded.get("agent") is None, "the catalog's page must not claim one agent's reach")
    probe.expect(embedded.get("default") == DENY, "the page's default verdict must be deny")
    expected_packs = [{"id": p.id, "title": p.title, "covers": p.covers} for p in packs().values()]
    probe.expect(embedded.get("packs") == expected_packs, "setup.html's embedded packs do not match the shipped packs")
    probe.expect(reference.get("packs") == expected_packs, "references/setup-contract.json packs do not match")


def main() -> int:
    probe = Probe()
    check_registry(probe)
    check_rules(probe)
    check_corpus(probe)
    replayed = check_evals(probe)
    check_gate(probe)
    check_setup_page(probe)
    if probe.failures:
        print(f"java-security: {len(probe.failures)} of {probe.checked} checks failed:", file=sys.stderr)
        for failure in probe.failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"java-security: {probe.checked} checks passed over {len(registry())} rules in {len(packs())} packs "
          f"({len(CASES)} rule cases, {len(FLOW_CASES)} flow cases, {replayed} eval cases through the gate, "
          "the correct-code corpus, the gate protocol, the setup page).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
