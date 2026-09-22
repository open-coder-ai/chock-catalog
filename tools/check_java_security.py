#!/usr/bin/env python3
"""Fail if the shipped Java security gate misjudges any construct its rules name, or passes one."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "base" / "java-security"
GATE = POLICY / "implementations" / "java-security-gate.py"
SETUP = ROOT / "skills" / "configure-java-security"

sys.path.insert(0, str(POLICY / "implementations"))
from chock_security.decision import ALLOW, ASK, DENY, FileText  # noqa: E402
from chock_security.engine import evaluate  # noqa: E402
from chock_security.rules import registry  # noqa: E402

MAPPER = '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN">\n<mapper namespace="a">\n'
CREDENTIALS = "config.setAllowCredentials(true);\n"
DOWNLOAD = (
    "public class C {\n"
    '  @GetMapping("/download")\n'
    "  public byte[] download(@RequestParam String file) throws Exception {\n"
    '    return Files.readAllBytes(Paths.get("/srv/files/" + file));\n'
    "  }\n}\n"
)
UPLOAD = (
    "public class C {\n"
    '  @PostMapping("/restore")\n'
    "  public void restore(HttpServletRequest request) throws Exception {\n"
    "    ObjectInputStream in = new ObjectInputStream(request.getInputStream());\n"
    "    state = in.readObject();\n"
    "  }\n}\n"
)
UNESCAPED = '<p th:utext="${bio}"></p>\n'
ESCAPED = '<p th:text="${bio}"></p>\n'
XSS = "java-xss-unescaped-template"
TRAVERSAL = "java-path-traversal-request-data"

#: (rule id, path, text, line numbers the rule must report). An empty list is a correct change
#: the rule must stay silent on. Ported from the engine's own suite, one row per case.
CASES: list[tuple[str, str, str, list[int]]] = [
    # MyBatis interpolation
    ("java-sqli-mybatis-interpolation", "UserMapper.xml", MAPPER + "SELECT * FROM t ORDER BY ${col}", [3]),
    ("java-sqli-mybatis-interpolation", "UserMapper.java",
     'import org.apache.ibatis.annotations.Select;\n@Select("SELECT * FROM ${t}")\n', [2]),
    ("java-sqli-mybatis-interpolation", "UserMapper.xml", MAPPER + "SELECT * FROM t WHERE id = #{id}", []),
    ("java-sqli-mybatis-interpolation", "pom.xml", "<project>\n  <version>${project.version}</version>\n</project>\n", []),
    ("java-sqli-mybatis-interpolation", "Config.java",
     'import org.springframework.beans.factory.annotation.Value;\n@Value("${app.url}")\n', []),
    # Unescaped template output
    (XSS, "p.html", UNESCAPED, [1]),
    (XSS, "p.html", ESCAPED, []),
    (XSS, "p.jsp", "<%= user.getName() %>", [1]),
    (XSS, "p.jsp", '<c:out value="${b}" escapeXml="false"/>', [1]),
    (XSS, "p.jsp", "<%-- a comment --%>", []),
    (XSS, "p.jsp", '<%@ page session="false" %>', []),
    (XSS, "p.jsp", "<%! int i; %>", []),
    (XSS, "p.ftl", "${bio?no_esc}\n<#noescape>${x}</#noescape>", [1, 2]),
    (XSS, "Doc.java", "// th:utext is documented here", []),
    # Unsafe deserialization
    ("java-unsafe-deserialization", "M.java", "mapper.enableDefaultTyping();", [1]),
    ("java-unsafe-deserialization", "M.java", "mapper.activateDefaultTyping(ptv);", [1]),
    ("java-unsafe-deserialization", "M.java", "var m = new ObjectMapper();", []),
    ("java-unsafe-deserialization", "M.java", "XStream x = new XStream();\nx.fromXML(input);\n", [1]),
    ("java-unsafe-deserialization", "M.java", "XStream x = new XStream();\nx.allowTypes(new Class[]{Order.class});\n", []),
    # CORS
    ("java-cors-wildcard-credentials", "Cors.java", CREDENTIALS + 'config.setAllowedOrigins(List.of("*"));\n', [2]),
    ("java-cors-wildcard-credentials", "Api.java", '@CrossOrigin(origins = "*", allowCredentials = "true")\n', [1]),
    ("java-cors-wildcard-credentials", "Cors.java", 'config.setAllowedOrigins(List.of("*"));\n', []),
    ("java-cors-wildcard-credentials", "Cors.java",
     CREDENTIALS + 'config.setAllowedOrigins(List.of("https://app.example.com"));\n', []),
    ("java-cors-wildcard-credentials", "Cors.java", CREDENTIALS + 'config.setAllowedOriginPatterns(List.of("*"));\n', []),
    ("java-cors-wildcard-credentials", "Cors.java", CREDENTIALS + 'config.addAllowedOriginPattern("*");\n', []),
    # Actuator
    ("java-actuator-wildcard-exposure", "application.properties", "management.endpoints.web.exposure.include=*\n", [1]),
    ("java-actuator-wildcard-exposure", "application.yml",
     'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n', [5]),
    ("java-actuator-wildcard-exposure", "application.properties",
     "management.endpoints.web.exposure.include=health,info,metrics\n", []),
    ("java-actuator-wildcard-exposure", "codecov.yml", 'coverage:\n  include: "*"\n', []),
    ("java-actuator-wildcard-exposure", "codecov.yml",
     '# operational exposure notes: keep actuator endpoints minimal\ncoverage:\n  include: "*.yml"\n', []),
    ("java-actuator-wildcard-exposure", "application.yml",
     'management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info\n  other:\n    include: "*"\n', []),
    ("java-actuator-wildcard-exposure", "application.properties", "server.port=8080\n", []),
    # JWT
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().parseClaimsJwt(token);\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().parseUnsecuredClaims(token);\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "JWT.require(Algorithm.none()).build().verify(token);\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "var a = SignatureAlgorithm.NONE;\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "var jwt = JWT.decode(token);\nreturn jwt.getSubject();\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().setSigningKey(key).parseClaimsJws(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().verifyWith(key).build().parseSignedClaims(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java", "JWT.require(Algorithm.HMAC256(secret)).build().verify(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java",
     "var kid = JWT.decode(token).getKeyId();\nJWT.require(alg).build().verify(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java", "var kid = JWT.decode(token).getKeyId();\nverifier.verify(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java",
     "var kid = JWT.decode(token).getKeyId();\nJwts.parser().verifyWith(key).build().parseSignedClaims(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java",
     "var t = JWT.create().withSubject(id).sign(Algorithm.HMAC256(secret));\n", []),
]

#: (label, Java body, rule ids the engine must report). The two flow rules are judged through
#: `evaluate`, the call the front end makes, because a flow model has no single line to name.
FLOW_CASES: list[tuple[str, str, set[str]]] = [
    ("a download path the caller chooses", DOWNLOAD, {TRAVERSAL}),
    ("a request body deserialized as java", UPLOAD, {"java-deserialization-request-stream"}),
    ("a fixed file name", DOWNLOAD.replace("+ file", '+ "catalog.json"'), set()),
    ("the directory taken out of the caller's hands",
     DOWNLOAD.replace('Paths.get("/srv/files/" + file)', 'Paths.get("/srv/files/").resolve(FilenameUtils.getName(file))'),
     set()),
    ("a stream the application opened itself",
     UPLOAD.replace("request.getInputStream()", 'new FileInputStream("/var/state.ser")'), set()),
    ("request bytes read as json rather than as java",
     UPLOAD.replace("ObjectInputStream in = new ObjectInputStream(request.getInputStream())",
                    "JsonNode in = mapper.readTree(request.getInputStream())"), set()),
    ("a line waiver naming the rule it waives", DOWNLOAD.replace("+ file));", f"+ file));  // chock: allow {TRAVERSAL}"), set()),
    ("a line waiver naming another rule", DOWNLOAD.replace("+ file));", "+ file));  // chock: allow other"), {TRAVERSAL}),
]

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


def check_rules(probe: Probe) -> None:
    rules = registry()
    refusing: set[str] = set()
    silent: set[str] = set()
    for rule_id, path, text, expected in CASES:
        rule = rules[rule_id]
        got = [f.line_no for f in rule.scan(FileText(path, text))] if rule.reads(FileText(path, text)) else []
        (refusing if expected else silent).add(rule_id)
        verb = "refused a correct change" if not expected else "missed the construct it names"
        probe.expect(got == expected, f"{rule_id} on {path}: {verb}; reported lines {got}, expected {expected}")
    for label, body, expected in FLOW_CASES:
        fired = {f.rule_id for f in evaluate([FileText("C.java", body)], ALL_DENY)}
        for rule_id in expected:
            refusing.add(rule_id)
        if not expected:
            silent.update({TRAVERSAL, "java-deserialization-request-stream"})
        probe.expect(fired == expected, f"flow: {label}: fired {sorted(fired)}, expected {sorted(expected)}")
    # A rule without a case that could have failed in each direction ships unproven.
    for rule_id in rules:
        probe.expect(rule_id in refusing, f"{rule_id} has no case showing it refuses anything")
        probe.expect(rule_id in silent, f"{rule_id} has no case showing it stays silent on correct code")
    # The engine renders the download refusal from the rule, never from the line it matched.
    rendered = [f.render() for f in evaluate([FileText("C.java", DOWNLOAD)], ALL_DENY)][0]
    probe.expect("FilenameUtils.getName" in rendered and "/srv/files/" not in rendered,
                 "the traversal refusal must say what to do instead without echoing the line")


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
        code, _ = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"rules": {XSS: ALLOW}}}})
        probe.expect(code == 0, f"a rule set to allow must be honoured; got {code}")
        code, _ = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"verdict": ALLOW}}})
        probe.expect(code == 0, f"a pack set to allow must be honoured; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"rules": {XSS: ASK}}}})
        probe.expect(code == 1 and "no terminal to ask" in err, f"an ask with nobody to ask must refuse; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, "{not json")
        probe.expect(code == 1 and "chock-security:" in err, f"an unreadable selection must refuse in words; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"rules": {XSS: {"pattern": "x"}}}}})
        probe.expect(code == 1 and "program in disguise" in err, f"a pattern in place of a verdict must refuse; got {code}")
        code, err = _gate(repo, {"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"rules": {"no-such-rule": DENY}}}})
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


def main() -> int:
    probe = Probe()
    check_rules(probe)
    check_gate(probe)
    check_setup_page(probe)
    if probe.failures:
        print(f"java-security: {len(probe.failures)} of {probe.checked} checks failed:", file=sys.stderr)
        for failure in probe.failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"java-security: {probe.checked} checks passed over {len(registry())} rules "
          f"({len(CASES)} rule cases, {len(FLOW_CASES)} flow cases, the gate protocol, the setup page).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
