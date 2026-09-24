"""Cases for the java pack: Core Java.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

from java_security.cases.java_sast import CASES as SAST_CASES
from java_security.cases.java_xml import CASES as XML_AND_ARCHIVE_CASES

TRAVERSAL = "java-path-traversal-request-data"
STREAM = "java-deserialization-request-stream"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    ("java-unsafe-deserialization", "M.java", "mapper.enableDefaultTyping();", [1]),
    ("java-unsafe-deserialization", "M.java", "mapper.activateDefaultTyping(ptv);", [1]),
    ("java-unsafe-deserialization", "M.java", "var m = new ObjectMapper();", []),
    ("java-unsafe-deserialization", "M.java", "XStream x = new XStream();\nx.fromXML(input);\n", [1]),
    (
        "java-unsafe-deserialization",
        "M.java",
        "XStream x = new XStream();\nx.allowTypes(new Class[]{Order.class});\n",
        [],
    ),
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().parseClaimsJwt(token);\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().parseUnsecuredClaims(token);\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "JWT.require(Algorithm.none()).build().verify(token);\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "var a = SignatureAlgorithm.NONE;\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "var jwt = JWT.decode(token);\nreturn jwt.getSubject();\n", [1]),
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().setSigningKey(key).parseClaimsJws(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java", "Jwts.parser().verifyWith(key).build().parseSignedClaims(token);\n", []),
    ("java-jwt-unverified-parse", "Auth.java", "JWT.require(Algorithm.HMAC256(secret)).build().verify(token);\n", []),
    (
        "java-jwt-unverified-parse",
        "Auth.java",
        "var kid = JWT.decode(token).getKeyId();\nJWT.require(alg).build().verify(token);\n",
        [],
    ),
    (
        "java-jwt-unverified-parse",
        "Auth.java",
        "var kid = JWT.decode(token).getKeyId();\nverifier.verify(token);\n",
        [],
    ),
    (
        "java-jwt-unverified-parse",
        "Auth.java",
        "var kid = JWT.decode(token).getKeyId();\nJwts.parser().verifyWith(key).build().parseSignedClaims(token);\n",
        [],
    ),
    (
        "java-jwt-unverified-parse",
        "Auth.java",
        "var t = JWT.create().withSubject(id).sign(Algorithm.HMAC256(secret));\n",
        [],
    ),
    (
        "java-command-injection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/run")\n'
        "  public void run(@RequestParam String cmd) throws Exception {\n"
        "    Runtime.getRuntime().exec(cmd);\n"
        "  }\n}\n",
        [4],
    ),
    (
        "java-command-injection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/ping")\n'
        "  public void ping(@RequestParam String host) throws Exception {\n"
        '    ProcessBuilder pb = new ProcessBuilder("ping", host);\n'
        "    pb.start();\n"
        "  }\n}\n",
        [4],
    ),
    (
        "java-command-injection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/run")\n'
        "  public void run(@RequestParam String cmd) throws Exception {\n"
        '    Runtime.getRuntime().exec("ls -la");\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-command-injection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/run")\n'
        "  public void run(@RequestParam String cmd) throws Exception {\n"
        '    Runtime.getRuntime().exec(new String[]{"sh", "-c", "ls -la"});\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-code-injection",
        "C.java",
        "import javax.script.ScriptEngine;\n"
        "import javax.script.ScriptEngineManager;\n"
        "public class C {\n"
        '  @PostMapping("/calc")\n'
        "  public Object calc(@RequestParam String expr) throws Exception {\n"
        '    ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");\n'
        "    return engine.eval(expr);\n"
        "  }\n}\n",
        [7],
    ),
    (
        "java-code-injection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/calc")\n'
        "  public Object calc(@RequestParam String expr) throws Exception {\n"
        "    return engine.eval(expr);\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-code-injection",
        "C.java",
        "import javax.script.ScriptEngine;\n"
        "public class C {\n"
        '  @PostMapping("/calc")\n'
        "  public Object calc(@RequestParam String expr) throws Exception {\n"
        '    ScriptEngine engine = mgr.getEngineByName("js");\n'
        '    return engine.eval("1+1");\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-unsafe-reflection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/load")\n'
        "  public Object load(@RequestParam String className) throws Exception {\n"
        "    return Class.forName(className).newInstance();\n"
        "  }\n}\n",
        [4],
    ),
    (
        "java-unsafe-reflection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/load")\n'
        "  public Object load(@RequestParam String className) throws Exception {\n"
        '    return Class.forName("com.acme.Handler").newInstance();\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-unsafe-reflection",
        "C.java",
        "public class C {\n"
        '  @PostMapping("/load")\n'
        "  public Object load(@RequestParam String className) throws Exception {\n"
        "    String checked = allowlist.get(className);\n"
        "    return Class.forName(checked).newInstance();\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-ssrf-request-url",
        "C.java",
        "public class C {\n"
        '  @GetMapping("/fetch")\n'
        "  public String fetch(@RequestParam String url) throws Exception {\n"
        "    URL u = new URL(url);\n"
        "    return u.toString();\n"
        "  }\n}\n",
        [4],
    ),
    (
        "java-ssrf-request-url",
        "C.java",
        "public class C {\n"
        '  @GetMapping("/fetch")\n'
        "  public String fetch(@RequestParam String target) throws Exception {\n"
        "    return restTemplate.getForObject(target, String.class);\n"
        "  }\n}\n",
        [4],
    ),
    (
        "java-ssrf-request-url",
        "C.java",
        "public class C {\n"
        '  @GetMapping("/fetch")\n'
        "  public String fetch(@RequestParam String url) throws Exception {\n"
        '    URL u = new URL("https://example.com/api");\n'
        "    return u.toString();\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-ssrf-request-url",
        "C.java",
        "public class C {\n"
        '  @GetMapping("/fetch")\n'
        "  public String fetch(@RequestParam String host) throws Exception {\n"
        "    String checked = allowlist.get(host);\n"
        "    URL u = new URL(checked);\n"
        "    return u.toString();\n"
        "  }\n}\n",
        [],
    ),
    *XML_AND_ARCHIVE_CASES,
    *SAST_CASES,
]
