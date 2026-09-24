"""Cases for the java pack: Core Java.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

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
TRAVERSAL = "java-path-traversal-request-data"
STREAM = "java-deserialization-request-stream"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    ('java-unsafe-deserialization', 'M.java',
     'mapper.enableDefaultTyping();', [1]),
    ('java-unsafe-deserialization', 'M.java',
     'mapper.activateDefaultTyping(ptv);', [1]),
    ('java-unsafe-deserialization', 'M.java',
     'var m = new ObjectMapper();', []),
    ('java-unsafe-deserialization', 'M.java',
     'XStream x = new XStream();\nx.fromXML(input);\n', [1]),
    ('java-unsafe-deserialization', 'M.java',
     'XStream x = new XStream();\nx.allowTypes(new Class[]{Order.class});\n', []),
    ('java-jwt-unverified-parse', 'Auth.java',
     'Jwts.parser().parseClaimsJwt(token);\n', [1]),
    ('java-jwt-unverified-parse', 'Auth.java',
     'Jwts.parser().parseUnsecuredClaims(token);\n', [1]),
    ('java-jwt-unverified-parse', 'Auth.java',
     'JWT.require(Algorithm.none()).build().verify(token);\n', [1]),
    ('java-jwt-unverified-parse', 'Auth.java',
     'var a = SignatureAlgorithm.NONE;\n', [1]),
    ('java-jwt-unverified-parse', 'Auth.java',
     'var jwt = JWT.decode(token);\nreturn jwt.getSubject();\n', [1]),
    ('java-jwt-unverified-parse', 'Auth.java',
     'Jwts.parser().setSigningKey(key).parseClaimsJws(token);\n', []),
    ('java-jwt-unverified-parse', 'Auth.java',
     'Jwts.parser().verifyWith(key).build().parseSignedClaims(token);\n', []),
    ('java-jwt-unverified-parse', 'Auth.java',
     'JWT.require(Algorithm.HMAC256(secret)).build().verify(token);\n', []),
    ('java-jwt-unverified-parse', 'Auth.java',
     'var kid = JWT.decode(token).getKeyId();\nJWT.require(alg).build().verify(token);\n', []),
    ('java-jwt-unverified-parse', 'Auth.java',
     'var kid = JWT.decode(token).getKeyId();\nverifier.verify(token);\n', []),
    ('java-jwt-unverified-parse', 'Auth.java',
     'var kid = JWT.decode(token).getKeyId();\nJwts.parser().verifyWith(key).build().parseSignedClaims(token);\n', []),
    ('java-jwt-unverified-parse', 'Auth.java',
     'var t = JWT.create().withSubject(id).sign(Algorithm.HMAC256(secret));\n', []),

    # -- java-command-injection --------------------------------------------------------------
    ('java-command-injection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/run")\n'
     '  public void run(@RequestParam String cmd) throws Exception {\n'
     '    Runtime.getRuntime().exec(cmd);\n'
     '  }\n}\n', [4]),
    ('java-command-injection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/ping")\n'
     '  public void ping(@RequestParam String host) throws Exception {\n'
     '    ProcessBuilder pb = new ProcessBuilder("ping", host);\n'
     '    pb.start();\n'
     '  }\n}\n', [4]),
    ('java-command-injection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/run")\n'
     '  public void run(@RequestParam String cmd) throws Exception {\n'
     '    Runtime.getRuntime().exec("ls -la");\n'
     '  }\n}\n', []),
    ('java-command-injection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/run")\n'
     '  public void run(@RequestParam String cmd) throws Exception {\n'
     '    Runtime.getRuntime().exec(new String[]{"sh", "-c", "ls -la"});\n'
     '  }\n}\n', []),

    # -- java-code-injection -------------------------------------------------------------------
    ('java-code-injection', 'C.java',
     'import javax.script.ScriptEngine;\n'
     'import javax.script.ScriptEngineManager;\n'
     'public class C {\n'
     '  @PostMapping("/calc")\n'
     '  public Object calc(@RequestParam String expr) throws Exception {\n'
     '    ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");\n'
     '    return engine.eval(expr);\n'
     '  }\n}\n', [7]),
    ('java-code-injection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/calc")\n'
     '  public Object calc(@RequestParam String expr) throws Exception {\n'
     '    return engine.eval(expr);\n'
     '  }\n}\n', []),
    ('java-code-injection', 'C.java',
     'import javax.script.ScriptEngine;\n'
     'public class C {\n'
     '  @PostMapping("/calc")\n'
     '  public Object calc(@RequestParam String expr) throws Exception {\n'
     '    ScriptEngine engine = mgr.getEngineByName("js");\n'
     '    return engine.eval("1+1");\n'
     '  }\n}\n', []),

    # -- java-unsafe-reflection ------------------------------------------------------------------
    ('java-unsafe-reflection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/load")\n'
     '  public Object load(@RequestParam String className) throws Exception {\n'
     '    return Class.forName(className).newInstance();\n'
     '  }\n}\n', [4]),
    ('java-unsafe-reflection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/load")\n'
     '  public Object load(@RequestParam String className) throws Exception {\n'
     '    return Class.forName("com.acme.Handler").newInstance();\n'
     '  }\n}\n', []),
    ('java-unsafe-reflection', 'C.java',
     'public class C {\n'
     '  @PostMapping("/load")\n'
     '  public Object load(@RequestParam String className) throws Exception {\n'
     '    String checked = allowlist.get(className);\n'
     '    return Class.forName(checked).newInstance();\n'
     '  }\n}\n', []),

    # -- java-xxe-parser --------------------------------------------------------------------------
    ('java-xxe-parser', 'X.java',
     'public class X {\n'
     '  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n'
     '}\n', [2]),
    ('java-xxe-parser', 'X.java',
     'public class X {\n'
     '  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n'
     '  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
     '}\n', []),
    ('java-xxe-parser', 'X.java',
     'public class X {\n'
     '  TransformerFactory tf = TransformerFactory.newInstance();\n'
     '  tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n'
     '}\n', []),

    # -- java-xml-decoder -------------------------------------------------------------------------
    ('java-xml-decoder', 'X.java',
     'public class X {\n'
     '  XMLDecoder d = new XMLDecoder(in);\n'
     '  Object o = d.readObject();\n'
     '}\n', [2]),
    ('java-xml-decoder', 'X.java',
     'import org.yaml.snakeyaml.Yaml;\n'
     'import org.yaml.snakeyaml.constructor.Constructor;\n'
     'public class X {\n'
     '  Yaml yaml = new Yaml(new Constructor(Object.class));\n'
     '  Object o = yaml.load(input);\n'
     '}\n', [4]),
    ('java-xml-decoder', 'X.java',
     'import org.yaml.snakeyaml.Yaml;\n'
     'public class X {\n'
     '  Yaml yaml = new Yaml();\n'
     '  Object o = yaml.load(input);\n'
     '}\n', []),
    ('java-xml-decoder', 'X.java',
     'import org.yaml.snakeyaml.Yaml;\n'
     'import org.yaml.snakeyaml.constructor.Constructor;\n'
     'public class X {\n'
     '  Yaml yaml = new Yaml(new Constructor(Person.class));\n'
     '  Object o = yaml.load(input);\n'
     '}\n', []),
    ('java-xml-decoder', 'X.java',
     'public class X {\n'
     '  XMLEncoder e = new XMLEncoder(out);\n'
     '}\n', []),

    # -- java-ssrf-request-url --------------------------------------------------------------------
    ('java-ssrf-request-url', 'C.java',
     'public class C {\n'
     '  @GetMapping("/fetch")\n'
     '  public String fetch(@RequestParam String url) throws Exception {\n'
     '    URL u = new URL(url);\n'
     '    return u.toString();\n'
     '  }\n}\n', [4]),
    ('java-ssrf-request-url', 'C.java',
     'public class C {\n'
     '  @GetMapping("/fetch")\n'
     '  public String fetch(@RequestParam String target) throws Exception {\n'
     '    return restTemplate.getForObject(target, String.class);\n'
     '  }\n}\n', [4]),
    ('java-ssrf-request-url', 'C.java',
     'public class C {\n'
     '  @GetMapping("/fetch")\n'
     '  public String fetch(@RequestParam String url) throws Exception {\n'
     '    URL u = new URL("https://example.com/api");\n'
     '    return u.toString();\n'
     '  }\n}\n', []),
    ('java-ssrf-request-url', 'C.java',
     'public class C {\n'
     '  @GetMapping("/fetch")\n'
     '  public String fetch(@RequestParam String host) throws Exception {\n'
     '    String checked = allowlist.get(host);\n'
     '    URL u = new URL(checked);\n'
     '    return u.toString();\n'
     '  }\n}\n', []),

    # -- java-zip-slip ------------------------------------------------------------------------------
    ('java-zip-slip', 'Z.java',
     'public class Z {\n'
     '  public void extract(ZipInputStream zis, File dest) throws Exception {\n'
     '    ZipEntry entry = zis.getNextEntry();\n'
     '    File out = new File(dest, entry.getName());\n'
     '    write(out);\n'
     '  }\n}\n', [4]),
    ('java-zip-slip', 'Z.java',
     'public class Z {\n'
     '  public void extract(ZipInputStream zis, File dest) throws Exception {\n'
     '    ZipEntry entry = zis.getNextEntry();\n'
     '    File out = new File(dest, entry.getName());\n'
     '    String canon = dest.toPath().normalize().toString();\n'
     '    if (!out.toPath().normalize().startsWith(canon)) throw new IOException("bad entry");\n'
     '    write(out);\n'
     '  }\n}\n', []),
    ('java-zip-slip', 'Z.java',
     'public class Z {\n'
     '  public void extract(ZipInputStream zis, File dest) throws Exception {\n'
     '    ZipEntry entry = zis.getNextEntry();\n'
     '    File out = new File(dest, entry.getName());\n'
     '    Path real = out.toPath().toRealPath();\n'
     '    if (!real.startsWith(dest.toPath())) throw new IOException("bad entry");\n'
     '    write(out);\n'
     '  }\n}\n', []),
    ('java-zip-slip', 'F.java',
     'public class F {\n'
     '  public void copy(File src, File dir) {\n'
     '    File out = new File(dir, src.getName());\n'
     '  }\n}\n', []),

    # -- java-ldap-injection ------------------------------------------------------------------------
    ('java-ldap-injection', 'C.java',
     'import javax.naming.directory.DirContext;\n'
     'import javax.naming.directory.InitialDirContext;\n'
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public void find(@RequestParam String uid) throws Exception {\n'
     '    DirContext ctx = new InitialDirContext(env);\n'
     '    ctx.search("ou=people", "(uid=" + uid + ")", controls);\n'
     '  }\n}\n', [7]),
    ('java-ldap-injection', 'C.java',
     'import javax.naming.directory.DirContext;\n'
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public void find(@RequestParam String uid) throws Exception {\n'
     '    ctx.search("ou=people", "(uid=" + LdapEncoder.filterEncode(uid) + ")", controls);\n'
     '  }\n}\n', []),
    ('java-ldap-injection', 'C.java',
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public void find(@RequestParam String uid) throws Exception {\n'
     '    ctx.search("ou=people", "(uid=" + uid + ")", controls);\n'
     '  }\n}\n', []),
    ('java-ldap-injection', 'C.java',
     'import org.springframework.ldap.core.LdapTemplate;\n'
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public void find(@RequestParam String uid) throws Exception {\n'
     '    ldapTemplate.search(query().where("uid").is(uid), mapper);\n'
     '  }\n}\n', []),

    # -- java-xpath-injection -----------------------------------------------------------------------
    ('java-xpath-injection', 'C.java',
     'import javax.xml.xpath.XPath;\n'
     'import javax.xml.xpath.XPathFactory;\n'
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public String find(@RequestParam String username) throws Exception {\n'
     '    XPath xpath = XPathFactory.newInstance().newXPath();\n'
     '    return xpath.evaluate("//user[@name=\'" + username + "\']", doc);\n'
     '  }\n}\n', [7]),
    ('java-xpath-injection', 'C.java',
     'import javax.xml.xpath.XPath;\n'
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public String find(@RequestParam String username) throws Exception {\n'
     '    xpath.setXPathVariableResolver(resolver); xpath.compile("//user[@name=$username]");\n'
     '    return "";\n'
     '  }\n}\n', []),
    ('java-xpath-injection', 'C.java',
     'import javax.xml.xpath.XPath;\n'
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public String find(@RequestParam String username) throws Exception {\n'
     '    return xpath.evaluate("//user[@name=\'root\']", doc);\n'
     '  }\n}\n', []),
    ('java-xpath-injection', 'C.java',
     'public class C {\n'
     '  @GetMapping("/find")\n'
     '  public String find(@RequestParam String username) throws Exception {\n'
     '    return xpath.evaluate("//user[@name=\'" + username + "\']", doc);\n'
     '  }\n}\n', []),
    ("java-xxe-parser", "Feed.java",
     "XMLInputFactory f = XMLInputFactory.newFactory();\nXMLStreamReader r = f.createXMLStreamReader(in);\n", [1]),
    ("java-xxe-parser", "Feed.java",
     "DocumentBuilderFactory f = DocumentBuilderFactory.newDefaultInstance();\n"
     "f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n", []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    ('a download path the caller chooses', "C.java",
     'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + file));\n  }\n}\n',
     {'java-path-traversal-request-data'}, {TRAVERSAL, STREAM}),
    ('a request body deserialized as java', "C.java",
     'public class C {\n  @PostMapping("/restore")\n  public void restore(HttpServletRequest request) throws Exception {\n    ObjectInputStream in = new ObjectInputStream(request.getInputStream());\n    state = in.readObject();\n  }\n}\n',
     {'java-deserialization-request-stream'}, {TRAVERSAL, STREAM}),
    ('a fixed file name', "C.java",
     'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + "catalog.json"));\n  }\n}\n',
     set(), {TRAVERSAL, STREAM}),
    ("the directory taken out of the caller's hands", "C.java",
     'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/").resolve(FilenameUtils.getName(file)));\n  }\n}\n',
     set(), {TRAVERSAL, STREAM}),
    ('a stream the application opened itself', "C.java",
     'public class C {\n  @PostMapping("/restore")\n  public void restore(HttpServletRequest request) throws Exception {\n    ObjectInputStream in = new ObjectInputStream(new FileInputStream("/var/state.ser"));\n    state = in.readObject();\n  }\n}\n',
     set(), {TRAVERSAL, STREAM}),
    ('request bytes read as json rather than as java', "C.java",
     'public class C {\n  @PostMapping("/restore")\n  public void restore(HttpServletRequest request) throws Exception {\n    JsonNode in = mapper.readTree(request.getInputStream());\n    state = in.readObject();\n  }\n}\n',
     set(), {TRAVERSAL, STREAM}),
    ('a line waiver naming the rule it waives', "C.java",
     'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + file));  // chock: allow java-path-traversal-request-data\n  }\n}\n',
     set(), {TRAVERSAL, STREAM}),
    ('a line waiver naming another rule', "C.java",
     'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + file));  // chock: allow other\n  }\n}\n',
     {'java-path-traversal-request-data'}, {TRAVERSAL, STREAM}),
]
