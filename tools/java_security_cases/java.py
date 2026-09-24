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
