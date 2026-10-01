"""Flow cases for the java pack: request data reaching a sink through a method body."""

from __future__ import annotations

from java_security.cases.java import STREAM, TRAVERSAL

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    (
        "a download path the caller chooses",
        "C.java",
        'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + file));\n  }\n}\n',
        {"java-path-traversal-request-data"},
        {TRAVERSAL, STREAM},
    ),
    (
        "a request body deserialized as java",
        "C.java",
        'public class C {\n  @PostMapping("/restore")\n  public void restore(HttpServletRequest request) throws Exception {\n    ObjectInputStream in = new ObjectInputStream(request.getInputStream());\n    state = in.readObject();\n  }\n}\n',
        {"java-deserialization-request-stream"},
        {TRAVERSAL, STREAM},
    ),
    (
        "a fixed file name",
        "C.java",
        'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + "catalog.json"));\n  }\n}\n',
        set(),
        {TRAVERSAL, STREAM},
    ),
    (
        "the directory taken out of the caller's hands",
        "C.java",
        'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/").resolve(FilenameUtils.getName(file)));\n  }\n}\n',
        set(),
        {TRAVERSAL, STREAM},
    ),
    (
        "a stream the application opened itself",
        "C.java",
        'public class C {\n  @PostMapping("/restore")\n  public void restore(HttpServletRequest request) throws Exception {\n    ObjectInputStream in = new ObjectInputStream(new FileInputStream("/var/state.ser"));\n    state = in.readObject();\n  }\n}\n',
        set(),
        {TRAVERSAL, STREAM},
    ),
    (
        "request bytes read as json rather than as java",
        "C.java",
        'public class C {\n  @PostMapping("/restore")\n  public void restore(HttpServletRequest request) throws Exception {\n    JsonNode in = mapper.readTree(request.getInputStream());\n    state = in.readObject();\n  }\n}\n',
        set(),
        {TRAVERSAL, STREAM},
    ),
    (
        "a line waiver naming the rule it waives",
        "C.java",
        'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + file));  // chock: allow java-path-traversal-request-data\n  }\n}\n',
        set(),
        {TRAVERSAL, STREAM},
    ),
    (
        "a line waiver naming another rule",
        "C.java",
        'public class C {\n  @GetMapping("/download")\n  public byte[] download(@RequestParam String file) throws Exception {\n    return Files.readAllBytes(Paths.get("/srv/files/" + file));  // chock: allow other\n  }\n}\n',
        {"java-path-traversal-request-data"},
        {TRAVERSAL, STREAM},
    ),
    (
        "an outbound URL the caller names outright",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@RequestParam String target) throws Exception {\n    return new URL(target).openStream();\n  }\n}\n',
        {"java-ssrf-request-url"},
        {"java-ssrf-request-url"},
    ),
    (
        "a scheme fixed but the host left to the caller",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@RequestParam String target) throws Exception {\n    return restTemplate.getForObject("https://" + target + "/v1", String.class);\n  }\n}\n',
        {"java-ssrf-request-url"},
        {"java-ssrf-request-url"},
    ),
    (
        "a fixed host with the value as a URI template variable",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@RequestParam String target) throws Exception {\n    return restTemplate.getForObject("https://api.weather.example/v1?city={c}", String.class, target);\n  }\n}\n',
        set(),
        {"java-ssrf-request-url"},
    ),
    (
        "a fixed host with the value in the path",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@RequestParam String target) throws Exception {\n    return new URL("https://api.example.com/v1/items/" + target).openStream();\n  }\n}\n',
        set(),
        {"java-ssrf-request-url"},
    ),
    (
        "a relative Location on this server",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@RequestParam String target) throws Exception {\n    return ResponseEntity.created(URI.create("/api/items/" + target)).build();\n  }\n}\n',
        set(),
        {"java-ssrf-request-url"},
    ),
    (
        "a numeric path variable cannot carry ../",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@PathVariable Long id) throws Exception {\n    return Files.readAllBytes(base.resolve(id + ".png"));\n  }\n}\n',
        set(),
        {TRAVERSAL},
    ),
    (
        "a UUID path variable cannot carry ../",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@PathVariable("id") UUID id) throws Exception {\n    return Files.readAllBytes(base.resolve(id + ".png"));\n  }\n}\n',
        set(),
        {TRAVERSAL},
    ),
    (
        "a string path variable still can",
        "C.java",
        'public class C {\n  @GetMapping("/x")\n  public Object x(@PathVariable String id) throws Exception {\n    return Files.readAllBytes(base.resolve(id + ".png"));\n  }\n}\n',
        {"java-path-traversal-request-data"},
        {TRAVERSAL},
    ),
    (
        "one-line methods, back to back, are each read",
        "C.java",
        'public class C {\n  @GetMapping("/a") public byte[] a(@RequestParam String f) throws Exception { return Files.readAllBytes(Paths.get("/srv/" + f)); }\n  @GetMapping("/b") public byte[] b(@RequestParam String f) throws Exception { return Files.readAllBytes(Paths.get("/srv/" + f)); }\n}\n',
        {TRAVERSAL},
        {TRAVERSAL},
    ),
]


def _download(body: str) -> str:
    return (
        'public class C {\n  @GetMapping("/download")\n'
        f"  public byte[] download(@RequestParam String file) throws Exception {{\n    {body}\n  }}\n}}\n"
    )


#: A sanitizer's name somewhere on the line is not a sanitizer applied to the request data.
_NAMED_NOT_APPLIED = {
    "a line comment naming a sanitizer": 'return Files.readAllBytes(Paths.get("/srv/" + file)); // TODO sanitize later',
    "a sanitizer name inside a string literal": 'return Files.readAllBytes(Paths.get("/srv/sanitize/" + file));',
    "a block comment naming a validator": 'return Files.readAllBytes(Paths.get("/srv/" + file)); /* isValid */',
    "a block comment opened on an earlier line": 'return read(/* sanitize the name\n     normalize() first */ Paths.get("/srv/" + file));',
    "a sanitizer applied to another value": 'audit(sanitize(other));\n    return Files.readAllBytes(Paths.get("/srv/" + file));',
    "a sanitizer in a variable name": 'String unsanitized = file;\n    return Files.readAllBytes(Paths.get("/srv/" + unsanitized));',
    "a sanitizer whose result is thrown away": 'sanitize(file); return Files.readAllBytes(Paths.get("/srv/" + file));',
    "the raw value beside its sanitized form": 'return Files.readAllBytes(Paths.get("/srv/" + file, sanitize(file)));',
    "startsWith on a literal": 'return Files.readAllBytes(Paths.get("/srv/" + file + ("".startsWith(file) ? "" : "")));',
    "a name ending in a sanitizer's": 'return Files.readAllBytes(Paths.get("/srv/", desanitize(file)));',
    "a sink after an escaped line break in a comment": '// ok \\u000a return Files.readAllBytes(Paths.get("/srv/" + file));',
}

#: The forms that really check the value the line carries.
_APPLIED = {
    "the name taken with FilenameUtils": 'return Files.readAllBytes(Paths.get("/srv/", FilenameUtils.getName(file)));',
    "resolved, normalized and checked against the base": "Path p = Paths.get(base, file).normalize();\n    if (!p.startsWith(base)) throw new IllegalArgumentException();\n    return Files.readAllBytes(p);",
    "normalized inside the call": "return Files.readAllBytes(Paths.get(base, file).normalize());",
    "a validator called on the value": "if (!validator.isValid(file)) throw new IllegalArgumentException();\n    return Files.readAllBytes(Paths.get(base, sanitize(file)));",
    "an allowlist consulted with the value": "return Files.readAllBytes(Paths.get(base, allowlist.get(file)));",
    "a pattern the value must match": 'return Files.readAllBytes(Paths.get(base, file.matches("[a-z]+") ? file : "x"));',
    "a named pattern the value must match": 'return Files.readAllBytes(Paths.get(base, file.matches(SAFE_NAME) ? file : "x"));',
    "normalized after a space": "return Files.readAllBytes(Paths.get(base, file) .normalize());",
    "a startsWith guard on the value": 'if (file.startsWith("docs/")) return Files.readAllBytes(Paths.get(base, sanitize(file)));',
    "sanitized, then assigned on the same line": "String safe = sanitize(file); return Files.readAllBytes(Paths.get(base, safe));",
}

FLOW_CASES += [
    (f"{label}: still refused", "C.java", _download(body), {TRAVERSAL}, {TRAVERSAL})
    for label, body in _NAMED_NOT_APPLIED.items()
] + [(f"{label}: allowed", "C.java", _download(body), set(), {TRAVERSAL}) for label, body in _APPLIED.items()]
