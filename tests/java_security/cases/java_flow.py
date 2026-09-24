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
