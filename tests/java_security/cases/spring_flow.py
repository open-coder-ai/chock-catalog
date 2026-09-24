"""Flow cases for the spring pack: request data reaching SpEL, redirects and view names."""

from __future__ import annotations

_SPEL_GUARD = "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    (
        "spel: parsed expression from a request parameter",
        "Eval.java",
        _SPEL_GUARD
        + (
            "public class Eval {\n"
            "  public String eval(@RequestParam String expr) {\n"
            "    SpelExpressionParser parser = new SpelExpressionParser();\n"
            "    return parser.parseExpression(expr).getValue(String.class);\n"
            "  }\n}\n"
        ),
        {"spring-spel-injection"},
        {"spring-spel-injection"},
    ),
    (
        "spel: a constant expression string",
        "Eval.java",
        _SPEL_GUARD
        + (
            "public class Eval {\n"
            "  public String eval() {\n"
            "    SpelExpressionParser parser = new SpelExpressionParser();\n"
            '    return parser.parseExpression("1 + 1").getValue(String.class);\n'
            "  }\n}\n"
        ),
        set(),
        {"spring-spel-injection"},
    ),
    (
        "open-redirect: redirect: prefix built from a request parameter",
        "Go.java",
        (
            "@Controller\n"
            "public class Go {\n"
            "  public String go(@RequestParam String url) {\n"
            '    return "redirect:" + url;\n'
            "  }\n}\n"
        ),
        {"spring-open-redirect"},
        {"spring-open-redirect"},
    ),
    (
        "open-redirect: target resolved through an allowlist lookup",
        "Go.java",
        (
            "@Controller\n"
            "public class Go {\n"
            "  public String go(@RequestParam String url) {\n"
            "    String target = allowlist.get(url);\n"
            '    return "redirect:" + target;\n'
            "  }\n}\n"
        ),
        set(),
        {"spring-open-redirect"},
    ),
    (
        "view-name: request parameter concatenated into a returned view name",
        "User.java",
        (
            "@Controller\n"
            "public class User {\n"
            '  @GetMapping("/user")\n'
            "  public String user(@RequestParam String lang) {\n"
            '    return "user/" + lang;\n'
            "  }\n}\n"
        ),
        {"spring-view-name-injection"},
        {"spring-view-name-injection"},
    ),
    (
        "view-name: the same concatenation, but in a @RestController",
        "User.java",
        (
            "@RestController\n"
            "public class User {\n"
            '  @GetMapping("/user")\n'
            "  public String user(@RequestParam String lang) {\n"
            '    return "user/" + lang;\n'
            "  }\n}\n"
        ),
        set(),
        {"spring-view-name-injection"},
    ),
]
