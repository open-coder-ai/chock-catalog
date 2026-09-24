"""Cases for the jakarta pack: Jakarta EE and other frameworks.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

from java_security.cases.jakarta_config import CASES as CONFIG_CASES
from java_security.cases.jakarta_edges import CASES as EDGE_CASES

OPEN_REDIRECT = "jakarta-open-redirect"
FORWARD = "jakarta-forward-request-path"
CORS = "jakarta-cors-wildcard-credentials"
LISTING = "jakarta-directory-listing"
METHOD_CONSTRAINT = "jakarta-http-method-constraint"
STRUTS = "jakarta-struts-ognl"
COOKIE = "jakarta-insecure-cookie"
SECURITY_DISABLED = "jakarta-security-disabled"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # -- jakarta-open-redirect --------------------------------------------------------------
    (
        OPEN_REDIRECT,
        "Redirect.java",
        "import jakarta.ws.rs.QueryParam;\n"
        "public class Redirect {\n"
        '  public void go(@QueryParam("next") String next, HttpServletResponse response) throws Exception {\n'
        "    response.sendRedirect(next);\n"
        "  }\n}\n",
        [4],
    ),
    (
        OPEN_REDIRECT,
        "Redirect.java",
        "import jakarta.ws.rs.QueryParam;\n"
        "public class Redirect {\n"
        '  public void go(@QueryParam("next") String next, HttpServletResponse response) throws Exception {\n'
        '    response.sendRedirect("/home");\n'
        "  }\n}\n",
        [],
    ),
    (
        OPEN_REDIRECT,
        "Redirect.java",
        "import jakarta.ws.rs.QueryParam;\n"
        "public class Redirect {\n"
        '  public void go(@QueryParam("next") String next, HttpServletResponse response) throws Exception {\n'
        '    response.sendRedirect(allowlist.contains(next) ? next : "/home");\n'
        "  }\n}\n",
        [],
    ),
    (
        OPEN_REDIRECT,
        "Redirect.java",
        "import org.springframework.web.bind.annotation.GetMapping;\n"
        "import org.springframework.web.bind.annotation.RequestParam;\n"
        "public class Redirect {\n"
        "  public void go(@RequestParam String next, HttpServletResponse response) throws Exception {\n"
        "    response.sendRedirect(next);\n"
        "  }\n}\n",
        [],
    ),
    # -- jakarta-forward-request-path --------------------------------------------------------
    (
        FORWARD,
        "Forward.java",
        "import jakarta.servlet.http.HttpServletRequest;\n"
        "public class Forward {\n"
        '  public void go(@QueryParam("page") String page, HttpServletRequest request) throws Exception {\n'
        "    request.getRequestDispatcher(page).forward(request, response);\n"
        "  }\n}\n",
        [4],
    ),
    (
        FORWARD,
        "Forward.java",
        "import jakarta.servlet.http.HttpServletRequest;\n"
        "public class Forward {\n"
        '  public void go(@QueryParam("page") String page, HttpServletRequest request) throws Exception {\n'
        '    request.getRequestDispatcher("/WEB-INF/views/home.jsp").forward(request, response);\n'
        "  }\n}\n",
        [],
    ),
    (
        FORWARD,
        "Forward.java",
        "import jakarta.servlet.http.HttpServletRequest;\n"
        "public class Forward {\n"
        '  public void go(@QueryParam("page") String page, HttpServletRequest request) throws Exception {\n'
        '    request.getRequestDispatcher(isValid(page) ? page : "/WEB-INF/views/home.jsp")'
        ".forward(request, response);\n"
        "  }\n}\n",
        [],
    ),
    # -- jakarta-cors-wildcard-credentials ---------------------------------------------------
    (
        CORS,
        "CorsFilter.java",
        "import jakarta.servlet.Filter;\n"
        "public class CorsFilter implements Filter {\n"
        "  public void doFilter() {\n"
        '    response.setHeader("Access-Control-Allow-Credentials", "true");\n'
        '    response.setHeader("Access-Control-Allow-Origin", "*");\n'
        "  }\n}\n",
        [5],
    ),
    (
        CORS,
        "CorsFilter.java",
        "import jakarta.servlet.Filter;\n"
        "public class CorsFilter implements Filter {\n"
        "  public void doFilter() {\n"
        '    response.setHeader("Access-Control-Allow-Origin", "*");\n'
        "  }\n}\n",
        [],
    ),
    (
        CORS,
        "CorsFilter.java",
        "import jakarta.servlet.Filter;\n"
        "public class CorsFilter implements Filter {\n"
        "  public void doFilter() {\n"
        '    response.setHeader("Access-Control-Allow-Credentials", "true");\n'
        '    response.setHeader("Access-Control-Allow-Origin", "https://app.example.com");\n'
        "  }\n}\n",
        [],
    ),
    (
        CORS,
        "Cors.java",
        "import io.vertx.ext.web.handler.CorsHandler;\n"
        "public class Cors {\n"
        "  public void configure() {\n"
        '    CorsHandler handler = CorsHandler.create("*").allowCredentials(true);\n'
        "  }\n}\n",
        [4],
    ),
    (
        CORS,
        "Cors.java",
        "import io.vertx.ext.web.handler.CorsHandler;\n"
        "public class Cors {\n"
        "  public void configure() {\n"
        '    CorsHandler handler = CorsHandler.create("*");\n'
        "  }\n}\n",
        [],
    ),
    (
        CORS,
        "application.properties",
        "quarkus.http.cors.origins=*\nquarkus.http.cors.access-control-allow-credentials=true\n",
        [1],
    ),
    (
        CORS,
        "application.properties",
        "quarkus.http.cors.origins=https://app.example.com\nquarkus.http.cors.access-control-allow-credentials=true\n",
        [],
    ),
    (CORS, "application.properties", "quarkus.http.cors.origins=*\n", []),
    (
        CORS,
        "application.yml",
        "micronaut:\n"
        "  server:\n"
        "    cors:\n"
        "      configurations:\n"
        "        web:\n"
        "          allow-credentials: true\n"
        "          allowed-origins:\n"
        '            - "*"\n',
        [8],
    ),
    (
        CORS,
        "application.yml",
        "micronaut:\n"
        "  server:\n"
        "    cors:\n"
        "      configurations:\n"
        "        web:\n"
        "          allow-credentials: true\n"
        "          allowed-origins:\n"
        '            - "https://app.example.com"\n',
        [],
    ),
    *CONFIG_CASES,
    *EDGE_CASES,
]
