"""Cases for the jakarta pack: Jakarta EE and other frameworks.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

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
    (OPEN_REDIRECT, "Redirect.java",
     "import jakarta.ws.rs.QueryParam;\n"
     "public class Redirect {\n"
     "  public void go(@QueryParam(\"next\") String next, HttpServletResponse response) throws Exception {\n"
     "    response.sendRedirect(next);\n"
     "  }\n}\n", [4]),
    (OPEN_REDIRECT, "Redirect.java",
     "import jakarta.ws.rs.QueryParam;\n"
     "public class Redirect {\n"
     "  public void go(@QueryParam(\"next\") String next, HttpServletResponse response) throws Exception {\n"
     "    response.sendRedirect(\"/home\");\n"
     "  }\n}\n", []),
    (OPEN_REDIRECT, "Redirect.java",
     "import jakarta.ws.rs.QueryParam;\n"
     "public class Redirect {\n"
     "  public void go(@QueryParam(\"next\") String next, HttpServletResponse response) throws Exception {\n"
     "    response.sendRedirect(allowlist.contains(next) ? next : \"/home\");\n"
     "  }\n}\n", []),
    (OPEN_REDIRECT, "Redirect.java",
     "import org.springframework.web.bind.annotation.GetMapping;\n"
     "import org.springframework.web.bind.annotation.RequestParam;\n"
     "public class Redirect {\n"
     "  public void go(@RequestParam String next, HttpServletResponse response) throws Exception {\n"
     "    response.sendRedirect(next);\n"
     "  }\n}\n", []),
    # -- jakarta-forward-request-path --------------------------------------------------------
    (FORWARD, "Forward.java",
     "import jakarta.servlet.http.HttpServletRequest;\n"
     "public class Forward {\n"
     "  public void go(@QueryParam(\"page\") String page, HttpServletRequest request) throws Exception {\n"
     "    request.getRequestDispatcher(page).forward(request, response);\n"
     "  }\n}\n", [4]),
    (FORWARD, "Forward.java",
     "import jakarta.servlet.http.HttpServletRequest;\n"
     "public class Forward {\n"
     "  public void go(@QueryParam(\"page\") String page, HttpServletRequest request) throws Exception {\n"
     "    request.getRequestDispatcher(\"/WEB-INF/views/home.jsp\").forward(request, response);\n"
     "  }\n}\n", []),
    (FORWARD, "Forward.java",
     "import jakarta.servlet.http.HttpServletRequest;\n"
     "public class Forward {\n"
     "  public void go(@QueryParam(\"page\") String page, HttpServletRequest request) throws Exception {\n"
     "    request.getRequestDispatcher(isValid(page) ? page : \"/WEB-INF/views/home.jsp\")"
     ".forward(request, response);\n"
     "  }\n}\n", []),
    # -- jakarta-cors-wildcard-credentials ---------------------------------------------------
    (CORS, "CorsFilter.java",
     "import jakarta.servlet.Filter;\n"
     "public class CorsFilter implements Filter {\n"
     "  public void doFilter() {\n"
     "    response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n"
     "    response.setHeader(\"Access-Control-Allow-Origin\", \"*\");\n"
     "  }\n}\n", [5]),
    (CORS, "CorsFilter.java",
     "import jakarta.servlet.Filter;\n"
     "public class CorsFilter implements Filter {\n"
     "  public void doFilter() {\n"
     "    response.setHeader(\"Access-Control-Allow-Origin\", \"*\");\n"
     "  }\n}\n", []),
    (CORS, "CorsFilter.java",
     "import jakarta.servlet.Filter;\n"
     "public class CorsFilter implements Filter {\n"
     "  public void doFilter() {\n"
     "    response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n"
     "    response.setHeader(\"Access-Control-Allow-Origin\", \"https://app.example.com\");\n"
     "  }\n}\n", []),
    (CORS, "Cors.java",
     "import io.vertx.ext.web.handler.CorsHandler;\n"
     "public class Cors {\n"
     "  public void configure() {\n"
     "    CorsHandler handler = CorsHandler.create(\"*\").allowCredentials(true);\n"
     "  }\n}\n", [4]),
    (CORS, "Cors.java",
     "import io.vertx.ext.web.handler.CorsHandler;\n"
     "public class Cors {\n"
     "  public void configure() {\n"
     "    CorsHandler handler = CorsHandler.create(\"*\");\n"
     "  }\n}\n", []),
    (CORS, "application.properties",
     "quarkus.http.cors.origins=*\nquarkus.http.cors.access-control-allow-credentials=true\n", [1]),
    (CORS, "application.properties",
     "quarkus.http.cors.origins=https://app.example.com\n"
     "quarkus.http.cors.access-control-allow-credentials=true\n", []),
    (CORS, "application.properties",
     "quarkus.http.cors.origins=*\n", []),
    (CORS, "application.yml",
     "micronaut:\n"
     "  server:\n"
     "    cors:\n"
     "      configurations:\n"
     "        web:\n"
     "          allow-credentials: true\n"
     "          allowed-origins:\n"
     "            - \"*\"\n", [8]),
    (CORS, "application.yml",
     "micronaut:\n"
     "  server:\n"
     "    cors:\n"
     "      configurations:\n"
     "        web:\n"
     "          allow-credentials: true\n"
     "          allowed-origins:\n"
     "            - \"https://app.example.com\"\n", []),
    # -- jakarta-directory-listing ------------------------------------------------------------
    (LISTING, "web.xml",
     "<web-app>\n"
     "  <servlet>\n"
     "    <servlet-name>default</servlet-name>\n"
     "    <init-param>\n"
     "      <param-name>listings</param-name>\n"
     "      <param-value>true</param-value>\n"
     "    </init-param>\n"
     "  </servlet>\n</web-app>\n", [6]),
    (LISTING, "web.xml",
     "<web-app>\n"
     "  <servlet>\n"
     "    <servlet-name>default</servlet-name>\n"
     "    <init-param>\n"
     "      <param-name>listings</param-name>\n"
     "      <param-value>false</param-value>\n"
     "    </init-param>\n"
     "  </servlet>\n</web-app>\n", []),
    (LISTING, "jetty.xml",
     '<Configure><Set name="dirAllowed">true</Set></Configure>\n', [1]),
    (LISTING, "jetty.xml",
     '<Configure><Set name="dirAllowed">false</Set></Configure>\n', []),
    (LISTING, "standalone.xml",
     "<handler directory-listing=\"true\"/>\n", [1]),
    (LISTING, "standalone.xml",
     "<handler directory-listing=\"false\"/>\n", []),
    (LISTING, "Static.java",
     "import io.vertx.ext.web.handler.StaticHandler;\n"
     "public class Static {\n"
     "  public void configure(StaticHandler h) {\n"
     "    h.setDirectoryListing(true);\n"
     "  }\n}\n", [4]),
    (LISTING, "Static.java",
     "import io.vertx.ext.web.handler.StaticHandler;\n"
     "public class Static {\n"
     "  public void configure(StaticHandler h) {\n"
     "    h.setDirectoryListing(false);\n"
     "  }\n}\n", []),
    # -- jakarta-http-method-constraint -------------------------------------------------------
    (METHOD_CONSTRAINT, "web.xml",
     "<web-app>\n"
     "  <security-constraint>\n"
     "    <web-resource-collection>\n"
     "      <web-resource-name>admin</web-resource-name>\n"
     "      <url-pattern>/admin/*</url-pattern>\n"
     "      <http-method>GET</http-method>\n"
     "      <http-method>POST</http-method>\n"
     "    </web-resource-collection>\n"
     "  </security-constraint>\n</web-app>\n", [6]),
    (METHOD_CONSTRAINT, "web.xml",
     "<web-app>\n"
     "  <security-constraint>\n"
     "    <web-resource-collection>\n"
     "      <web-resource-name>admin</web-resource-name>\n"
     "      <url-pattern>/admin/*</url-pattern>\n"
     "      <http-method-omission>TRACE</http-method-omission>\n"
     "    </web-resource-collection>\n"
     "  </security-constraint>\n</web-app>\n", []),
    (METHOD_CONSTRAINT, "web.xml",
     "<web-app>\n"
     "  <security-constraint>\n"
     "    <web-resource-collection>\n"
     "      <web-resource-name>admin</web-resource-name>\n"
     "      <url-pattern>/admin/*</url-pattern>\n"
     "    </web-resource-collection>\n"
     "  </security-constraint>\n</web-app>\n", []),
    # -- jakarta-struts-ognl -------------------------------------------------------------------
    (STRUTS, "struts.xml",
     '<!DOCTYPE struts PUBLIC "-//Apache Software Foundation//DTD Struts Configuration 2.5//EN" '
     '"http://struts.apache.org/dtds/struts-2.5.dtd">\n'
     "<struts>\n"
     '  <constant name="struts.devMode" value="true" />\n'
     "</struts>\n", [3]),
    (STRUTS, "struts.xml",
     '<!DOCTYPE struts PUBLIC "-//Apache Software Foundation//DTD Struts Configuration 2.5//EN" '
     '"http://struts.apache.org/dtds/struts-2.5.dtd">\n'
     "<struts>\n"
     '  <constant name="struts.devMode" value="false" />\n'
     "</struts>\n", []),
    (STRUTS, "struts.properties",
     "struts.devMode=true\n", [1]),
    (STRUTS, "struts.properties",
     "struts.devMode=false\nstruts.ognl.allowStaticMethodAccess=false\n", []),
    (STRUTS, "app.properties",
     "some.other.key=true\n", []),
    # -- jakarta-insecure-cookie ---------------------------------------------------------------
    (COOKIE, "Session.java",
     "import jakarta.servlet.http.Cookie;\n"
     "public class Session {\n"
     "  public void set(HttpServletResponse response) {\n"
     "    Cookie cookie = new Cookie(\"session\", token);\n"
     "    cookie.setHttpOnly(false);\n"
     "    response.addCookie(cookie);\n"
     "  }\n}\n", [5]),
    (COOKIE, "Session.java",
     "import jakarta.servlet.http.Cookie;\n"
     "public class Session {\n"
     "  public void set(HttpServletResponse response) {\n"
     "    Cookie cookie = new Cookie(\"session\", token);\n"
     "    cookie.setHttpOnly(true);\n"
     "    cookie.setSecure(true);\n"
     "    response.addCookie(cookie);\n"
     "  }\n}\n", []),
    (COOKIE, "web.xml",
     "<web-app>\n"
     "  <session-config>\n"
     "    <cookie-config>\n"
     "      <http-only>false</http-only>\n"
     "      <secure>true</secure>\n"
     "    </cookie-config>\n"
     "  </session-config>\n</web-app>\n", [4]),
    (COOKIE, "web.xml",
     "<web-app>\n"
     "  <session-config>\n"
     "    <cookie-config>\n"
     "      <http-only>true</http-only>\n"
     "      <secure>true</secure>\n"
     "    </cookie-config>\n"
     "  </session-config>\n</web-app>\n", []),
    # -- jakarta-security-disabled -------------------------------------------------------------
    (SECURITY_DISABLED, "application.yml",
     "micronaut:\n  security:\n    enabled: false\n", [3]),
    (SECURITY_DISABLED, "application.yml",
     "micronaut:\n  security:\n    enabled: true\n", []),
    (SECURITY_DISABLED, "application-test.yml",
     "micronaut:\n  security:\n    enabled: false\n", []),
    (SECURITY_DISABLED, "application.properties",
     "micronaut.security.enabled=false\n", [1]),
    (SECURITY_DISABLED, "application.properties",
     "micronaut.security.enabled=true\n", []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    ("open redirect from a JAX-RS query param", "Redirect.java",
     "import jakarta.ws.rs.QueryParam;\n"
     "public class Redirect {\n"
     "  public void go(@QueryParam(\"next\") String next, HttpServletResponse response) throws Exception {\n"
     "    response.sendRedirect(next);\n"
     "  }\n}\n",
     {OPEN_REDIRECT}, {OPEN_REDIRECT, FORWARD, STRUTS}),
    ("dispatcher forward from a JAX-RS path param, past the open-redirect sink", "Forward.java",
     "import jakarta.servlet.http.HttpServletRequest;\n"
     "public class Forward {\n"
     "  public void go(@PathParam(\"page\") String page, HttpServletRequest request) throws Exception {\n"
     "    request.getRequestDispatcher(page).forward(request, response);\n"
     "  }\n}\n",
     {FORWARD}, {OPEN_REDIRECT, FORWARD}),
    ("a Spring controller redirecting a request param -- Spring's own pack, not this one", "Redirect.java",
     "import org.springframework.web.bind.annotation.GetMapping;\n"
     "import org.springframework.web.bind.annotation.RequestParam;\n"
     "public class Redirect {\n"
     "  @GetMapping(\"/go\")\n"
     "  public void go(@RequestParam String next, HttpServletResponse response) throws Exception {\n"
     "    response.sendRedirect(next);\n"
     "  }\n}\n",
     set(), {OPEN_REDIRECT, FORWARD, CORS}),
    ("Struts OGNL findValue built from a request-carried expression", "ShowAction.java",
     "import com.opensymphony.xwork2.ActionSupport;\n"
     "public class ShowAction extends ActionSupport {\n"
     "  public String execute(@QueryParam(\"expr\") String expr) throws Exception {\n"
     "    Object value = ActionContext.getContext().getValueStack().findValue(expr);\n"
     "    return SUCCESS;\n"
     "  }\n}\n",
     {STRUTS}, {STRUTS, OPEN_REDIRECT}),
    ("a wildcard CORS origin with no credentials anywhere in the file", "CorsFilter.java",
     "import jakarta.servlet.Filter;\n"
     "public class CorsFilter implements Filter {\n"
     "  public void doFilter() {\n"
     "    response.setHeader(\"Access-Control-Allow-Origin\", \"*\");\n"
     "  }\n}\n",
     set(), {CORS}),
    ("a servlet cookie set up correctly, alongside an unrelated open redirect", "Login.java",
     "import jakarta.servlet.http.Cookie;\n"
     "import jakarta.ws.rs.QueryParam;\n"
     "public class Login {\n"
     "  public void go(@QueryParam(\"next\") String next, HttpServletResponse response) {\n"
     "    Cookie cookie = new Cookie(\"session\", token);\n"
     "    cookie.setHttpOnly(true);\n"
     "    cookie.setSecure(true);\n"
     "    response.addCookie(cookie);\n"
     "    response.sendRedirect(next);\n"
     "  }\n}\n",
     {OPEN_REDIRECT}, {COOKIE, OPEN_REDIRECT}),
]
