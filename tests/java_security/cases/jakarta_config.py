"""Cases for the jakarta pack's configuration rules: listing, method constraints, Struts, cookies, security off.

Rows are (rule id, path, text, line numbers the rule must report); an empty list is a correct
change the rule must stay silent on.
"""

from __future__ import annotations

LISTING = "jakarta-directory-listing"
METHOD_CONSTRAINT = "jakarta-http-method-constraint"
STRUTS = "jakarta-struts-ognl"
COOKIE = "jakarta-insecure-cookie"
SECURITY_DISABLED = "jakarta-security-disabled"

CASES: list[tuple[str, str, str, list[int]]] = [
    # -- jakarta-directory-listing ------------------------------------------------------------
    (
        LISTING,
        "web.xml",
        "<web-app>\n"
        "  <servlet>\n"
        "    <servlet-name>default</servlet-name>\n"
        "    <init-param>\n"
        "      <param-name>listings</param-name>\n"
        "      <param-value>true</param-value>\n"
        "    </init-param>\n"
        "  </servlet>\n</web-app>\n",
        [6],
    ),
    (
        LISTING,
        "web.xml",
        "<web-app>\n"
        "  <servlet>\n"
        "    <servlet-name>default</servlet-name>\n"
        "    <init-param>\n"
        "      <param-name>listings</param-name>\n"
        "      <param-value>false</param-value>\n"
        "    </init-param>\n"
        "  </servlet>\n</web-app>\n",
        [],
    ),
    (LISTING, "jetty.xml", '<Configure><Set name="dirAllowed">true</Set></Configure>\n', [1]),
    (LISTING, "jetty.xml", '<Configure><Set name="dirAllowed">false</Set></Configure>\n', []),
    (LISTING, "standalone.xml", '<handler directory-listing="true"/>\n', [1]),
    (LISTING, "standalone.xml", '<handler directory-listing="false"/>\n', []),
    (
        LISTING,
        "Static.java",
        "import io.vertx.ext.web.handler.StaticHandler;\n"
        "public class Static {\n"
        "  public void configure(StaticHandler h) {\n"
        "    h.setDirectoryListing(true);\n"
        "  }\n}\n",
        [4],
    ),
    (
        LISTING,
        "Static.java",
        "import io.vertx.ext.web.handler.StaticHandler;\n"
        "public class Static {\n"
        "  public void configure(StaticHandler h) {\n"
        "    h.setDirectoryListing(false);\n"
        "  }\n}\n",
        [],
    ),
    # -- jakarta-http-method-constraint -------------------------------------------------------
    (
        METHOD_CONSTRAINT,
        "web.xml",
        "<web-app>\n"
        "  <security-constraint>\n"
        "    <web-resource-collection>\n"
        "      <web-resource-name>admin</web-resource-name>\n"
        "      <url-pattern>/admin/*</url-pattern>\n"
        "      <http-method>GET</http-method>\n"
        "      <http-method>POST</http-method>\n"
        "    </web-resource-collection>\n"
        "  </security-constraint>\n</web-app>\n",
        [6],
    ),
    (
        METHOD_CONSTRAINT,
        "web.xml",
        "<web-app>\n"
        "  <security-constraint>\n"
        "    <web-resource-collection>\n"
        "      <web-resource-name>admin</web-resource-name>\n"
        "      <url-pattern>/admin/*</url-pattern>\n"
        "      <http-method-omission>TRACE</http-method-omission>\n"
        "    </web-resource-collection>\n"
        "  </security-constraint>\n</web-app>\n",
        [],
    ),
    (
        METHOD_CONSTRAINT,
        "web.xml",
        "<web-app>\n"
        "  <security-constraint>\n"
        "    <web-resource-collection>\n"
        "      <web-resource-name>admin</web-resource-name>\n"
        "      <url-pattern>/admin/*</url-pattern>\n"
        "    </web-resource-collection>\n"
        "  </security-constraint>\n</web-app>\n",
        [],
    ),
    # -- jakarta-struts-ognl -------------------------------------------------------------------
    (
        STRUTS,
        "struts.xml",
        '<!DOCTYPE struts PUBLIC "-//Apache Software Foundation//DTD Struts Configuration 2.5//EN" '
        '"http://struts.apache.org/dtds/struts-2.5.dtd">\n'
        "<struts>\n"
        '  <constant name="struts.devMode" value="true" />\n'
        "</struts>\n",
        [3],
    ),
    (
        STRUTS,
        "struts.xml",
        '<!DOCTYPE struts PUBLIC "-//Apache Software Foundation//DTD Struts Configuration 2.5//EN" '
        '"http://struts.apache.org/dtds/struts-2.5.dtd">\n'
        "<struts>\n"
        '  <constant name="struts.devMode" value="false" />\n'
        "</struts>\n",
        [],
    ),
    (STRUTS, "struts.properties", "struts.devMode=true\n", [1]),
    (STRUTS, "struts.properties", "struts.devMode=false\nstruts.ognl.allowStaticMethodAccess=false\n", []),
    (STRUTS, "app.properties", "some.other.key=true\n", []),
    # -- jakarta-insecure-cookie ---------------------------------------------------------------
    (
        COOKIE,
        "Session.java",
        "import jakarta.servlet.http.Cookie;\n"
        "public class Session {\n"
        "  public void set(HttpServletResponse response) {\n"
        '    Cookie cookie = new Cookie("session", token);\n'
        "    cookie.setHttpOnly(false);\n"
        "    response.addCookie(cookie);\n"
        "  }\n}\n",
        [5],
    ),
    (
        COOKIE,
        "Session.java",
        "import jakarta.servlet.http.Cookie;\n"
        "public class Session {\n"
        "  public void set(HttpServletResponse response) {\n"
        '    Cookie cookie = new Cookie("session", token);\n'
        "    cookie.setHttpOnly(true);\n"
        "    cookie.setSecure(true);\n"
        "    response.addCookie(cookie);\n"
        "  }\n}\n",
        [],
    ),
    (
        COOKIE,
        "web.xml",
        "<web-app>\n"
        "  <session-config>\n"
        "    <cookie-config>\n"
        "      <http-only>false</http-only>\n"
        "      <secure>true</secure>\n"
        "    </cookie-config>\n"
        "  </session-config>\n</web-app>\n",
        [4],
    ),
    (
        COOKIE,
        "web.xml",
        "<web-app>\n"
        "  <session-config>\n"
        "    <cookie-config>\n"
        "      <http-only>true</http-only>\n"
        "      <secure>true</secure>\n"
        "    </cookie-config>\n"
        "  </session-config>\n</web-app>\n",
        [],
    ),
    # -- jakarta-security-disabled -------------------------------------------------------------
    (SECURITY_DISABLED, "application.yml", "micronaut:\n  security:\n    enabled: false\n", [3]),
    (SECURITY_DISABLED, "application.yml", "micronaut:\n  security:\n    enabled: true\n", []),
    (SECURITY_DISABLED, "application-test.yml", "micronaut:\n  security:\n    enabled: false\n", []),
    (SECURITY_DISABLED, "application.properties", "micronaut.security.enabled=false\n", [1]),
    (SECURITY_DISABLED, "application.properties", "micronaut.security.enabled=true\n", []),
]
