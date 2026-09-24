"""Flow cases for the jakarta pack: request data reaching a sink through a method body."""

from __future__ import annotations

from java_security.cases.jakarta import COOKIE, CORS, FORWARD, OPEN_REDIRECT, STRUTS

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    (
        "open redirect from a JAX-RS query param",
        "Redirect.java",
        "import jakarta.ws.rs.QueryParam;\n"
        "public class Redirect {\n"
        '  public void go(@QueryParam("next") String next, HttpServletResponse response) throws Exception {\n'
        "    response.sendRedirect(next);\n"
        "  }\n}\n",
        {OPEN_REDIRECT},
        {OPEN_REDIRECT, FORWARD, STRUTS},
    ),
    (
        "dispatcher forward from a JAX-RS path param, past the open-redirect sink",
        "Forward.java",
        "import jakarta.servlet.http.HttpServletRequest;\n"
        "public class Forward {\n"
        '  public void go(@PathParam("page") String page, HttpServletRequest request) throws Exception {\n'
        "    request.getRequestDispatcher(page).forward(request, response);\n"
        "  }\n}\n",
        {FORWARD},
        {OPEN_REDIRECT, FORWARD},
    ),
    (
        "a Spring controller redirecting a request param -- Spring's own pack, not this one",
        "Redirect.java",
        "import org.springframework.web.bind.annotation.GetMapping;\n"
        "import org.springframework.web.bind.annotation.RequestParam;\n"
        "public class Redirect {\n"
        '  @GetMapping("/go")\n'
        "  public void go(@RequestParam String next, HttpServletResponse response) throws Exception {\n"
        "    response.sendRedirect(next);\n"
        "  }\n}\n",
        set(),
        {OPEN_REDIRECT, FORWARD, CORS},
    ),
    (
        "Struts OGNL findValue built from a request-carried expression",
        "ShowAction.java",
        "import com.opensymphony.xwork2.ActionSupport;\n"
        "public class ShowAction extends ActionSupport {\n"
        '  public String execute(@QueryParam("expr") String expr) throws Exception {\n'
        "    Object value = ActionContext.getContext().getValueStack().findValue(expr);\n"
        "    return SUCCESS;\n"
        "  }\n}\n",
        {STRUTS},
        {STRUTS, OPEN_REDIRECT},
    ),
    (
        "a wildcard CORS origin with no credentials anywhere in the file",
        "CorsFilter.java",
        "import jakarta.servlet.Filter;\n"
        "public class CorsFilter implements Filter {\n"
        "  public void doFilter() {\n"
        '    response.setHeader("Access-Control-Allow-Origin", "*");\n'
        "  }\n}\n",
        set(),
        {CORS},
    ),
    (
        "a servlet cookie set up correctly, alongside an unrelated open redirect",
        "Login.java",
        "import jakarta.servlet.http.Cookie;\n"
        "import jakarta.ws.rs.QueryParam;\n"
        "public class Login {\n"
        '  public void go(@QueryParam("next") String next, HttpServletResponse response) {\n'
        '    Cookie cookie = new Cookie("session", token);\n'
        "    cookie.setHttpOnly(true);\n"
        "    cookie.setSecure(true);\n"
        "    response.addCookie(cookie);\n"
        "    response.sendRedirect(next);\n"
        "  }\n}\n",
        {OPEN_REDIRECT},
        {COOKIE, OPEN_REDIRECT},
    ),
]
