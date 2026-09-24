"""Cases for the java pack's SAST additions: response headers/cookies, the response body, the
session, regex patterns and JavaMail -- all request-data flows into a Servlet-family sink.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

HEADER_INJECTION = "java-response-header-injection"
XSS_WRITER = "java-xss-writer"
SESSION_TRUST_BOUNDARY = "java-session-trust-boundary"
REGEX_REDOS = "java-regex-redos"
MAIL_HEADER_INJECTION = "java-mail-header-injection"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # -- java-response-header-injection -----------------------------------------------------
    (
        HEADER_INJECTION,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String name, HttpServletResponse response) {\n"
        '    response.setHeader("X-Name", name);\n'
        "  }\n}\n",
        [3],
    ),
    (
        HEADER_INJECTION,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String token, HttpServletResponse response) {\n"
        '    Cookie cookie = new Cookie("session", token);\n'
        "    response.addCookie(cookie);\n"
        "  }\n}\n",
        [3],
    ),
    (
        HEADER_INJECTION,
        "C.java",
        "public class C {\n"
        "  public void go(HttpServletRequest request, HttpServletResponse response) {\n"
        '    response.addHeader("X-Echo", request.getHeader("X-Echo"));\n'
        "  }\n}\n",
        [3],
    ),
    (
        HEADER_INJECTION,
        "C.java",
        "public class C {\n"
        "  public void go(HttpServletResponse response) {\n"
        '    response.setHeader("X-Frame-Options", "DENY");\n'
        "  }\n}\n",
        [],
    ),
    (
        HEADER_INJECTION,
        "C.java",
        "public class C {\n"
        "  public void go(@PathVariable Long id, HttpServletResponse response) {\n"
        '    response.setHeader("X-User-Id", String.valueOf(id));\n'
        "  }\n}\n",
        [],
    ),
    (
        HEADER_INJECTION,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String name, HttpServletResponse response) {\n"
        "    String safe = sanitize(name);\n"
        '    response.setHeader("X-Name", safe);\n'
        "  }\n}\n",
        [],
    ),
    # -- java-xss-writer -----------------------------------------------------------------------
    (
        XSS_WRITER,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String name, HttpServletResponse response) throws Exception {\n"
        "    response.getWriter().write(name);\n"
        "  }\n}\n",
        [3],
    ),
    (
        XSS_WRITER,
        "C.java",
        "public class C {\n"
        "  public void go(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        '    response.getWriter().println(request.getParameter("q"));\n'
        "  }\n}\n",
        [3],
    ),
    (
        XSS_WRITER,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String msg, HttpServletResponse response) throws Exception {\n"
        "    response.getOutputStream().print(msg);\n"
        "  }\n}\n",
        [3],
    ),
    (
        XSS_WRITER,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String name, HttpServletResponse response) throws Exception {\n"
        "    response.getWriter().write(HtmlUtils.htmlEscape(name));\n"
        "  }\n}\n",
        [],
    ),
    (
        XSS_WRITER,
        "C.java",
        "public class C {\n"
        "  public void go(HttpServletResponse response) throws Exception {\n"
        "    response.getWriter().write(service.csv());\n"
        "  }\n}\n",
        [],
    ),
    (
        XSS_WRITER,
        "C.java",
        "public class C {\n"
        "  public void go(@PathVariable Long id, HttpServletResponse response) throws Exception {\n"
        "    response.getWriter().write(String.valueOf(id));\n"
        "  }\n}\n",
        [],
    ),
    # -- java-session-trust-boundary -----------------------------------------------------------
    (
        SESSION_TRUST_BOUNDARY,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String role, HttpSession session) {\n"
        '    session.setAttribute("role", role);\n'
        "  }\n}\n",
        [3],
    ),
    (
        SESSION_TRUST_BOUNDARY,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String next, HttpServletRequest request) {\n"
        '    request.getSession().setAttribute("next", next);\n'
        "  }\n}\n",
        [3],
    ),
    (
        SESSION_TRUST_BOUNDARY,
        "C.java",
        "public class C {\n"
        "  public void go(HttpServletRequest request, HttpSession session) {\n"
        '    session.setAttribute("q", request.getParameter("q"));\n'
        "  }\n}\n",
        [3],
    ),
    (
        SESSION_TRUST_BOUNDARY,
        "C.java",
        "public class C {\n"
        "  public void go(HttpSession session) {\n"
        '    session.setAttribute("initialized", Boolean.TRUE);\n'
        "  }\n}\n",
        [],
    ),
    (
        SESSION_TRUST_BOUNDARY,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String role, HttpSession session) {\n"
        "    String checked = sanitize(role);\n"
        '    session.setAttribute("accountRole", checked);\n'
        "  }\n}\n",
        [],
    ),
    (
        SESSION_TRUST_BOUNDARY,
        "C.java",
        "public class C {\n"
        "  public void go(@PathVariable Long id, HttpSession session) {\n"
        '    session.setAttribute("id", id);\n'
        "  }\n}\n",
        [],
    ),
    # -- java-regex-redos ------------------------------------------------------------------------
    (
        REGEX_REDOS,
        "C.java",
        "public class C {\n  public void go(@RequestParam String expr) {\n    Pattern p = Pattern.compile(expr);\n  }\n}\n",
        [3],
    ),
    (
        REGEX_REDOS,
        "C.java",
        "public class C {\n"
        "  public void go(HttpServletRequest request) {\n"
        '    Pattern p = Pattern.compile(request.getParameter("re"));\n'
        "  }\n}\n",
        [3],
    ),
    (
        REGEX_REDOS,
        "C.java",
        'public class C {\n  public void go(@QueryParam("re") String re) {\n    Pattern p = Pattern.compile(re);\n  }\n}\n',
        [3],
    ),
    (
        REGEX_REDOS,
        "C.java",
        'public class C {\n  public void go(@RequestParam String value) {\n    Pattern p = Pattern.compile("^[a-z]+$");\n  }\n}\n',
        [],
    ),
    (
        REGEX_REDOS,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String value) {\n"
        "    Pattern p = Pattern.compile(Pattern.quote(value));\n"
        "  }\n}\n",
        [],
    ),
    (
        REGEX_REDOS,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String value) {\n"
        "    String safe = sanitize(value);\n"
        "    Pattern p = Pattern.compile(safe);\n"
        "  }\n}\n",
        [],
    ),
    # -- java-mail-header-injection ---------------------------------------------------------
    (
        MAIL_HEADER_INJECTION,
        "C.java",
        "import jakarta.mail.internet.MimeMessage;\n"
        "public class C {\n"
        "  public void go(@RequestParam String subject, MimeMessage msg) throws Exception {\n"
        "    msg.setSubject(subject);\n"
        "  }\n}\n",
        [4],
    ),
    (
        MAIL_HEADER_INJECTION,
        "C.java",
        "import jakarta.mail.Message;\n"
        "public class C {\n"
        "  public void go(@RequestParam String to, Message msg) throws Exception {\n"
        "    msg.addRecipient(Message.RecipientType.TO, to);\n"
        "  }\n}\n",
        [4],
    ),
    (
        MAIL_HEADER_INJECTION,
        "C.java",
        "import javax.mail.internet.MimeMessage;\n"
        "public class C {\n"
        "  public void go(@RequestParam String from, MimeMessage msg) throws Exception {\n"
        "    msg.setFrom(from);\n"
        "  }\n}\n",
        [4],
    ),
    (
        MAIL_HEADER_INJECTION,
        "C.java",
        "import jakarta.mail.internet.MimeMessage;\n"
        "public class C {\n"
        "  public void go(MimeMessage msg) throws Exception {\n"
        '    msg.setSubject("Welcome");\n'
        "  }\n}\n",
        [],
    ),
    (
        MAIL_HEADER_INJECTION,
        "C.java",
        "public class C {\n"
        "  public void go(@RequestParam String subject, ReportBuilder msg) {\n"
        "    msg.setSubject(subject);\n"
        "  }\n}\n",
        [],
    ),
    (
        MAIL_HEADER_INJECTION,
        "C.java",
        "import jakarta.mail.internet.MimeMessage;\n"
        "public class C {\n"
        "  public void go(@RequestParam String subject, MimeMessage msg) throws Exception {\n"
        "    String safe = sanitize(subject);\n"
        "    msg.setSubject(safe);\n"
        "  }\n}\n",
        [],
    ),
]
