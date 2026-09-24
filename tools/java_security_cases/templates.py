"""Cases for the templates pack: Templates and views.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

UNESCAPED = '<p th:utext="${bio}"></p>\n'
ESCAPED = '<p th:text="${bio}"></p>\n'
XSS = "java-xss-unescaped-template"
SSTI = "templates-ssti-request-template"
AUTOESCAPE = "templates-autoescape-disabled"
BUILTINS = "templates-freemarker-unsafe-builtins"
INCLUDE = "templates-include-request-path"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    ('java-xss-unescaped-template', 'p.html',
     '<p th:utext="${bio}"></p>\n', [1]),
    ('java-xss-unescaped-template', 'p.html',
     '<p th:text="${bio}"></p>\n', []),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%= user.getName() %>', [1]),
    ('java-xss-unescaped-template', 'p.jsp',
     '<c:out value="${b}" escapeXml="false"/>', [1]),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%-- a comment --%>', []),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%@ page session="false" %>', []),
    ('java-xss-unescaped-template', 'p.jsp',
     '<%! int i; %>', []),
    ('java-xss-unescaped-template', 'p.ftl',
     '${bio?no_esc}\n<#noescape>${x}</#noescape>', [1, 2]),
    ('java-xss-unescaped-template', 'Doc.java',
     '// th:utext is documented here', []),
    ('java-xss-unescaped-template', 'p.html',
     '<p>[(${bio})]</p>\n', [1]),
    ('java-xss-unescaped-template', 'p.html',
     '<p>[[${bio}]]</p>\n', []),
    ('java-xss-unescaped-template', 'p.xhtml',
     '<h:outputText value="#{bio}" escape="false"/>\n', [1]),
    ('java-xss-unescaped-template', 'p.xhtml',
     '<h:outputText value="#{bio}" escape="true"/>\n', []),
    ('java-xss-unescaped-template', 'p.peb',
     '{{ bio | raw }}\n', [1]),
    ('java-xss-unescaped-template', 'p.pebble',
     '{{ bio|raw }}\n', [1]),
    ('java-xss-unescaped-template', 'p.peb',
     '{{ bio }}\n', []),
    ('java-xss-unescaped-template', 'p.mustache',
     '{{{ bio }}}\n', [1]),
    ('java-xss-unescaped-template', 'p.hbs',
     '{{& bio }}\n', [1]),
    ('java-xss-unescaped-template', 'p.mustache',
     '{{ bio }}\n', []),

    # templates-autoescape-disabled
    (AUTOESCAPE, 'C.java',
     'import com.mitchellbosecke.pebble.PebbleEngine;\n'
     'public class C {\n'
     '  public void configure(PebbleEngine.Builder builder) {\n'
     '    builder.autoEscaping(false);\n'
     '  }\n}\n', [4]),
    (AUTOESCAPE, 'C.java',
     'import com.github.jknack.handlebars.Handlebars;\n'
     'public class C {\n'
     '  public void configure(Handlebars hb) {\n'
     '    hb.with(EscapingStrategy.NOOP);\n'
     '  }\n}\n', [4]),
    (AUTOESCAPE, 'C.java',
     'import freemarker.template.Configuration;\n'
     'public class C {\n'
     '  public void configure(Configuration cfg) {\n'
     '    cfg.setOutputFormat(PlainTextOutputFormat.INSTANCE);\n'
     '  }\n}\n', [4]),
    (AUTOESCAPE, 'p.ftlh',
     '<#ftl output_format="plainText">\n', [1]),
    (AUTOESCAPE, 'C.java',
     'builder.autoEscaping(false);\n', []),
    (AUTOESCAPE, 'C.java',
     'import freemarker.template.Configuration;\n'
     'public class C {\n'
     '  public void configure(Configuration cfg) {\n'
     '    cfg.setOutputFormat(HTMLOutputFormat.INSTANCE);\n'
     '  }\n}\n', []),
    (AUTOESCAPE, 'p.ftlh',
     '<#ftl>\n<p>${bio}</p>\n', []),

    # templates-freemarker-unsafe-builtins
    (BUILTINS, 'p.ftl',
     '${"freemarker.template.utility.Execute"?new()}\n', [1]),
    (BUILTINS, 'p.ftl',
     '${myBean?api.getClass().getClassLoader()}\n', [1]),
    (BUILTINS, 'C.java',
     'cfg.setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER);\n', [1]),
    (BUILTINS, 'C.java',
     'cfg.setAPIBuiltinEnabled(true);\n', [1]),
    (BUILTINS, 'C.java',
     'cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);\n', []),
    (BUILTINS, 'C.java',
     'cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);\n', []),
    (BUILTINS, 'p.ftl',
     '${bio}\n', []),

    # templates-include-request-path
    (INCLUDE, 'p.jsp',
     '<jsp:include page="<%= request.getParameter(\"page\") %>"/>\n', [1]),
    (INCLUDE, 'p.jsp',
     '<c:import url="${param.page}"/>\n', [1]),
    (INCLUDE, 'p.jsp',
     '<jsp:include page="${param.page}"/>\n', [1]),
    (INCLUDE, 'p.html',
     '<div th:replace="${param.frag}"></div>\n', [1]),
    (INCLUDE, 'p.html',
     '<div th:insert="~{${param.frag}}"></div>\n', [1]),
    (INCLUDE, 'p.jsp',
     '<jsp:include page="/WEB-INF/header.jsp"/>\n', []),
    (INCLUDE, 'p.html',
     '<div th:replace="~{fragments/header :: header}"></div>\n', []),
    (INCLUDE, 'p.jsp',
     '<c:out value="${param.page}"/>\n', []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    ('a FreeMarker template compiled from a request parameter', "C.java",
     'import freemarker.template.Template;\n'
     'public class C {\n'
     '  @PostMapping("/preview")\n'
     '  public String preview(@RequestParam String body) throws Exception {\n'
     '    Template t = new Template("preview", body, cfg);\n'
     '    return render(t);\n'
     '  }\n}\n',
     {SSTI}, {SSTI}),
    ('a Thymeleaf string template resolver processing a request parameter', "C.java",
     'import org.thymeleaf.templateresolver.StringTemplateResolver;\n'
     'public class C {\n'
     '  @PostMapping("/preview")\n'
     '  public String preview(TemplateEngine templateEngine, @RequestParam String body) {\n'
     '    return templateEngine.process(body, context);\n'
     '  }\n}\n',
     {SSTI}, {SSTI}),
    ('a fixed FreeMarker template', "C.java",
     'import freemarker.template.Template;\n'
     'public class C {\n'
     '  public String preview(String body) throws Exception {\n'
     '    Template t = new Template("preview", "fixed content", cfg);\n'
     '    return render(t);\n'
     '  }\n}\n',
     set(), {SSTI}),
    ('a Template class with no FreeMarker import', "C.java",
     'public class C {\n'
     '  public String preview(@RequestParam String body) throws Exception {\n'
     '    Template t = new Template(body);\n'
     '    return render(t);\n'
     '  }\n}\n',
     set(), {SSTI}),
    ('Thymeleaf process with no StringTemplateResolver in the file', "C.java",
     'public class C {\n'
     '  @PostMapping("/preview")\n'
     '  public String preview(TemplateEngine templateEngine, @RequestParam String body) {\n'
     '    return templateEngine.process(body, context);\n'
     '  }\n}\n',
     set(), {SSTI}),
]
