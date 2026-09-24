"""Cases for the java pack's XML, archive and directory rules: XXE, XMLDecoder, zip slip, LDAP, XPath.

Rows are (rule id, path, text, line numbers the rule must report); an empty list is a correct
change the rule must stay silent on.
"""

from __future__ import annotations

CASES: list[tuple[str, str, str, list[int]]] = [
    (
        "java-xxe-parser",
        "X.java",
        "public class X {\n  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n}\n",
        [2],
    ),
    (
        "java-xxe-parser",
        "X.java",
        "public class X {\n"
        "  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        '  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
        "}\n",
        [],
    ),
    (
        "java-xxe-parser",
        "X.java",
        "public class X {\n"
        "  TransformerFactory tf = TransformerFactory.newInstance();\n"
        '  tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n'
        "}\n",
        [],
    ),
    (
        "java-xml-decoder",
        "X.java",
        "public class X {\n  XMLDecoder d = new XMLDecoder(in);\n  Object o = d.readObject();\n}\n",
        [2],
    ),
    (
        "java-xml-decoder",
        "X.java",
        "import org.yaml.snakeyaml.Yaml;\n"
        "import org.yaml.snakeyaml.constructor.Constructor;\n"
        "public class X {\n"
        "  Yaml yaml = new Yaml(new Constructor(Object.class));\n"
        "  Object o = yaml.load(input);\n"
        "}\n",
        [4],
    ),
    (
        "java-xml-decoder",
        "X.java",
        "import org.yaml.snakeyaml.Yaml;\n"
        "public class X {\n"
        "  Yaml yaml = new Yaml();\n"
        "  Object o = yaml.load(input);\n"
        "}\n",
        [],
    ),
    (
        "java-xml-decoder",
        "X.java",
        "import org.yaml.snakeyaml.Yaml;\n"
        "import org.yaml.snakeyaml.constructor.Constructor;\n"
        "public class X {\n"
        "  Yaml yaml = new Yaml(new Constructor(Person.class));\n"
        "  Object o = yaml.load(input);\n"
        "}\n",
        [],
    ),
    ("java-xml-decoder", "X.java", "public class X {\n  XMLEncoder e = new XMLEncoder(out);\n}\n", []),
    (
        "java-zip-slip",
        "Z.java",
        "public class Z {\n"
        "  public void extract(ZipInputStream zis, File dest) throws Exception {\n"
        "    ZipEntry entry = zis.getNextEntry();\n"
        "    File out = new File(dest, entry.getName());\n"
        "    write(out);\n"
        "  }\n}\n",
        [4],
    ),
    (
        "java-zip-slip",
        "Z.java",
        "public class Z {\n"
        "  public void extract(ZipInputStream zis, File dest) throws Exception {\n"
        "    ZipEntry entry = zis.getNextEntry();\n"
        "    File out = new File(dest, entry.getName());\n"
        "    String canon = dest.toPath().normalize().toString();\n"
        '    if (!out.toPath().normalize().startsWith(canon)) throw new IOException("bad entry");\n'
        "    write(out);\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-zip-slip",
        "Z.java",
        "public class Z {\n"
        "  public void extract(ZipInputStream zis, File dest) throws Exception {\n"
        "    ZipEntry entry = zis.getNextEntry();\n"
        "    File out = new File(dest, entry.getName());\n"
        "    Path real = out.toPath().toRealPath();\n"
        '    if (!real.startsWith(dest.toPath())) throw new IOException("bad entry");\n'
        "    write(out);\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-zip-slip",
        "F.java",
        "public class F {\n"
        "  public void copy(File src, File dir) {\n"
        "    File out = new File(dir, src.getName());\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-ldap-injection",
        "C.java",
        "import javax.naming.directory.DirContext;\n"
        "import javax.naming.directory.InitialDirContext;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public void find(@RequestParam String uid) throws Exception {\n"
        "    DirContext ctx = new InitialDirContext(env);\n"
        '    ctx.search("ou=people", "(uid=" + uid + ")", controls);\n'
        "  }\n}\n",
        [7],
    ),
    (
        "java-ldap-injection",
        "C.java",
        "import javax.naming.directory.DirContext;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public void find(@RequestParam String uid) throws Exception {\n"
        '    ctx.search("ou=people", "(uid=" + LdapEncoder.filterEncode(uid) + ")", controls);\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-ldap-injection",
        "C.java",
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public void find(@RequestParam String uid) throws Exception {\n"
        '    ctx.search("ou=people", "(uid=" + uid + ")", controls);\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-ldap-injection",
        "C.java",
        "import org.springframework.ldap.core.LdapTemplate;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public void find(@RequestParam String uid) throws Exception {\n"
        '    ldapTemplate.search(query().where("uid").is(uid), mapper);\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-xpath-injection",
        "C.java",
        "import javax.xml.xpath.XPath;\n"
        "import javax.xml.xpath.XPathFactory;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public String find(@RequestParam String username) throws Exception {\n"
        "    XPath xpath = XPathFactory.newInstance().newXPath();\n"
        '    return xpath.evaluate("//user[@name=\'" + username + "\']", doc);\n'
        "  }\n}\n",
        [7],
    ),
    (
        "java-xpath-injection",
        "C.java",
        "import javax.xml.xpath.XPath;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public String find(@RequestParam String username) throws Exception {\n"
        '    xpath.setXPathVariableResolver(resolver); xpath.compile("//user[@name=$username]");\n'
        '    return "";\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-xpath-injection",
        "C.java",
        "import javax.xml.xpath.XPath;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public String find(@RequestParam String username) throws Exception {\n"
        "    return xpath.evaluate(\"//user[@name='root']\", doc);\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-xpath-injection",
        "C.java",
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public String find(@RequestParam String username) throws Exception {\n"
        '    return xpath.evaluate("//user[@name=\'" + username + "\']", doc);\n'
        "  }\n}\n",
        [],
    ),
    (
        "java-xxe-parser",
        "Feed.java",
        "XMLInputFactory f = XMLInputFactory.newFactory();\nXMLStreamReader r = f.createXMLStreamReader(in);\n",
        [1],
    ),
    (
        "java-xxe-parser",
        "Feed.java",
        "DocumentBuilderFactory f = DocumentBuilderFactory.newDefaultInstance();\n"
        'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n',
        [],
    ),
]

#: A file that uses XPath can compile a regex from request data too: that is ReDoS's to report, and
#: the XPath rule's `.compile(` sink is not `Pattern.compile(`.
CASES += [
    (
        "java-xpath-injection",
        "C.java",
        "import javax.xml.xpath.XPath;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public boolean find(@RequestParam String pattern) {\n"
        "    return Pattern.compile(pattern).matcher(name).matches();\n"
        "  }\n}\n",
        [],
    ),
    (
        "java-xpath-injection",
        "C.java",
        "import javax.xml.xpath.XPath;\n"
        "public class C {\n"
        '  @GetMapping("/find")\n'
        "  public Object find(@RequestParam String expr) throws Exception {\n"
        "    return xpath.compile(expr).evaluate(doc);\n"
        "  }\n}\n",
        [5],
    ),
]
