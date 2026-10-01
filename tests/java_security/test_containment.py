"""Checks that hold on one side of a branch: containment of a normalized path, allowlist membership and lookups."""

from __future__ import annotations

import pytest
from chock_security.decision import FileText
from chock_security.flow import flows
from chock_security.rules import registry

SINKS = ["new File(", "Paths.get(", "Files.readAllBytes("]
F = "@RequestParam String f"
CONSTANTS = (
    '  private static final Map<String, String> ALLOWED = Map.of("a", "a.txt");\n'
    '  private static final Set<String> NAMES = Set.of("a", "b");\n'
)


def _lines(body: str, fields: str = CONSTANTS) -> list[int]:
    """The body's lines that a sink takes request data on; the fields follow the method."""
    text = f'public class C {{\n  @GetMapping("/x")\n  public Object x({F}) throws Exception {{\n    {body}\n  }}\n{fields}}}\n'
    return [flow.line_no for flow in flows(FileText("C.java", text), SINKS)]


P = "Path p = Paths.get(base, f).normalize();\n    "
READ = "\n    return Files.readAllBytes(p);"
THROW = " throw new IllegalStateException();"


def _guarded(guard: str) -> str:
    return P + guard + READ


REFUSED_CONTAINMENT = [
    "return Files.readAllBytes(Paths.get(base, f).normalize());",
    "return new File(Paths.get(base, f).normalize().toString());",
    P + "return Files.readAllBytes(p);",
    _guarded('if (!p.startsWith("")) throw new IllegalStateException();'),
    _guarded("if (!q.startsWith(base)) throw new IllegalStateException();"),
    _guarded("p.startsWith(base);"),
    _guarded("log(base.startsWith(p));"),
    _guarded("if (!base.startsWith(p)) throw new IllegalStateException();"),
    P + "p = p.resolve(f);\n    if (!p.startsWith(base)) throw new IllegalStateException();" + READ,
    "Path p = Paths.get(base, f).normalize().resolve(f);\n    if (!p.startsWith(base)) return null;" + READ,
    # a Java assert is off by default
    _guarded("assert p.startsWith(base);"),
    # a check whose failing branch does not leave
    _guarded('if (!p.startsWith(base)) log.warn("outside");'),
    _guarded("if (!p.startsWith(base)) {\n      log();\n    }"),
    _guarded("if (!p.startsWith(base)) log();\n    else cleanup();"),
    "Path p = Paths.get(base, f).normalize(); if (!p.startsWith(base)) log(); return Files.readAllBytes(p);",
    # a condition that can pass whatever the path is, or holds it to nothing
    _guarded("if (!p.startsWith(base) || ok) throw new IllegalStateException();"),
    _guarded("if (!p.startsWith(base) && ok) throw new IllegalStateException();"),
    _guarded('if (!p.startsWith("/")) throw new IllegalStateException();'),
    _guarded('if (!p.startsWith("./")) throw new IllegalStateException();'),
    _guarded("if (!p.startsWith(f)) throw new IllegalStateException();"),
    _guarded("if (!p.startsWith(base.resolve(f))) throw new IllegalStateException();"),
    _guarded("if (!(p.startsWith(base) && ok)) throw new IllegalStateException();"),
    # the wrong way round, or the check is not always on
    _guarded("if (p.startsWith(base)) log();"),
    _guarded("if (p.startsWith(base))\n      log();"),
    _guarded("if (p.startsWith(base)) {\n      log();\n    }"),
    _guarded("checkpoint(p.startsWith(base));"),
    _guarded("verifyAndLog(p.startsWith(base));"),
    _guarded("Objects.requireNonNull(p.startsWith(base));"),
    _guarded("Preconditions.checkArgument(!p.startsWith(base));"),
    _guarded("Preconditions.checkArgument(ok, p.startsWith(base));"),
    # a String path compared without a separator: /srv-evil starts with /srv
    "String c = new File(base, f).getCanonicalPath();\n    if (!c.startsWith(base)) return null;\n    return Files.readAllBytes(Paths.get(c));",
    'String c = Paths.get(base, f).normalize().toString();\n    if (!c.startsWith("/srv")) return null;\n    return Files.readAllBytes(Paths.get(c));',
    "String c = new File(base, f).getCanonicalPath();\n    if (!c.startsWith(File.separatorX)) return null;\n    return Files.readAllBytes(Paths.get(c));",
    "File c = new File(base, f).getCanonicalFile();\n    if (!c.startsWith(base)) return null;\n    return Files.readAllBytes(c.toPath());",
    # a variable derived from a canonical file is not tracked
    "File c = new File(base, f).getCanonicalFile();\n    Path p = c.toPath();\n    if (!p.startsWith(base)) return null;\n    return Files.readAllBytes(p);",
    # an exit that is not on every path to the sink
    _guarded("list.forEach(x -> { if (!p.startsWith(base)) return; });"),
    _guarded("list.forEach(x -> {\n      if (!p.startsWith(base)) return;\n    });"),
    _guarded("try { if (!p.startsWith(base)) throw new IllegalStateException(); } catch (Exception e) { }"),
    _guarded(
        "try {\n      if (!p.startsWith(base)) throw new IllegalStateException();\n    } catch (Exception e) {\n    }"
    ),
    _guarded("if (flag) { if (!p.startsWith(base)) throw new IllegalStateException(); }"),
    _guarded("if (flag) {\n      if (!p.startsWith(base)) throw new IllegalStateException();\n    }"),
    _guarded(
        "if (a) {\n      x();\n    } else if (!p.startsWith(base)) {\n      throw new IllegalStateException();\n    }"
    ),
    _guarded("if (a) { x(); } else if (!p.startsWith(base)) throw new IllegalStateException();"),
    _guarded("for (String q : xs) {\n      if (!p.startsWith(base)) continue;\n    }"),
    _guarded("for (String q : xs) { if (!p.startsWith(base)) continue; }"),
    _guarded("while (more()) {\n      if (!p.startsWith(base)) break;\n    }"),
    _guarded("switch (k) {\n      case 1:\n        if (!p.startsWith(base)) break;\n    }"),
    _guarded(
        "switch (k) {\n      case 1:\n        if (!p.startsWith(base)) break;\n      default:\n        read(p);\n    }"
    ),
    _guarded("switch (k) { case 1: if (!p.startsWith(base)) break; }"),
    _guarded("new Runnable() {\n      public void run() {\n        if (!p.startsWith(base)) return;\n      }\n    };"),
    _guarded("if (flag) {\n      Preconditions.checkArgument(p.startsWith(base));\n    }"),
    # a brace in a string, comment or char literal opens or closes no block
    _guarded('if (flag) { log("}"); if (!p.startsWith(base)) throw new IllegalStateException(); }'),
    _guarded('if (flag) {\n      log("}");\n      if (!p.startsWith(base)) throw new IllegalStateException();\n    }'),
    _guarded(
        "if (flag) {\n      char c = '}';\n      if (!p.startsWith(base)) throw new IllegalStateException();\n    }"
    ),
    _guarded("if (flag) {\n      /* } */\n      if (!p.startsWith(base)) throw new IllegalStateException();\n    }"),
    # the exit is the read
    "Path p = Paths.get(base, f).normalize();\n    if (!p.startsWith(base)) {\n      return Files.readAllBytes(p);\n    } else {\n      return null;\n    }",
    "Path p = Paths.get(base, f).normalize();\n    if (!p.startsWith(base)) return Files.readAllBytes(p);\n    return null;",
    "Path p = Paths.get(base, f).normalize();\n    if (!p.startsWith(base))\n      return Files.readAllBytes(p);\n    return null;",
    # a ternary whose branches the line does not hold
    P + "return Files.readAllBytes(p.startsWith(base) ?\n      p : null);",
    # the check ends where its block does
    "Path p = Paths.get(base, f).normalize();\n    if (p.startsWith(base)) {\n      log();\n    }\n    return Files.readAllBytes(p);",
    "Path p = Paths.get(base, f).normalize();\n    if (p.startsWith(base)) {\n      log();\n    } else {\n      cleanup();\n    }\n    return Files.readAllBytes(p);",
]


@pytest.mark.parametrize("body", REFUSED_CONTAINMENT)
def test_a_normalized_path_that_is_not_held_to_its_base_is_refused(body: str) -> None:
    assert _lines(body), body


ALLOWED_CONTAINMENT = [
    # a brace in a string, comment or char literal before a top-level guard changes nothing
    P + "char c = '}';\n    if (!p.startsWith(base)) throw new IllegalStateException();" + READ,
    P + "/* } */\n    if (!p.startsWith(base)) throw new IllegalStateException();" + READ,
    P + 'log("}");\n    if (!p.startsWith(base)) throw new IllegalStateException();' + READ,
    P + 'String t = """\n      }\n      """;\n    if (!p.startsWith(base)) throw new IllegalStateException();' + READ,
    P + "// }\n    if (!p.startsWith(base)) throw new IllegalStateException();" + READ,
    # an exit on every path to the sink: in the same block, or the same loop body
    P
    + "for (String q : xs) {\n      if (!p.startsWith(base)) continue;\n      Files.readAllBytes(p);\n    }\n    return null;",
    P
    + "for (String q : xs) {\n      if (!p.startsWith(base)) break;\n      Files.readAllBytes(p);\n    }\n    return null;",
    P
    + "if (flag) {\n      if (!p.startsWith(base)) throw new IllegalStateException();\n      return Files.readAllBytes(p);\n    }\n    return null;",
    P
    + "try {\n      if (!p.startsWith(base)) throw new IllegalStateException();\n      return Files.readAllBytes(p);\n    } catch (Exception e) {\n      return null;\n    }",
    P
    + "list.forEach(x -> {\n      if (!p.startsWith(base)) return;\n      Files.readAllBytes(p);\n    });\n    return null;",
    P + 'if (!p.startsWith(base)) throw new IllegalStateException("outside " + p);' + READ,
    _guarded("if (!p.startsWith(base)) throw new IllegalStateException();"),
    _guarded('if (!p.startsWith("/srv/files")) throw new IllegalStateException();'),
    _guarded("if (!p.startsWith(base)) return null;"),
    _guarded("if (!p.startsWith(base)) {\n      throw new IllegalStateException();\n    }"),
    _guarded("if (!p.startsWith(base)) {\n      return null;\n    }"),
    _guarded("if (!p.startsWith(base))\n      throw new IllegalStateException();"),
    _guarded("if (!p.startsWith(base)) {\n      throw new IllegalStateException();\n    }"),
    _guarded("if (!p.startsWith(base))\n    {\n      throw new IllegalStateException();\n    }"),
    _guarded("if (!(p.startsWith(base))) throw new IllegalStateException();"),
    _guarded("if (p == null)\n      return null;\n    if (!p.startsWith(base)) continue;"),
    "Path p = Paths.get(base, f).normalize(); if (!p.startsWith(base)) return null; return Files.readAllBytes(p);",
    P + "if (p.startsWith(base)) {\n      return Files.readAllBytes(p);\n    }\n    return null;",
    P + "if (p.startsWith(base)) return Files.readAllBytes(p);\n    return null;",
    P + "if (p.startsWith(base)) { return Files.readAllBytes(p); }\n    return null;",
    _guarded("if (!p.startsWith(base)) { throw new IllegalStateException(); }"),
    P + "if (ok && p.startsWith(base)) {\n      return Files.readAllBytes(p);\n    }\n    return null;",
    P + "if (p.startsWith(base)) {\n      return Files.readAllBytes(p);\n    } else {\n      return null;\n    }",
    P + "return p.startsWith(base) ? Files.readAllBytes(p) : null;",
    _guarded("Preconditions.checkArgument(p.startsWith(base));"),
    _guarded('Preconditions.checkArgument(p.startsWith(base), "outside");'),
    _guarded("Preconditions.checkState(p.startsWith(base));"),
    _guarded("Validate.isTrue(p.startsWith(base));"),
    _guarded('Assert.isTrue(p.startsWith(base), "x");'),
    "Path p = Paths.get(base, f).toRealPath();\n    if (!p.startsWith(base)) return null;" + READ,
    'String c = new File(base, f).getCanonicalPath();\n    if (!c.startsWith("/srv/files/")) return null;\n    return Files.readAllBytes(Paths.get(c));',
    'String c = new File(base, f).getCanonicalPath();\n    if (!c.startsWith("\\\\srv\\\\")) return null;\n    return Files.readAllBytes(Paths.get(c));',
    "String c = new File(base, f).getCanonicalPath();\n    if (!c.startsWith(base + File.separator)) return null;\n    return Files.readAllBytes(Paths.get(c));",
    'String c = new File(base, f).getCanonicalPath();\n    if (!c.startsWith(base + "/")) return null;\n    return Files.readAllBytes(Paths.get(c));',
    "if (Paths.get(base, f).normalize().startsWith(base)) return Files.readAllBytes(Paths.get(base, f));",
    "return Files.readAllBytes(Paths.get(base, FilenameUtils.getName(f)).normalize());",
]


@pytest.mark.parametrize("body", ALLOWED_CONTAINMENT)
def test_a_normalized_path_held_to_its_base_passes(body: str) -> None:
    assert _lines(body) == [], body


def test_a_refused_normalized_path_is_reported_where_it_is_built() -> None:
    assert _lines(P + "return null;") == [4]
    assert _lines(P + "return Files.readAllBytes(p);") == [4, 5]
    assert _lines(_guarded("if (!p.startsWith(base)) throw new IllegalStateException();")) == []


def test_a_path_cleared_inside_a_block_is_carried_again_after_it() -> None:
    body = P + "if (p.startsWith(base)) {\n      read(p);\n    }\n    return Files.readAllBytes(p);"
    assert _lines(body) == [8]


LOOKUP_REFUSED = [
    "return new File(base, ALLOWED.get(g) + f);",
    "ALLOWED.get(f);\n    return new File(base, f);",
    "return new File(base, f + ALLOWED.get(f));",
    "if (ALLOWED.get(f) != null) return new File(base, f);",
    "return new File(base, allowed.get(f));",
    "return new File(base, names.get(f));",
    "return new File(base, ALLOWED.getOrDefault(f, f));",
    'return new File(base, Map.of(f, "a").get("k"));',
    "return new File(base, Map.of(f, f).get(f));",
    "return new File(base, SOURCE.get(0).concat(f));",
    "return new File(base, f.contains(ALLOWED) ? f : null);",
    "return new File(base, ALLOWED.get(f.trim()) + f);",
    # membership the wrong way round
    "return new File(base, ALLOWED.containsKey(f) ? x : f);",
    "return new File(base, !ALLOWED.containsKey(f) ? f : x);",
    "if (!ALLOWED.containsKey(f)) log();\n    return new File(base, f);",
    "if (!ALLOWED.containsKey(f)) log(); return new File(base, f);",
    "if (!NAMES.contains(f) || ok) throw new IllegalStateException();\n    return new File(base, f);",
    "if (!NAMES.contains(f) && ok) throw new IllegalStateException();\n    return new File(base, f);",
    "if (NAMES.contains(f)) log();\n    return new File(base, f);",
    "if (NAMES.contains(f)) {\n      log();\n    }\n    return new File(base, f);",
    "if (NAMES.contains(f) || ok) return new File(base, f);\n    return null;",
    "Preconditions.checkArgument(!NAMES.contains(f));\n    return new File(base, f);",
    "if (!NAMES.contains(f.trim())) throw new IllegalStateException();\n    return new File(base, f);",
]


@pytest.mark.parametrize("body", LOOKUP_REFUSED)
def test_a_lookup_that_does_not_replace_the_raw_value_is_not_a_check(body: str) -> None:
    assert _lines(body), body


LOOKUP_ALLOWED = [
    "return new File(base, ALLOWED.get(f));",
    "String s = ALLOWED.get(f);\n    return new File(base, s);",
    'return new File(base, Map.of("a", "a.txt", "b", "b.txt").get(f));',
    "if (NAMES.contains(f)) return new File(base, f);",
    "if (ALLOWED.containsKey(f)) {\n      return new File(base, f);\n    }\n    return null;",
    'return new File(base, Set.of("a", "b").contains(f) ? f : "a");',
    'return new File(base, !NAMES.contains(f) ? "a" : f);',
    "return new File(base, NAMES.contains(f) ? f : null);",
    "if (!NAMES.contains(f)) throw new IllegalStateException();\n    return new File(base, f);",
    "if (!NAMES.contains(f)) {\n      return null;\n    }\n    return new File(base, f);",
    "if (!ALLOWED.containsKey(f))\n      throw new IllegalStateException();\n    return new File(base, f);",
    "Preconditions.checkArgument(NAMES.contains(f));\n    return new File(base, f);",
    "if (ok && NAMES.contains(f)) return new File(base, f);",
    "String q = NAMES.contains(f) ? (ok ? f : x) : y;\n    return new File(base, q);",
]


@pytest.mark.parametrize("body", LOOKUP_ALLOWED)
def test_a_lookup_in_an_immutable_constant_is_a_check(body: str) -> None:
    assert _lines(body) == [], body


@pytest.mark.parametrize(
    "fields",
    [
        "  private static final Map<String, String> ALLOWED = new HashMap<>();\n",
        '  private static Map<String, String> ALLOWED = Map.of("a", "a");\n',
        '  private final Map<String, String> ALLOWED = Map.of("a", "a");\n',
        '  private static final Map<String, String> ALLOWED = Map.of("a", "a");\n  static { ALLOWED.put("b", "b"); }\n',
        '  private static final Map<String, String> ALLOWED = Map.of("a", "a");\n  void add(String k) { ALLOWED.putAll(other); }\n',
        "  private static final Map<String, String> ALLOWED = Collections.unmodifiableMap(BACKING);\n",
        "",
    ],
)
def test_a_constant_that_is_not_visibly_immutable_is_not_an_allowlist(fields: str) -> None:
    assert _lines("return new File(base, ALLOWED.get(f));", fields)
    assert _lines("if (ALLOWED.containsKey(f)) return new File(base, f);", fields)


@pytest.mark.parametrize(
    "fields",
    [
        '  private static final Map<String, String> ALLOWED = Map.of("a", "a");\n',
        '  static final Map<String, String> ALLOWED = ImmutableMap.of("a", "a");\n',
        '  public final static Map<String, String> ALLOWED = Map.ofEntries(Map.entry("a", "a"));\n',
        "  private static final Map<String, String> ALLOWED = Map.copyOf(other());\n",
        '  private static final Map<String, String> ALLOWED = Collections.unmodifiableMap(new HashMap<>(Map.of("a", "a")));\n',
        '  private static final Map<String, String> ALLOWED = Map.of("a", "a");\n  String x = other.put("b", "b");\n',
    ],
)
def test_a_constant_declared_immutable_and_never_changed_is_an_allowlist(fields: str) -> None:
    assert _lines("return new File(base, ALLOWED.get(f));", fields) == []
    assert _lines("if (ALLOWED.containsKey(f)) return new File(base, f);", fields) == []


def test_a_constant_of_another_class_is_not_an_allowlist() -> None:
    assert _lines("return new File(base, Config.ALLOWED.get(f));")
    assert _lines("if (Config.NAMES.contains(f)) return new File(base, f);")


SEPARATORS = [chr(0x2028), chr(0x2029), "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85"]


@pytest.mark.parametrize("separator", SEPARATORS)
def test_finalize_override_reads_a_file_with_any_line_separator(separator: str) -> None:
    rule = registry()["resources-finalize-override"]
    lines = [
        "class C {",
        f"  // note{separator}still the comment",
        f'  String s = "a{separator}b";',
        f"  /* x{separator}y */",
        "  protected void finalize() {}",
        "}",
    ]
    file = FileText("C.java", "\n".join(lines) + "\n")
    assert [finding.line_no for finding in rule.scan(file)] == [len(file.lines) - 1]
    clean = FileText("C.java", file.text.replace("finalize", "close"))
    assert list(rule.scan(clean)) == []
