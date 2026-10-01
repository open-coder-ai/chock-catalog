"""A normalized path is a check only once held to its base; a constant allowlist lookup replaces the value."""

from __future__ import annotations

import pytest
from chock_security.decision import FileText
from chock_security.flow import flows
from chock_security.rules import registry

SINKS = ["new File(", "Paths.get(", "Files.readAllBytes("]
F = "@RequestParam String f"


def _lines(body: str, sinks: list[str] = SINKS) -> list[int]:
    text = f'public class C {{\n  @GetMapping("/x")\n  public Object x({F}) throws Exception {{\n    {body}\n  }}\n}}\n'
    return [flow.line_no for flow in flows(FileText("C.java", text), sinks)]


NORMALIZED = "Path p = Paths.get(base, f).normalize();\n    "


@pytest.mark.parametrize(
    "body",
    [
        "return Files.readAllBytes(Paths.get(base, f).normalize());",
        "return new File(Paths.get(base, f).normalize().toString());",
        NORMALIZED + "return Files.readAllBytes(p);",
        NORMALIZED + 'if (!p.startsWith("")) throw new IllegalStateException();\n    return Files.readAllBytes(p);',
        NORMALIZED + "if (!q.startsWith(base)) throw new IllegalStateException();\n    return Files.readAllBytes(p);",
        NORMALIZED + "p.startsWith(base);\n    return Files.readAllBytes(p);",
        NORMALIZED + "log(base.startsWith(p));\n    return Files.readAllBytes(p);",
        NORMALIZED + "if (!base.startsWith(p)) throw new IllegalStateException();\n    return Files.readAllBytes(p);",
        NORMALIZED
        + "p = p.resolve(f);\n    if (!p.startsWith(base)) throw new IllegalStateException();\n    return Files.readAllBytes(p);",
        "Path p = Paths.get(base, f).normalize().resolve(f);\n    if (!p.startsWith(base)) return null;\n    return Files.readAllBytes(p);",
    ],
)
def test_normalize_without_a_containment_check_on_that_value_is_refused(body: str) -> None:
    assert _lines(body), body


@pytest.mark.parametrize(
    "body",
    [
        NORMALIZED + "if (!p.startsWith(base)) throw new IllegalStateException();\n    return Files.readAllBytes(p);",
        NORMALIZED + "if (p.startsWith(base)) {\n      return Files.readAllBytes(p);\n    }\n    return null;",
        NORMALIZED
        + 'if (!p.startsWith("/srv/files/")) throw new IllegalStateException();\n    return Files.readAllBytes(p);',
        NORMALIZED + "assert p.startsWith(base);\n    return Files.readAllBytes(p);",
        NORMALIZED + "Preconditions.checkArgument(p.startsWith(base));\n    return Files.readAllBytes(p);",
        "Path p = Paths.get(base, f).toRealPath();\n    if (!p.startsWith(base)) return null;\n    return Files.readAllBytes(p);",
        "String c = new File(base, f).getCanonicalPath();\n    if (!c.startsWith(base)) return null;\n    return Files.readAllBytes(Paths.get(c));",
        "if (Paths.get(base, f).normalize().startsWith(base)) return Files.readAllBytes(Paths.get(base, f));",
        "return Files.readAllBytes(Paths.get(base, FilenameUtils.getName(f)).normalize());",
    ],
)
def test_normalize_then_a_containment_check_on_the_same_value_passes(body: str) -> None:
    assert _lines(body) == [], body


def test_a_refused_normalized_path_is_reported_where_it_is_built() -> None:
    assert _lines(NORMALIZED + "return null;") == [4]
    assert _lines(NORMALIZED + "return Files.readAllBytes(p);") == [4, 5]
    held = NORMALIZED + "if (!p.startsWith(base)) throw new IllegalStateException();\n    return Files.readAllBytes(p);"
    assert _lines(held) == []


@pytest.mark.parametrize(
    "body",
    [
        "return new File(base, ALLOWED.get(f));",
        "String s = ALLOWED.get(f);\n    return new File(base, s);",
        "return new File(base, Config.ALLOWED_NAMES.get(f));",
        'return new File(base, Map.of("a", "a.txt", "b", "b.txt").get(f));',
        "if (ALLOWED.contains(f)) return new File(base, f);",
        'return new File(base, Set.of("a", "b").contains(f) ? f : "a");',
        "if (NAMES.containsKey(f)) return new File(base, f);",
    ],
)
def test_a_lookup_in_a_constant_allowlist_is_a_check(body: str) -> None:
    assert _lines(body) == [], body


@pytest.mark.parametrize(
    "body",
    [
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
    ],
)
def test_a_lookup_that_does_not_replace_the_raw_value_is_not_a_check(body: str) -> None:
    assert _lines(body) == [4] or _lines(body) == [5], body


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
