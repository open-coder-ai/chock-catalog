"""Allowlist lookups and membership tests: by polarity, and only in a constant the file shows to be immutable."""

from __future__ import annotations

import pytest
from java_security.test_containment import lines_taken

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
    assert lines_taken(body), body


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
    assert lines_taken(body) == [], body


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
    assert lines_taken("return new File(base, ALLOWED.get(f));", fields)
    assert lines_taken("if (ALLOWED.containsKey(f)) return new File(base, f);", fields)


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
    assert lines_taken("return new File(base, ALLOWED.get(f));", fields) == []
    assert lines_taken("if (ALLOWED.containsKey(f)) return new File(base, f);", fields) == []


def test_a_constant_of_another_class_is_not_an_allowlist() -> None:
    assert lines_taken("return new File(base, Config.ALLOWED.get(f));")
    assert lines_taken("if (Config.NAMES.contains(f)) return new File(base, f);")
