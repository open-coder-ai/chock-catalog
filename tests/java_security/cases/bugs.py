"""Cases for the bugs pack: Bug patterns.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

STRING_IDENTITY = "bugs-string-identity-comparison"
EQUALS_NO_HASHCODE = "bugs-equals-without-hashcode"
EQUALS_NON_OBJECT = "bugs-equals-non-object-parameter"
BIGDECIMAL_DOUBLE = "bugs-bigdecimal-double-constructor"
NAN_COMPARISON = "bugs-nan-comparison"
IGNORED_RETURN = "bugs-ignored-return-value"
BOOLEAN_ASSIGN = "bugs-boolean-assignment-in-condition"
ARRAY_TOSTRING = "bugs-array-tostring"
THREAD_RUN = "bugs-thread-run-instead-of-start"
SELF_ASSIGNMENT = "bugs-self-assignment"
MATH_ABS = "bugs-math-abs-of-hashcode-or-random"
INT_DIV_DOUBLE = "bugs-integer-division-to-double"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # bugs-string-identity-comparison
    (STRING_IDENTITY, "C.java", 'if (name == "admin") {\n  x();\n}\n', [1]),
    (STRING_IDENTITY, "C.java", 'if ("admin" == name) {\n  x();\n}\n', [1]),
    (STRING_IDENTITY, "C.java", "if (name != new String(bytes)) {\n  x();\n}\n", [1]),
    (STRING_IDENTITY, "C.java", 'if (name.equals("admin")) {\n  x();\n}\n', []),
    (STRING_IDENTITY, "C.java", 'if ("admin".equals(name)) {\n  x();\n}\n', []),
    (STRING_IDENTITY, "C.java", "if (name == null) {\n  x();\n}\n", []),
    (STRING_IDENTITY, "C.java", '// if (name == "admin") return;\n', []),
    (STRING_IDENTITY, "C.java", 'String s = "name == \\"admin\\"";\n', []),
    # bugs-equals-without-hashcode
    (
        EQUALS_NO_HASHCODE,
        "Point.java",
        "public class Point {\n"
        "  private final int x;\n"
        "  @Override\n"
        "  public boolean equals(Object o) {\n"
        "    return o instanceof Point p && p.x == x;\n"
        "  }\n"
        "}\n",
        [4],
    ),
    (
        EQUALS_NO_HASHCODE,
        "Point.java",
        "public class Point {\n  private final int x;\n  @Override\n  public int hashCode() {\n    return x;\n  }\n}\n",
        [4],
    ),
    (
        EQUALS_NO_HASHCODE,
        "Point.java",
        "public class Point {\n"
        "  private final int x;\n"
        "  @Override\n"
        "  public boolean equals(Object o) {\n"
        "    return o instanceof Point p && p.x == x;\n"
        "  }\n"
        "  @Override\n"
        "  public int hashCode() {\n"
        "    return x;\n"
        "  }\n"
        "}\n",
        [],
    ),
    (
        EQUALS_NO_HASHCODE,
        "Empty.java",
        "public class Empty {\n  private final int x;\n}\n",
        [],
    ),
    (
        EQUALS_NO_HASHCODE,
        "Lombok.java",
        "@EqualsAndHashCode\npublic class Lombok {\n  public boolean equals(Object o) {\n    return true;\n  }\n}\n",
        [],
    ),
    (
        EQUALS_NO_HASHCODE,
        "Rec.java",
        "public record Rec(int x) {\n}\n",
        [],
    ),
    (
        EQUALS_NO_HASHCODE,
        "Truncated.java",
        "public class Truncated\n",
        [],
    ),
    (
        EQUALS_NO_HASHCODE,
        "Split.java",
        "public class Split {\n  public boolean\n  equals(Object o) { return true; }\n}\n",
        [],
    ),
    # bugs-equals-non-object-parameter
    (EQUALS_NON_OBJECT, "C.java", "public boolean equals(Foo o) {\n  return true;\n}\n", [1]),
    (EQUALS_NON_OBJECT, "C.java", "public boolean equals(Object o) {\n  return true;\n}\n", []),
    (EQUALS_NON_OBJECT, "C.java", "private boolean equals(Foo o) {\n  return true;\n}\n", []),
    (EQUALS_NON_OBJECT, "C.java", "public boolean sameAs(Foo o) {\n  return true;\n}\n", []),
    # bugs-bigdecimal-double-constructor
    (BIGDECIMAL_DOUBLE, "C.java", "BigDecimal price = new BigDecimal(0.1);\n", [1]),
    (BIGDECIMAL_DOUBLE, "C.java", "BigDecimal price = new BigDecimal(3.14f);\n", [1]),
    (BIGDECIMAL_DOUBLE, "C.java", 'BigDecimal price = new BigDecimal("0.1");\n', []),
    (BIGDECIMAL_DOUBLE, "C.java", "BigDecimal price = BigDecimal.valueOf(0.1);\n", []),
    (BIGDECIMAL_DOUBLE, "C.java", "BigDecimal price = new BigDecimal(100);\n", []),
    (BIGDECIMAL_DOUBLE, "C.java", "BigDecimal price = new BigDecimal(rate);\n", []),
    # bugs-nan-comparison
    (NAN_COMPARISON, "C.java", "if (x == Double.NaN) {\n  return;\n}\n", [1]),
    (NAN_COMPARISON, "C.java", "if (Float.NaN != y) {\n  return;\n}\n", [1]),
    (NAN_COMPARISON, "C.java", "if (Double.isNaN(x)) {\n  return;\n}\n", []),
    (NAN_COMPARISON, "C.java", "if (x.equals(Double.NaN)) {\n  return;\n}\n", []),
    (NAN_COMPARISON, "C.java", "if (Double.compare(x, Double.NaN) == 0) {\n  return;\n}\n", []),
    # bugs-ignored-return-value
    (IGNORED_RETURN, "C.java", "s.trim();\n", [1]),
    (IGNORED_RETURN, "C.java", "date.plusDays(1);\n", [1]),
    (IGNORED_RETURN, "C.java", "s = s.trim();\n", []),
    (IGNORED_RETURN, "C.java", "return s.trim();\n", []),
    (IGNORED_RETURN, "C.java", "if (s.trim().isEmpty()) {\n  return;\n}\n", []),
    (IGNORED_RETURN, "C.java", "list.add(x);\n", []),
    # bugs-boolean-assignment-in-condition
    (BOOLEAN_ASSIGN, "C.java", "if (found = true) {\n  x();\n}\n", [1]),
    (BOOLEAN_ASSIGN, "C.java", "while (done = false) {\n  x();\n}\n", [1]),
    (BOOLEAN_ASSIGN, "C.java", "if (found == true) {\n  x();\n}\n", []),
    (BOOLEAN_ASSIGN, "C.java", "if (found) {\n  x();\n}\n", []),
    (BOOLEAN_ASSIGN, "C.java", "if (found = computeFlag()) {\n  x();\n}\n", []),
    # bugs-array-tostring
    (ARRAY_TOSTRING, "C.java", "String[] names = load();\nlog.info(names.toString());\n", [2]),
    (ARRAY_TOSTRING, "C.java", "int[] ids = load();\nString s = ids.toString();\n", [2]),
    (ARRAY_TOSTRING, "C.java", "String[] names = load();\nlog.info(Arrays.toString(names));\n", []),
    (ARRAY_TOSTRING, "C.java", "List<String> names = load();\nlog.info(names.toString());\n", []),
    (
        ARRAY_TOSTRING,
        "C.java",
        "String[] names = load();\nList<String> other = load();\nlog.info(other.toString());\n",
        [],
    ),
    # bugs-thread-run-instead-of-start
    (THREAD_RUN, "C.java", "new Thread(task).run();\n", [1]),
    (THREAD_RUN, "C.java", "Thread worker = new Thread(task);\nworker.run();\n", [2]),
    (THREAD_RUN, "C.java", "new Thread(task).start();\n", []),
    (THREAD_RUN, "C.java", "Runnable task = load();\ntask.run();\n", []),
    # bugs-self-assignment
    (SELF_ASSIGNMENT, "C.java", "x = x;\n", [1]),
    (SELF_ASSIGNMENT, "C.java", "  count = count;\n", [1]),
    (SELF_ASSIGNMENT, "C.java", "this.x = x;\n", []),
    (SELF_ASSIGNMENT, "C.java", "x = y;\n", []),
    (SELF_ASSIGNMENT, "C.java", "count = count + 1;\n", []),
    # bugs-math-abs-of-hashcode-or-random
    (MATH_ABS, "C.java", "int h = Math.abs(key.hashCode());\n", [1]),
    (MATH_ABS, "C.java", "int n = Math.abs(random.nextInt());\n", [1]),
    (MATH_ABS, "C.java", "int a = Math.abs(x);\n", []),
    (MATH_ABS, "C.java", "int n = Math.abs(random.nextInt(100));\n", []),
    (MATH_ABS, "C.java", "int n = random.nextInt();\n", []),
    # bugs-integer-division-to-double
    (INT_DIV_DOUBLE, "C.java", "double ratio = 7 / 2;\n", [1]),
    (INT_DIV_DOUBLE, "C.java", "double ratio = -7 / 2;\n", [1]),
    (INT_DIV_DOUBLE, "C.java", "double ratio = 7.0 / 2;\n", []),
    (INT_DIV_DOUBLE, "C.java", "double ratio = a / b;\n", []),
    (INT_DIV_DOUBLE, "C.java", "int ratio = 7 / 2;\n", []),
    (INT_DIV_DOUBLE, "C.java", "double ratio = 7 / 0;\n", []),
]
