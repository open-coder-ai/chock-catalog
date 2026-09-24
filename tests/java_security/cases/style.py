"""Cases for the style pack: Code style.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

REDUNDANT_IMPORT = "style-redundant-import"
SYSTEM_OUT_PRINTLN = "style-system-out-println"
BOOLEAN_LITERAL_COMPARISON = "style-boolean-literal-comparison"
EMPTY_STATEMENT = "style-empty-statement"
TYPE_NAME = "style-type-name"
CONSTANT_NAME = "style-constant-name"
MULTIPLE_VARIABLE_DECLARATIONS = "style-multiple-variable-declarations"
UPPER_ELL = "style-upper-ell"
ARRAY_TYPE_STYLE = "style-array-type-style"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # style-redundant-import
    (
        REDUNDANT_IMPORT,
        "C.java",
        "package com.acme;\n\nimport java.lang.String;\nimport java.util.List;\n\nclass C { List<String> l; }\n",
        [3],
    ),
    (
        REDUNDANT_IMPORT,
        "C.java",
        "package com.acme;\n\nimport java.util.List;\nimport java.util.List;\n\nclass C { List l; }\n",
        [4],
    ),
    (
        REDUNDANT_IMPORT,
        "C.java",
        "package com.acme;\n\nimport java.lang.*;\nimport java.util.List;\n\nclass C { List l; }\n",
        [3],
    ),
    (
        REDUNDANT_IMPORT,
        "com/acme/Widget.java",
        "package com.acme;\n\nimport com.acme.Helper;\n\nclass Widget { Helper h; }\n",
        [3],
    ),
    (
        REDUNDANT_IMPORT,
        "C.java",
        "package com.acme;\n\nimport static java.lang.Math.PI;\n\nclass C { double d = PI; }\n",
        [],
    ),
    (
        REDUNDANT_IMPORT,
        "C.java",
        "package com.acme;\n\nimport java.util.List;\nimport java.util.Map;\n\nclass C { List l; Map m; }\n",
        [],
    ),
    (
        REDUNDANT_IMPORT,
        "C.java",
        "import Widget;\n\nclass C { Widget w; }\n",
        [],
    ),
    # style-system-out-println
    (
        SYSTEM_OUT_PRINTLN,
        "src/main/java/com/acme/Service.java",
        'class Service {\n  void run() {\n    System.out.println("starting");\n  }\n}\n',
        [3],
    ),
    (
        SYSTEM_OUT_PRINTLN,
        "src/main/java/com/acme/Service.java",
        'class Service {\n  void run() {\n    System.err.print("oops");\n  }\n}\n',
        [3],
    ),
    (
        SYSTEM_OUT_PRINTLN,
        "src/main/java/com/acme/Reporter.java",
        'class Reporter {\n  void run() {\n    System.out.print("progress");\n  }\n}\n',
        [3],
    ),
    (
        SYSTEM_OUT_PRINTLN,
        "src/test/java/com/acme/ServiceTest.java",
        'class ServiceTest {\n  void t() {\n    System.out.println("debug");\n  }\n}\n',
        [],
    ),
    (
        # is_test_path's other branch: a bare filename ending in Test.java, no src/test/ directory.
        SYSTEM_OUT_PRINTLN,
        "ServiceTest.java",
        'class ServiceTest {\n  void t() {\n    System.out.println("debug");\n  }\n}\n',
        [],
    ),
    (
        SYSTEM_OUT_PRINTLN,
        "src/main/java/com/acme/Cli.java",
        'class Cli {\n  public static void main(String[] args) {\n    System.out.println("hi");\n  }\n}\n',
        [],
    ),
    (
        SYSTEM_OUT_PRINTLN,
        "src/main/java/com/acme/Service.java",
        'class Service {\n  // System.out.println("debug");\n  void run() {}\n}\n',
        [],
    ),
    # style-boolean-literal-comparison
    (BOOLEAN_LITERAL_COMPARISON, "C.java", "boolean b = (x == true);\n", [1]),
    (BOOLEAN_LITERAL_COMPARISON, "C.java", "boolean b = (false == x);\n", [1]),
    (BOOLEAN_LITERAL_COMPARISON, "C.java", "boolean b = (x != false);\n", [1]),
    (BOOLEAN_LITERAL_COMPARISON, "C.java", "boolean b = x;\n", []),
    (BOOLEAN_LITERAL_COMPARISON, "C.java", "boolean b = (x == y);\n", []),
    (BOOLEAN_LITERAL_COMPARISON, "C.java", "// b == true\n", []),
    # style-empty-statement
    (EMPTY_STATEMENT, "C.java", "if (ready());\n", [1]),
    (EMPTY_STATEMENT, "C.java", "for (int i = 0; i < 10; i++);\n", [1]),
    (EMPTY_STATEMENT, "C.java", "while (true);\n", [1]),
    (EMPTY_STATEMENT, "C.java", "if (ready()) { fire(); }\n", []),
    (EMPTY_STATEMENT, "C.java", "while (queue.poll() != null) {}\n", []),
    (
        EMPTY_STATEMENT,
        "C.java",
        "if (someVeryLongCondition\n    && other) {\n  doThing();\n}\n",
        [],
    ),
    # style-type-name
    (TYPE_NAME, "C.java", "class userService {}\n", [1]),
    (TYPE_NAME, "C.java", "interface http_client {}\n", [1]),
    (TYPE_NAME, "C.java", "enum status_code {}\n", [1]),
    (TYPE_NAME, "C.java", "class UserService {}\n", []),
    (TYPE_NAME, "C.java", "interface HttpClient {}\n", []),
    (TYPE_NAME, "C.java", "@interface MyAnnotation {}\n", []),
    # style-constant-name
    (CONSTANT_NAME, "C.java", 'private static final String tableName = "orders";\n', [1]),
    (CONSTANT_NAME, "C.java", "static final int maxRetries = 3;\n", [1]),
    (CONSTANT_NAME, "C.java", "protected static final boolean enabled = true;\n", [1]),
    (CONSTANT_NAME, "C.java", 'private static final String TABLE_NAME = "orders";\n', []),
    (CONSTANT_NAME, "C.java", "private static final long serialVersionUID = 1L;\n", []),
    (CONSTANT_NAME, "C.java", "private static final Logger log = LoggerFactory.getLogger(C.class);\n", []),
    # style-multiple-variable-declarations
    (MULTIPLE_VARIABLE_DECLARATIONS, "C.java", "int a, b;\n", [1]),
    (MULTIPLE_VARIABLE_DECLARATIONS, "C.java", "String first, last;\n", [1]),
    (MULTIPLE_VARIABLE_DECLARATIONS, "C.java", "double x = 0, y = 0;\n", [1]),
    (MULTIPLE_VARIABLE_DECLARATIONS, "C.java", "int a;\nint b;\n", []),
    (
        MULTIPLE_VARIABLE_DECLARATIONS,
        "C.java",
        "for (int i = 0, j = len; i < j; i++, j--) {}\n",
        [],
    ),
    (MULTIPLE_VARIABLE_DECLARATIONS, "C.java", "String name(int a, int b) { return null; }\n", []),
    (
        # branch coverage: the multi-decl shape without a terminating ';' (continues on another
        # line) is not the single-statement construct this rule targets.
        MULTIPLE_VARIABLE_DECLARATIONS,
        "C.java",
        "int a, b = matrix[i][j]\n",
        [],
    ),
    (
        # near miss: a comma inside a method call on the right-hand side is not a second declaration.
        MULTIPLE_VARIABLE_DECLARATIONS,
        "C.java",
        'String url = builder.queryParam("city", city).build();\n',
        [],
    ),
    # style-upper-ell
    (UPPER_ELL, "C.java", "long x = 10l;\n", [1]),
    (UPPER_ELL, "C.java", "long x = 0x1Fl;\n", [1]),
    (UPPER_ELL, "C.java", "long y = 0b101l;\n", [1]),
    (UPPER_ELL, "C.java", "long x = 10L;\n", []),
    (UPPER_ELL, "C.java", "int x = 10;\n", []),
    (UPPER_ELL, "C.java", "int l = 5;\n", []),
    # style-array-type-style
    (ARRAY_TYPE_STYLE, "C.java", "String args[];\n", [1]),
    (ARRAY_TYPE_STYLE, "C.java", "public static void main(String argv[]) {}\n", [1]),
    (ARRAY_TYPE_STYLE, "C.java", "int matrix[][];\n", [1]),
    (ARRAY_TYPE_STYLE, "C.java", "String[] args;\n", []),
    (ARRAY_TYPE_STYLE, "C.java", "int value = values[i];\n", []),
    (ARRAY_TYPE_STYLE, "C.java", "int[] matrix = new int[]{1, 2, 3};\n", []),
]
