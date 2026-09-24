"""Cases for the exceptions pack: Exception handling.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

EMPTY_CATCH = "exceptions-empty-catch"
CATCH_BROAD = "exceptions-catch-broad"
CATCH_NPE = "exceptions-catch-npe"
FINALLY_CONTROL_FLOW = "exceptions-finally-control-flow"
GENERIC_THROWN = "exceptions-generic-thrown"
LOST_CAUSE = "exceptions-lost-cause"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # exceptions-empty-catch
    (EMPTY_CATCH, "E.java", "void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n  }\n}\n", [4]),
    (EMPTY_CATCH, "E.java", "void m() {\n  try {\n    risky();\n  } catch (IOException e) {}\n}\n", [4]),
    (
        EMPTY_CATCH,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (IOException | SQLException e) {\n  }\n}\n",
        [4],
    ),
    (
        # a comment is enough of a reason on its own -- Sonar's own S108 treats it as handled
        EMPTY_CATCH,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    // deliberately ignored: retried by the caller\n  }\n}\n",
        [],
    ),
    (
        EMPTY_CATCH,
        "E.java",
        'void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    log.warn("failed", e);\n  }\n}\n',
        [],
    ),
    (EMPTY_CATCH, "E.java", "void m() throws IOException {\n  risky();\n}\n", []),
    (
        # unclosed catch parameter list -- the file ends before `)`, so nothing can be parsed
        EMPTY_CATCH,
        "E.java",
        "void m() {\n  try {\n  } catch (IOException e\n}\n",
        [],
    ),
    (
        # empty catch parens -- no type/variable to parse
        EMPTY_CATCH,
        "E.java",
        "void m() {\n  try {\n  } catch () {\n  }\n}\n",
        [],
    ),
    (
        # something other than whitespace sits between the catch header and its block
        EMPTY_CATCH,
        "E.java",
        "void m() {\n  try {\n  } catch (IOException e) foo(); if (x) {\n  }\n}\n",
        [],
    ),
    (
        # the catch body opens but nothing ever closes it -- not even the method itself
        EMPTY_CATCH,
        "E.java",
        "void m() {\n  try {\n  } catch (IOException e) {\n    doWork();\n",
        [],
    ),
    # exceptions-catch-broad
    (
        CATCH_BROAD,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (Throwable t) {\n    log.error(t);\n  }\n}\n",
        [4],
    ),
    (
        CATCH_BROAD,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (Error e) {\n    log.error(e);\n  }\n}\n",
        [4],
    ),
    (
        CATCH_BROAD,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (java.lang.Throwable t) {\n    log.error(t);\n  }\n}\n",
        [4],
    ),
    (
        CATCH_BROAD,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (Exception e) {\n    log.error(e);\n  }\n}\n",
        [],
    ),
    (
        CATCH_BROAD,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (OutOfMemoryError e) {\n    abort(e);\n  }\n}\n",
        [],
    ),
    (
        CATCH_BROAD,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (RuntimeException e) {\n    log.error(e);\n  }\n}\n",
        [],
    ),
    # exceptions-catch-npe
    (
        CATCH_NPE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (NullPointerException e) {\n    fallback();\n  }\n}\n",
        [4],
    ),
    (
        CATCH_NPE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (java.lang.NullPointerException e) {\n    fallback();\n  }\n}\n",
        [4],
    ),
    (
        CATCH_NPE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (NullPointerException | IllegalStateException e) {\n    fallback();\n  }\n}\n",
        [4],
    ),
    (
        CATCH_NPE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (IllegalArgumentException e) {\n    fallback();\n  }\n}\n",
        [],
    ),
    (CATCH_NPE, "E.java", "void m() {\n  if (x == null) {\n    fallback();\n  }\n}\n", []),
    (
        CATCH_NPE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (Exception e) {\n    fallback();\n  }\n}\n",
        [],
    ),
    # exceptions-finally-control-flow
    (
        FINALLY_CONTROL_FLOW,
        "E.java",
        "boolean m() {\n  try {\n    risky();\n    return true;\n  } finally {\n    return false;\n  }\n}\n",
        [6],
    ),
    (
        FINALLY_CONTROL_FLOW,
        "E.java",
        "void m() throws IOException {\n  try {\n    risky();\n  } finally {\n    throw new IOException();\n  }\n}\n",
        [5],
    ),
    (
        FINALLY_CONTROL_FLOW,
        "E.java",
        "boolean m() {\n  try {\n    return risky();\n  } finally {\n    cleanup();\n    return false;\n  }\n}\n",
        [6],
    ),
    (
        # cleanup only -- no jump escapes the finally
        FINALLY_CONTROL_FLOW,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } finally {\n    conn.close();\n  }\n}\n",
        [],
    ),
    (
        # the return lives inside a nested, braced if -- still inside the finally, but not at its own top level
        FINALLY_CONTROL_FLOW,
        "E.java",
        'boolean m() {\n  try {\n    return risky();\n  } finally {\n    if (retry) {\n      log.warn("retry");\n    }\n  }\n}\n',
        [],
    ),
    (
        # a loop's own break lives entirely inside the finally block -- it never escapes it
        FINALLY_CONTROL_FLOW,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } finally {\n    for (Item i : items) {\n      if (i.done()) break;\n      i.close();\n    }\n  }\n}\n",
        [],
    ),
    (
        # the return sits inside a braced nested if -- not at the finally block's own top level
        FINALLY_CONTROL_FLOW,
        "E.java",
        "boolean m() {\n  try {\n    return risky();\n  } finally {\n    if (retry) {\n      return recover();\n    }\n  }\n}\n",
        [],
    ),
    (
        # the finally block opens but nothing ever closes it -- not even the method itself
        FINALLY_CONTROL_FLOW,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } finally {\n    cleanup();\n",
        [],
    ),
    # exceptions-generic-thrown
    (GENERIC_THROWN, "E.java", 'void m() throws Exception {\n  throw new Exception("failed");\n}\n', [2]),
    (GENERIC_THROWN, "E.java", 'void m() {\n  throw new RuntimeException("failed");\n}\n', [2]),
    (GENERIC_THROWN, "E.java", 'void m() throws Throwable {\n  throw new Throwable("failed");\n}\n', [2]),
    (GENERIC_THROWN, "E.java", 'void m() {\n  throw new IllegalArgumentException("bad input");\n}\n', []),
    (GENERIC_THROWN, "E.java", "void m() throws Exception {\n  risky();\n}\n", []),
    (
        GENERIC_THROWN,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (Exception e) {\n    throw e;\n  }\n}\n",
        [],
    ),
    # exceptions-lost-cause
    (
        LOST_CAUSE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    throw new RuntimeException(e.getMessage());\n  }\n}\n",
        [5],
    ),
    (
        LOST_CAUSE,
        "E.java",
        'void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    throw new RuntimeException("failed");\n  }\n}\n',
        [5],
    ),
    (
        LOST_CAUSE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (SQLException e) {\n    throw new DataAccessException(e.getMessage(), e.getErrorCode());\n  }\n}\n",
        [5],
    ),
    (
        LOST_CAUSE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    throw new RuntimeException(e);\n  }\n}\n",
        [],
    ),
    (
        LOST_CAUSE,
        "E.java",
        'void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    throw new RuntimeException("failed", e);\n  }\n}\n',
        [],
    ),
    (
        LOST_CAUSE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    throw e;\n  }\n}\n",
        [],
    ),
    (
        # the constructor's argument list never closes within the catch body -- nothing to check
        LOST_CAUSE,
        "E.java",
        "void m() {\n  try {\n    risky();\n  } catch (IOException e) {\n    throw new Foo(a, (b);\n  }\n}\n",
        [],
    ),
]

#: Handled the way Sonar accepts it, and dropped on purpose by name.
CASES += [
    (
        "exceptions-lost-cause",
        "A.java",
        'void f() {\n  try { g(); } catch (IOException e) {\n    log.error("read failed", e);\n'
        '    throw new IllegalStateException("read failed");\n  }\n}\n',
        [],
    ),
    (
        "exceptions-lost-cause",
        "A.java",
        'void f() {\n  try { g(); } catch (IOException e) {\n    log.error("read failed: " + e.getMessage());\n'
        '    throw new IllegalStateException("read failed");\n  }\n}\n',
        [4],
    ),
    (
        "exceptions-empty-catch",
        "A.java",
        "void f() {\n  try { g(); } catch (InterruptedException ignored) {\n  }\n}\n",
        [],
    ),
    (
        "exceptions-empty-catch",
        "A.java",
        "void f() {\n  try { g(); } catch (NumberFormatException expected) {}\n}\n",
        [],
    ),
    ("exceptions-empty-catch", "A.java", "void f() {\n  try { g(); } catch (NumberFormatException ex) {}\n}\n", [2]),
]
