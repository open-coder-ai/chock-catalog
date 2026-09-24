"""Cases for the performance pack: Performance.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

BOXING_CONSTRUCTOR = "performance-boxing-constructor"
STRING_CONCAT_LOOP = "performance-string-concat-loop"
MAP_KEYSET_GET = "performance-map-keyset-get"
SIZE_CHECK = "performance-size-check"
LEGACY_COLLECTION = "performance-legacy-collection"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # performance-boxing-constructor
    (BOXING_CONSTRUCTOR, "P.java", "Integer i = new Integer(1);\n", [1]),
    (BOXING_CONSTRUCTOR, "P.java", "Boolean b = new Boolean(true);\n", [1]),
    (BOXING_CONSTRUCTOR, "P.java", 'String s = new String("hi");\n', [1]),
    (BOXING_CONSTRUCTOR, "P.java", "Integer i = Integer.valueOf(1);\n", []),
    (BOXING_CONSTRUCTOR, "P.java", "int i = 1;\n", []),
    (BOXING_CONSTRUCTOR, "P.java", "StringBuilder sb = new StringBuilder();\n", []),
    (BOXING_CONSTRUCTOR, "P.java", "// Integer i = new Integer(1);\n", []),
    # performance-string-concat-loop
    (
        STRING_CONCAT_LOOP,
        "P.java",
        'void m(List<String> parts) {\n  String out = "";\n  for (String p : parts) {\n    out += p;\n  }\n}\n',
        [4],
    ),
    (
        STRING_CONCAT_LOOP,
        "P.java",
        'void m(List<String> parts) {\n  String out = "";\n  for (String p : parts) {\n    out = out + p;\n  }\n}\n',
        [4],
    ),
    (
        STRING_CONCAT_LOOP,
        "P.java",
        'void m(int n) {\n  String out = "";\n  int i = 0;\n  while (i < n) {\n    out += i;\n    i++;\n  }\n}\n',
        [5],
    ),
    (
        # StringBuilder used correctly: never matches +=
        STRING_CONCAT_LOOP,
        "P.java",
        "void m(List<String> parts) {\n  StringBuilder out = new StringBuilder();\n  for (String p : parts) {\n    out.append(p);\n  }\n}\n",
        [],
    ),
    (
        # concatenation outside any loop
        STRING_CONCAT_LOOP,
        "P.java",
        "void m(String a, String b) {\n  String out = a;\n  out += b;\n}\n",
        [],
    ),
    (
        # `line` is a field, not declared String in this method
        STRING_CONCAT_LOOP,
        "P.java",
        "void m(List<String> parts) {\n  for (String p : parts) {\n    line += p;\n  }\n}\n",
        [],
    ),
    # performance-map-keyset-get
    (
        MAP_KEYSET_GET,
        "P.java",
        "void m(Map<String, Integer> counts) {\n  for (String key : counts.keySet()) {\n    Integer v = counts.get(key);\n    use(v);\n  }\n}\n",
        [3],
    ),
    (
        MAP_KEYSET_GET,
        "P.java",
        "void m(Map<String, Integer> scores) {\n  for (String name : scores.keySet()) {\n    total += scores.get(name);\n  }\n}\n",
        [3],
    ),
    (
        MAP_KEYSET_GET,
        "P.java",
        "void m(Map<Long, Order> orders) {\n  for (Long id : orders.keySet()) {\n    log.info(id);\n    process(orders.get(id));\n  }\n}\n",
        [4],
    ),
    (
        # entrySet() already used -- the efficient form
        MAP_KEYSET_GET,
        "P.java",
        "void m(Map<String, Integer> counts) {\n  for (Map.Entry<String, Integer> e : counts.entrySet()) {\n    use(e.getValue());\n  }\n}\n",
        [],
    ),
    (
        # keySet() loop that never re-looks the value up
        MAP_KEYSET_GET,
        "P.java",
        "void m(Map<String, Integer> counts) {\n  for (String key : counts.keySet()) {\n    log.info(key);\n  }\n}\n",
        [],
    ),
    (
        # a different map is queried -- not the wrong-iterator pattern
        MAP_KEYSET_GET,
        "P.java",
        "void m(Map<String, Integer> counts, Map<String, Integer> other) {\n  for (String key : counts.keySet()) {\n    use(other.get(key));\n  }\n}\n",
        [],
    ),
    (
        # a brace-less single-statement loop body -- no block to look inside
        MAP_KEYSET_GET,
        "P.java",
        "void m(Map<String, Integer> counts) {\n  for (String key : counts.keySet())\n    log.info(key);\n}\n",
        [],
    ),
    (
        # the file ends before the loop's body ever opens
        MAP_KEYSET_GET,
        "P.java",
        "for (String key : counts.keySet())\n",
        [],
    ),
    # performance-size-check
    (
        SIZE_CHECK,
        "P.java",
        "void m(List<String> items) {\n  if (items.size() == 0) {\n    return;\n  }\n}\n",
        [2],
    ),
    (
        SIZE_CHECK,
        "P.java",
        "void m(Set<String> tags) {\n  if (tags.size() > 0) {\n    process(tags);\n  }\n}\n",
        [2],
    ),
    (
        SIZE_CHECK,
        "P.java",
        "void m(String name) {\n  if (name.length() == 0) {\n    return;\n  }\n}\n",
        [2],
    ),
    (
        SIZE_CHECK,
        "P.java",
        "void m(List<String> items) {\n  if (items.isEmpty()) {\n    return;\n  }\n}\n",
        [],
    ),
    (
        SIZE_CHECK,
        "P.java",
        "void m(List<String> items) {\n  if (items.size() > 10) {\n    trim(items);\n  }\n}\n",
        [],
    ),
    (
        # `queue` is not declared as one of the tracked collection types in this method
        SIZE_CHECK,
        "P.java",
        "void m() {\n  if (queue.size() == 0) {\n    return;\n  }\n}\n",
        [],
    ),
    # performance-legacy-collection
    (LEGACY_COLLECTION, "P.java", "Vector<String> v = new Vector<>();\n", [1]),
    (LEGACY_COLLECTION, "P.java", "Hashtable<String, String> h = new Hashtable<>();\n", [1]),
    (LEGACY_COLLECTION, "P.java", "Stack<Integer> s = new Stack<>();\n", [1]),
    (LEGACY_COLLECTION, "P.java", "List<String> v = new ArrayList<>();\n", []),
    (LEGACY_COLLECTION, "P.java", "Map<String, String> h = new HashMap<>();\n", []),
    (LEGACY_COLLECTION, "P.java", "Deque<Integer> s = new ArrayDeque<>();\n", []),
]
