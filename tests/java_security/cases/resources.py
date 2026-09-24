"""Cases for the resources pack: Resources and lifecycle.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on.
"""

from __future__ import annotations

UNCLOSED_CLOSEABLE = "resources-unclosed-closeable"
FINALIZE_OVERRIDE = "resources-finalize-override"
FORCED_GC = "resources-forced-gc"
SYSTEM_EXIT = "resources-system-exit"
RUN_FINALIZERS_ON_EXIT = "resources-run-finalizers-on-exit"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # resources-unclosed-closeable
    (
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    FileInputStream fis = new FileInputStream(f);\n    read(fis);\n}\n",
        [2],
    ),
    (
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    Connection conn = dataSource.getConnection();\n    use(conn);\n}\n",
        [2],
    ),
    (
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    ExecutorService pool = Executors.newFixedThreadPool(4);\n    pool.submit(task);\n}\n",
        [2],
    ),
    (
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    Scanner sc = new Scanner(new File(path));\n    sc.nextLine();\n}\n",
        [2],
    ),
    (
        # comment mentioning FileInputStream is blanked, so `code()` never even reaches the decl form
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    // FileInputStream fis = new FileInputStream(f);\n    doWork();\n}\n",
        [],
    ),
    (
        # try-with-resources: declared inside the `try (` header, not a leak
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    try (FileInputStream fis = new FileInputStream(f)) {\n        read(fis);\n    }\n}\n",
        [],
    ),
    (
        # multi-resource try-with-resources spanning lines: the continuation line is still the header
        UNCLOSED_CLOSEABLE,
        "R.java",
        (
            "void m() throws Exception {\n"
            "    try (Connection c = ds.getConnection();\n"
            "         PreparedStatement ps = c.prepareStatement(SQL)) {\n"
            "        ps.execute();\n"
            "    }\n}\n"
        ),
        [],
    ),
    (
        # closed explicitly later in the method
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() throws IOException {\n    FileInputStream fis = new FileInputStream(f);\n    read(fis);\n    fis.close();\n}\n",
        [],
    ),
    (
        # ExecutorService shut down later in the method
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    ExecutorService pool = Executors.newFixedThreadPool(4);\n    pool.submit(task);\n    pool.shutdown();\n}\n",
        [],
    ),
    (
        # returned to the caller: the caller now owns it
        UNCLOSED_CLOSEABLE,
        "R.java",
        "InputStream m() throws IOException {\n    FileInputStream fis = new FileInputStream(f);\n    return fis;\n}\n",
        [],
    ),
    (
        # Scanner over System.in is not a file handle
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() {\n    Scanner sc = new Scanner(System.in);\n    sc.nextLine();\n}\n",
        [],
    ),
    (
        # a raw reader wrapped and closed via an outer BufferedReader's own try-with-resources header
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() throws IOException {\n    FileReader fr = new FileReader(f);\n    try (BufferedReader br = new BufferedReader(fr)) {\n        br.readLine();\n    }\n}\n",
        [],
    ),
    (
        # stored onto a field: the field now owns it
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() throws IOException {\n    FileInputStream fis = new FileInputStream(f);\n    holder.stream = fis;\n}\n",
        [],
    ),
    (
        # handed to another constructor: that wrapper now owns it
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() throws IOException {\n    FileInputStream fis = new FileInputStream(f);\n    InputStreamReader isr = new InputStreamReader(fis);\n}\n",
        [],
    ),
    (
        # the constructor call spans lines -- not a single complete statement, so it is left alone
        UNCLOSED_CLOSEABLE,
        "R.java",
        "void m() throws IOException {\n    FileInputStream fis = new FileInputStream(\n        f);\n}\n",
        [],
    ),
    (
        # a three-resource try-with-resources header spanning three lines: the middle line's own
        # parens net to a still-open depth, so the header stays open past it
        UNCLOSED_CLOSEABLE,
        "R.java",
        (
            "void m() throws Exception {\n"
            "    try (Connection c = ds.getConnection();\n"
            "         PreparedStatement ps = c.prepareStatement(SQL);\n"
            "         ResultSet rs = ps.executeQuery()) {\n"
            "        use(rs);\n"
            "    }\n}\n"
        ),
        [],
    ),
    # resources-finalize-override
    (
        FINALIZE_OVERRIDE,
        "R.java",
        "class C {\n  protected void finalize() throws Throwable {\n    cleanup();\n  }\n}\n",
        [2],
    ),
    (FINALIZE_OVERRIDE, "R.java", "class C {\n  public void finalize() {\n    cleanup();\n  }\n}\n", [2]),
    (FINALIZE_OVERRIDE, "R.java", "class C {\n  @Override\n  void finalize() {\n    cleanup();\n  }\n}\n", [3]),
    (
        FINALIZE_OVERRIDE,
        "R.java",
        "class C {\n  void cleanup() throws Throwable {\n    super.finalize();\n  }\n}\n",
        [],
    ),
    (FINALIZE_OVERRIDE, "R.java", "class C {\n  // void finalize() should not be overridden\n}\n", []),
    (FINALIZE_OVERRIDE, "R.java", "class C {\n  void finalizeOrder(int x) {\n    process(x);\n  }\n}\n", []),
    # resources-forced-gc
    (FORCED_GC, "R.java", "void m() {\n    System.gc();\n}\n", [2]),
    (FORCED_GC, "R.java", "void m() {\n    Runtime.getRuntime().gc();\n}\n", [2]),
    (FORCED_GC, "R.java", "void m() {\n    System.runFinalization();\n}\n", [2]),
    (FORCED_GC, "R.java", "void m() {\n    // System.gc() was tried here and reverted\n}\n", []),
    (FORCED_GC, "R.java", 'void m() {\n    log.info("System.gc() disabled");\n}\n', []),
    (FORCED_GC, "R.java", "void m() {\n    collector.gc();\n}\n", []),
    # resources-system-exit
    (SYSTEM_EXIT, "R.java", "class Job {\n  void run() {\n    System.exit(1);\n  }\n}\n", [3]),
    (SYSTEM_EXIT, "R.java", "class Job {\n  void run() {\n    Runtime.getRuntime().exit(1);\n  }\n}\n", [3]),
    (SYSTEM_EXIT, "R.java", "class Job {\n  void run() {\n    Runtime.getRuntime().halt(1);\n  }\n}\n", [3]),
    (
        SYSTEM_EXIT,
        "R.java",
        "class Main {\n  public static void main(String[] args) {\n    System.exit(1);\n  }\n}\n",
        [],
    ),
    (SYSTEM_EXIT, "R.java", "class Job {\n  void run() {\n    // System.exit(1) was removed here\n  }\n}\n", []),
    (SYSTEM_EXIT, "R.java", "class Job {\n  void run() {\n    throw new IllegalStateException();\n  }\n}\n", []),
    # resources-run-finalizers-on-exit
    (RUN_FINALIZERS_ON_EXIT, "R.java", "void m() {\n    System.runFinalizersOnExit(true);\n}\n", [2]),
    (
        RUN_FINALIZERS_ON_EXIT,
        "R.java",
        "void m() {\n    Runtime.getRuntime().runFinalizersOnExit(true);\n}\n",
        [2],
    ),
    (RUN_FINALIZERS_ON_EXIT, "R.java", "void m() {\n    System.runFinalizersOnExit(false);\n}\n", [2]),
    (RUN_FINALIZERS_ON_EXIT, "R.java", "void m() {\n    System.runFinalization();\n}\n", []),
    (RUN_FINALIZERS_ON_EXIT, "R.java", "void m() {\n    // System.runFinalizersOnExit(true) is banned here\n}\n", []),
    (RUN_FINALIZERS_ON_EXIT, "R.java", "void m() {\n    System.gc();\n}\n", []),
]

#: Returning the resource hands it to the caller; returning what a call on it produced does not.
CASES += [
    (
        "resources-unclosed-closeable",
        "A.java",
        "byte[] load(File f) throws IOException {\n  FileInputStream in = new FileInputStream(f);\n"
        "  return in.readAllBytes();\n}\n",
        [2],
    ),
    (
        "resources-unclosed-closeable",
        "A.java",
        "InputStream open(File f) throws IOException {\n  FileInputStream in = new FileInputStream(f);\n"
        "  return in;\n}\n",
        [],
    ),
]
