"""code and prompt-memory packs: dynamic code and SQL, retrieved text in system messages, unowned memory."""

from __future__ import annotations

from agentic_code_security.cases.case import Case

SQL_BUILT = """def find(cur, uid, name, table):
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    cur.executemany("INSERT INTO {} VALUES (?)".format(table), rows)
    cur.execute("SELECT * FROM " + table)
    stmt = f"DELETE FROM users WHERE id = {uid}"
    cur.execute(stmt)
    conn.raw("SELECT * FROM users WHERE n = " + name)
    session.query("select * from users where n = " + name)
"""
SQL_SAFE = """def find(cur, uid, table, index, topic):
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
    cur.execute("SELECT 1")
    cur.execute(query_from_config)
    session.query(User)
    index.query(f"summarize {topic}")
    label = "a" + "b"
    cur.execute(label + label)
    stmt = "SELECT * FROM users"
    cur.execute(stmt)
"""

REFUSED = [
    Case(
        "code-dynamic-eval-exec",
        "gen/run.py",
        "result = eval(expression)\nexec(compiled_source)\n",
        "evals and execs text that is not a literal",
    ),
    Case("code-sql-string-built", "db/find.py", SQL_BUILT, "builds SQL with f-strings, %, format, + and a variable"),
    Case(
        "code-sql-string-built",
        "db/find.js",
        "const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);\n",
        "passes a template literal with ${} to query",
    ),
    Case(
        "prompt-untrusted-in-system-message",
        "rag/prompt.py",
        'messages = [{"role": "system", "content": f"Answer using {retrieved_docs}"}]\n'
        'note = SystemMessage(content="Page: " + page_html)\n'
        'chat = ChatPromptTemplate.from_messages([("system", "Context: {}".format(chunk))])\n'
        'run(system=f"Follow {email_body}")\n',
        "splices retrieved text into system messages",
    ),
    Case(
        "memory-mem0-unscoped",
        "mem/store.py",
        "from mem0 import Memory\n\nmemory = Memory()\nmemory.add(messages)\nhits = memory.search(query)\n",
        "adds to and searches mem0 with no user_id, agent_id or run_id",
    ),
    Case(
        "memory-mem0-unscoped",
        "mem/client.py",
        "from mem0 import MemoryClient\n\nclass Store:\n    def __init__(self):\n        self.client = MemoryClient(api_key=key)\n\n"
        "    def save(self, m):\n        self.client.add(m)\n",
        "adds through a MemoryClient held on self with no scope",
    ),
]

SILENT = [
    Case(
        "code-dynamic-eval-exec",
        "gen/run.py",
        'import ast\n\nvalue = ast.literal_eval(text)\nmodel.eval()\nresult = eval("1 + 1")\nexec("x = 1")\neval()\n',
        "uses literal_eval, a method named eval, and string literals",
    ),
    Case(
        "code-sql-string-built",
        "db/find.py",
        SQL_SAFE,
        "binds parameters, runs constant SQL, and queries a non-SQL engine",
    ),
    Case(
        "code-sql-string-built",
        "db/find.js",
        'const rows = await db.query("SELECT * FROM users WHERE id = $1", [id]);\n// db.query(`SELECT ${id}`)\n',
        "binds a parameter, the template literal only in a comment",
    ),
    Case(
        "prompt-untrusted-in-system-message",
        "rag/prompt.py",
        'messages = [{"role": "system", "content": "You answer from the user message."},\n'
        '            {"role": "user", "content": f"Answer using {retrieved_docs}"},\n'
        '            {"role": "system", "content": f"You are {persona}"}]\n'
        'x = SystemMessage(content=f"Docs: {n}")\ny = SystemMessage(content=fixed_text)\nz = SystemMessage()\n',
        "keeps system messages constant, and retrieved text in the user message",
    ),
    Case(
        "memory-mem0-unscoped",
        "mem/store.py",
        "from mem0 import Memory\n\nmemory = Memory()\nmemory.add(messages, user_id=uid)\nhits = memory.search(query, filters={'agent_id': aid})\n"
        "more = memory.add(messages, **scope)\nseen = set()\nseen.add(item)\nfound = re.search(p, s)\n",
        "scopes every mem0 call, and other add and search calls are not mem0's",
    ),
]
