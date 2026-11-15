"""The correct-work `uce-k*` and legacy `uce-g*` inputs of the review (REVIEW-deps.md, section 9); see unsafe_exec_review_cases."""

from __future__ import annotations

from policies.unsafe_exec_review_cases import README

OPS_OLD = "import os\n\n\ndef clean(d):\n    os.system('rm -rf ' + d)\n\n\ndef other():\n    return 1\n"

# Correct work: 34 of the review's 35 (uce-k22 carries a pragma and is not rebuilt).
CORRECT: dict[str, tuple[str, dict[str, str], dict[str, str]]] = {
    "uce-k01": (
        "commit",
        {"app/parse.py": "import ast\n\n\ndef parse(s):\n    return ast.literal_eval(s)\n"},
        README,
    ),
    "uce-k02": (
        "commit",
        {
            "app/ops.py": "import subprocess\n\n\ndef status():\n"
            '    return subprocess.run(["git", "status", "--short"], check=True, capture_output=True, shell=False)\n'
        },
        README,
    ),
    "uce-k03": (
        "commit",
        {
            "tests/test_no_eval.py": "from pathlib import Path\n\n\ndef test_no_eval():\n"
            '    source = Path("app/calc.py").read_text()\n    assert "eval(" not in source\n'
        },
        README,
    ),
    "uce-k04": (
        "commit",
        {
            "app/parse.py": "import ast\n\n\ndef parse(s):\n"
            "    # never call eval() on user input; use ast.literal_eval\n    return ast.literal_eval(s)\n"
        },
        README,
    ),
    "uce-k05": (
        "commit",
        {
            "app/ops.py": 'def run(argv):\n    """Run argv without a shell. Do not use os.system() or shell=True here."""\n'
            "    import subprocess\n\n    return subprocess.run(argv, check=True)\n"
        },
        README,
    ),
    "uce-k06": (
        "commit",
        {
            "ml/train.py": "class Trainer:\n    def eval(self, loader):\n"
            "        self.model.eval()\n        return [self.model(x) for x in loader]\n"
        },
        README,
    ),
    "uce-k07": (
        "commit",
        {
            "app/io.py": "import numpy as np\nimport torch\nimport yaml\n\n\ndef read(f, p):\n"
            "    a = yaml.safe_load(f)\n    b = yaml.load(f, Loader=yaml.SafeLoader)\n"
            "    c = torch.load(p, weights_only=True)\n    d = np.load(p, allow_pickle=False)\n    return a, b, c, d\n"
        },
        README,
    ),
    "uce-k08": (
        "commit",
        {
            "app/db.py": 'import importlib\nimport re\n\nPAT = re.compile(r"^[a-z]+$")\n'
            'json = importlib.import_module("json")\n\n\ndef find(cur, name):\n'
            '    cur.execute("SELECT id FROM users WHERE name = %s", (name,))\n    return cur.fetchone()\n'
        },
        README,
    ),
    "uce-k09": (
        "commit",
        {
            "app/cache.py": "import json\nimport pickle\n\n\ndef pack(obj):\n    return pickle.dumps(obj)\n\n\n"
            "def unpack(s):\n    return json.loads(s)\n"
        },
        README,
    ),
    "uce-k10": (
        "commit",
        {
            "src/util.js": "const m = /(\\d+)/.exec(input);\n"
            "db.exec('CREATE TABLE IF NOT EXISTS t (id INTEGER)');\n"
            "setTimeout(() => refresh(), 1000);\nsetInterval(tick, 500);\n"
        },
        README,
    ),
    "uce-k11": (
        "commit",
        {
            "src/ops.js": "const { execFile, spawn } = require('child_process');\n"
            "execFile('git', ['status'], cb);\nspawn('node', ['build.js'], { stdio: 'inherit' });\n"
        },
        README,
    ),
    "uce-k12": (
        "commit",
        {
            "src/command.ts": "export class Query {\n  constructor(private sql: string) {}\n\n"
            "  async exec(conn: Conn): Promise<Row[]> {\n    return conn.query(this.sql);\n  }\n}\n"
        },
        README,
    ),
    "uce-k13": (
        "commit",
        {
            "eslint.config.js": "export default [\n  {\n    rules: {\n      'no-eval': 'error',\n"
            "      'no-implied-eval': 'error',\n"
            "      'no-restricted-syntax': ['error', { selector: \"CallExpression[callee.name='eval']\", "
            "message: 'Do not call eval(); parse the input instead.' }],\n    },\n  },\n];\n"
        },
        README,
    ),
    "uce-k14": (
        "commit",
        {
            "docker/entrypoint.sh": '#!/bin/sh\nset -e\nif [ "$(id -u)" = \'0\' ]; then\n  exec gosu app "$@"\nfi\nexec "$@"\n'
        },
        README,
    ),
    "uce-k15": (
        "commit",
        {
            "scripts/dev-env.sh": '#!/usr/bin/env bash\neval "$(ssh-agent -s)"\neval "$(pyenv init -)"\n'
            'eval "$(direnv hook bash)"\n'
        },
        README,
    ),
    "uce-k16": (
        "commit",
        {
            "Dockerfile": "FROM nginx:1.27\nCOPY dist/ /usr/share/nginx/html/\n"
            'CMD ["sh", "-c", "envsubst < /etc/nginx/t.conf > /etc/nginx/conf.d/default.conf '
            "&& nginx -g 'daemon off;'\"]\n"
        },
        README,
    ),
    "uce-k17": (
        "commit",
        {
            "deploy/job.yaml": "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: migrate\nspec:\n  template:\n"
            "    spec:\n      restartPolicy: Never\n      containers:\n        - name: migrate\n"
            "          image: registry.corp.example/app:1.2.3\n"
            '          command: ["/bin/sh", "-c", "alembic upgrade head"]\n'
        },
        README,
    ),
    "uce-k18": (
        "commit",
        {
            "docker-compose.yml": "services:\n  web:\n    image: app:dev\n"
            '    command: ["sh", "-c", "npm run migrate && npm start"]\n    healthcheck:\n'
            '      test: ["CMD", "sh", "-c", "wget -qO- http://localhost:3000/health"]\n'
        },
        README,
    ),
    "uce-k19": (
        "commit",
        {
            "docs/security.md": "# Shell injection\n\nBad:\n\n```python\nsubprocess.run(cmd, shell=True)\n"
            'os.system(cmd)\n```\n\nGood:\n\n```python\nsubprocess.run(["ls", path])\n```\n\n'
            "Never call `eval()` on input.\n"
        },
        README,
    ),
    "uce-k20": (
        "commit",
        {"docs/install.md": "# Install\n\n```\npip install acme-tool\nnpm install -g acme-cli\n```\n"},
        README,
    ),
    "uce-k21": (
        "commit",
        {
            "third_party/runtime.min.js": "(function(){var g;g=function(){return this}();try{g=g||new Function"
            "('return this')()}catch(e){if(typeof window==='object')g=window}module.exports=g})();\n"
        },
        README,
    ),
    "uce-k23": (
        "commit",
        {
            "db/migrations/004.sql": "EXEC sp_rename 'dbo.users.fullname', 'full_name', 'COLUMN';\nEXECUTE dbo.rebuild_index;\n"
        },
        README,
    ),
    "uce-k24": (
        "commit",
        {
            ".vscode/tasks.json": '{\n  "version": "2.0.0",\n'
            '  "tasks": [{"label": "build", "type": "shell", "command": "npm run build"}]\n}\n'
        },
        README,
    ),
    "uce-k25": (
        "commit",
        {
            "ansible/site.yml": "- hosts: web\n  tasks:\n    - name: reload nginx\n"
            "      ansible.builtin.shell: nginx -s reload\n      become: true\n"
        },
        README,
    ),
    "uce-k26": (
        "commit",
        {
            "gui/main.py": "import sys\n\nfrom PySide6.QtWidgets import QApplication\n\n"
            "app = QApplication(sys.argv)\nsys.exit(app.exec())\n"
        },
        README,
    ),
    "uce-k27": (
        "commit",
        {
            "services/api/app.py": "from flask import Flask\n\napp = Flask(__name__)\n",
            "services/worker/main.go": 'package main\n\nimport "os/exec"\n\n'
            'func main() { _ = exec.Command("git", "status").Run() }\n',
            "apps/web/src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
        },
        README,
    ),
    "uce-k28": ("commit", {"analysis/calc.py": 'def total(df):\n    return df.eval("a + b")\n'}, README),
    "uce-k29": (
        "commit",
        {
            "app/store.py": "def run(session, client, sql, params, script, key):\n"
            "    session.execute(sql, params)\n    return client.eval(script, 1, key)\n"
        },
        README,
    ),
    "uce-k30": (
        "commit",
        {
            "src/types.ts": "export type Handler = (fn: Function) => void;\nexport const call = Function.prototype.call;\n"
        },
        README,
    ),
    "uce-g01": (
        "commit",
        {"app/ops.py": OPS_OLD + "\n\ndef third():\n    return 3\n"},
        {"app/ops.py": OPS_OLD},
    ),
    "uce-g02": (
        "commit",
        {"app/ops.py": "import os\n\n\ndef clean(d):\n  os.system('rm -rf ' + d)\n\n\ndef other():\n  return 1\n"},
        {"app/ops.py": OPS_OLD},
    ),
    "uce-g03": (
        "commit",
        {"app/ops.py": 'import os\n\n\ndef clean(d):\n    os.system("rm -rf " + d)\n\n\ndef other():\n    return 1\n'},
        {"app/ops.py": OPS_OLD},
    ),
    "uce-g04": (
        "commit",
        {"app/calc.py": 'def run(x):\n    return eval(x, {"__builtins__": {}})\n'},
        {"app/calc.py": "def run(x):\n    return eval(x)\n"},
    ),
    "uce-g05": (
        "commit",
        {
            "app/fs.py": "import os\n\n\ndef clean(d):\n    os.system('rm -rf ' + d)\n",
            "app/ops.py": "def other():\n    return 1\n",
        },
        {"app/ops.py": OPS_OLD},
    ),
}
