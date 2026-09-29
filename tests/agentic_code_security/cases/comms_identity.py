"""comms and identity packs: certificate checks off, and the operator's credentials handed over."""

from __future__ import annotations

from agentic_code_security.cases.case import Case

COMPOSE_MOUNTS = """services:
  agent:
    image: acme/agent:1.0
    volumes:
      - ~/.aws:/root/.aws:ro
      - ${HOME}/.ssh:/root/.ssh
      - ~/.config/gcloud:/root/.config/gcloud
  sandbox:
    image: acme/sandbox:1.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
COMPOSE_SAFE = """services:
  agent:
    image: acme/agent:1.0
    volumes:
      - ./workspace:/workspace
      - ./aws-config:/root/.aws:ro
    environment:
      - NODE_TLS_REJECT_UNAUTHORIZED=1
"""

REFUSED = [
    Case(
        "comms-tls-verify-disabled",
        "net/client.py",
        "import requests\n\nr = requests.get(url, verify=False)\n",
        "calls requests with verify=False",
    ),
    Case(
        "comms-tls-verify-disabled",
        "net/httpx_client.py",
        "import httpx\n\nclient = httpx.Client(verify=False)\n",
        "builds an httpx client with verify=False",
    ),
    Case(
        "comms-tls-verify-disabled",
        "net/session.py",
        "import requests\n\nsession = requests.Session()\nsession.verify = False\n",
        "turns verification off on a requests session",
    ),
    Case(
        "comms-ssl-context-unverified",
        "net/ssl_ctx.py",
        "import ssl\n\nctx = ssl._create_unverified_context()\nctx.verify_mode = ssl.CERT_NONE\nctx.check_hostname = False\n",
        "builds an ssl context that verifies nothing",
    ),
    Case(
        "comms-ssl-context-unverified",
        "net/ssl_kw.py",
        "conn = connect(host, check_hostname=False)\n",
        "passes check_hostname=False",
    ),
    Case(
        "comms-node-tls-disabled",
        "net/agent.js",
        "const agent = new https.Agent({ rejectUnauthorized: false });\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
        "turns off Node certificate checks in code",
    ),
    Case(
        "comms-node-tls-disabled",
        ".env",
        "NODE_TLS_REJECT_UNAUTHORIZED=0\n",
        "sets NODE_TLS_REJECT_UNAUTHORIZED=0 in an env file",
    ),
    Case(
        "comms-node-tls-disabled",
        "Dockerfile",
        "FROM node:22\nENV NODE_TLS_REJECT_UNAUTHORIZED 0\n",
        "sets NODE_TLS_REJECT_UNAUTHORIZED in a Dockerfile",
    ),
    Case(
        "comms-node-tls-disabled",
        "ci/env.yaml",
        'env:\n  NODE_TLS_REJECT_UNAUTHORIZED: "0"\n',
        "sets NODE_TLS_REJECT_UNAUTHORIZED in YAML",
    ),
    Case(
        "comms-node-tls-disabled",
        "net/env.py",
        'import os\n\nos.environ["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"\n',
        "sets NODE_TLS_REJECT_UNAUTHORIZED from Python",
    ),
    Case(
        "identity-env-passthrough",
        "sandbox/run.py",
        "import os\nimport subprocess\n\nsubprocess.run(cmd, env=os.environ)\nsubprocess.run(cmd, env=dict(os.environ))\n"
        "subprocess.run(cmd, env={**os.environ})\nsubprocess.run(cmd, env={**os.environ, 'X': '1'})\nsubprocess.run(cmd, env=os.environ.copy())\n",
        "passes the whole environment to a subprocess",
    ),
    Case(
        "identity-env-passthrough",
        "sandbox/run.ts",
        'const child = spawn("node", args, { env: process.env });\nconst other = spawn("node", args, { env: { ...process.env, X: "1" } });\n',
        "passes process.env whole to a child process",
    ),
    Case(
        "identity-sensitive-mount",
        "docker-compose.yml",
        COMPOSE_MOUNTS,
        "mounts ~/.aws, ~/.ssh, gcloud config and the Docker socket into agent containers",
    ),
    Case(
        "identity-sensitive-mount",
        "sandbox/launch.py",
        'container = client.containers.run("acme/agent", volumes=["~/.ssh:/root/.ssh:ro"])\n',
        "mounts ~/.ssh into an agent container from Python",
    ),
    Case(
        "identity-sensitive-mount",
        "sandbox/launch.sh",
        "docker run --mount type=bind,source=/home/dev/.aws,target=/root/.aws acme/sandbox\n",
        "bind-mounts an AWS credentials directory into a sandbox",
    ),
]

SILENT = [
    Case(
        "comms-tls-verify-disabled",
        "net/client.py",
        'import requests\n\na = requests.get(url, verify=True)\nb = requests.get(url, verify="/etc/ssl/ca.pem")\nc = requests.get(url)\n',
        "keeps verification on",
    ),
    Case(
        "comms-tls-verify-disabled",
        "crypto/sig.py",
        "ok = key.check(sig, verify=False)\n",
        "has verify=False in a file with no HTTP client",
    ),
    Case(
        "comms-ssl-context-unverified",
        "net/ssl_ctx.py",
        "import ssl\n\nctx = ssl.create_default_context()\nctx.verify_mode = ssl.CERT_REQUIRED\nctx.check_hostname = True\nconn = connect(host, check_hostname=True)\n",
        "keeps the default verifying context",
    ),
    Case(
        "comms-node-tls-disabled",
        "net/agent.js",
        "// rejectUnauthorized: false was here\nconst agent = new https.Agent({ rejectUnauthorized: true });\nconst m = 'rejectUnauthorized: false';\n",
        "keeps verification on, the old setting only in a comment and a string",
    ),
    Case(
        "comms-node-tls-disabled",
        ".env",
        "NODE_EXTRA_CA_CERTS=/etc/ssl/corp.pem\nNODE_TLS_REJECT_UNAUTHORIZED=1\n",
        "trusts a private CA and keeps checks on",
    ),
    Case(
        "identity-env-passthrough",
        "sandbox/run.py",
        "import os\nimport subprocess\n\nsubprocess.run(cmd, env={'PATH': os.environ['PATH'], 'LANG': 'C'})\nsubprocess.run(cmd, env=None)\n"
        "subprocess.run(cmd, env={**base})\nsubprocess.run(cmd, cwd=os.environ)\n",
        "passes a named allowlist of variables",
    ),
    Case(
        "identity-env-passthrough",
        "sandbox/run.ts",
        'const child = spawn("node", args, { env: { PATH: process.env.PATH } });\nconst mode = { env: process.env.NODE_ENV };\n',
        "passes named variables only",
    ),
    Case(
        "identity-sensitive-mount",
        "docker-compose.yml",
        COMPOSE_SAFE,
        "mounts a workspace, and only names .aws on the container side",
    ),
    Case(
        "identity-sensitive-mount",
        "web/docker-compose.yml",
        "services:\n  web:\n    image: acme/web\n    volumes:\n      - ~/.ssh:/root/.ssh:ro\n",
        "mounts ~/.ssh in a compose file that is not about an agent or a sandbox",
    ),
]
