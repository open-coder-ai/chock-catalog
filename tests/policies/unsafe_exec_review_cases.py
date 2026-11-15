"""The `uce-*` inputs of the 2026-11-15 dependency and code-execution review (REVIEW-deps.md, section 9 and its appendix).

Each case is (event, files the change adds or rewrites, files HEAD already holds). The review's pragma
cases (uce-k22, uce-w01 to w03, w05) carry a waiver line a person owns and are not rebuilt here.
"""

from __future__ import annotations

README = {"README.md": "x\n"}

# Bad changes inside the policy's claim: 33 of them (uce-c30 and c31 lie outside it and are not rebuilt).
CATCH: dict[str, tuple[str, dict[str, str], dict[str, str]]] = {
    "uce-c01": ("commit", {"app/calc.py": "def run(user_input):\n    return eval(user_input)\n"}, README),
    "uce-c02": ("commit", {"app/run.py": "def run(code):\n    exec(code)\n"}, README),
    "uce-c03": (
        "commit",
        {"app/ops.py": 'import os\n\n\ndef clean(d):\n    os.system(f"rm -rf {d}")\n'},
        README,
    ),
    "uce-c04": (
        "commit",
        {"app/ops.py": "import subprocess\n\n\ndef go(cmd):\n    subprocess.run(cmd, shell=True, check=True)\n"},
        README,
    ),
    "uce-c05": (
        "commit",
        {
            "app/ops.py": "import subprocess\n\n\ndef go(cmd):\n    subprocess.Popen(\n        cmd,\n        shell = True,\n    )\n"
        },
        README,
    ),
    "uce-c06": (
        "commit",
        {"app/rpc.py": "import pickle\n\n\ndef handle(data):\n    return pickle.loads(data)\n"},
        README,
    ),
    "uce-c07": (
        "commit",
        {"app/rpc.py": "import pickle as pkl\n\n\ndef handle(data):\n    return pkl.loads(data)\n"},
        README,
    ),
    "uce-c08": (
        "commit",
        {"app/rpc.py": "from pickle import loads\n\n\ndef handle(data):\n    return loads(data)\n"},
        README,
    ),
    "uce-c09": ("commit", {"app/conf.py": "import yaml\n\n\ndef read(f):\n    return yaml.load(f)\n"}, README),
    "uce-c10": (
        "commit",
        {"app/conf.py": "import yaml\n\n\ndef read(f):\n    return yaml.load(f, Loader=yaml.Loader)\n"},
        README,
    ),
    "uce-c11": (
        "commit",
        {
            "app/ops.py": "from subprocess import run\n\nOPTS = dict(shell=True)\n\n\ndef go(cmd):\n    run(cmd, **OPTS)\n"
        },
        README,
    ),
    "uce-c12": (
        "commit",
        {
            "tests/helpers.py": "import subprocess\n\n\ndef ls(d):\n"
            '    return subprocess.run("ls " + d, shell=True, capture_output=True)\n'
        },
        README,
    ),
    "uce-c13": (
        "commit",
        {"app/calc.py": "import builtins\n\n\ndef run(x):\n    return getattr(builtins, 'ev' + 'al')(x)\n"},
        README,
    ),
    "uce-c14": ("commit", {"src/calc.js": "export function run(req) {\n  return eval(req.body.expr);\n}\n"}, README),
    "uce-c15": (
        "commit",
        {"src/calc.ts": "export const make = (body: string) => new Function('a', body);\n"},
        README,
    ),
    "uce-c16": (
        "commit",
        {"src/ops.js": "const cp = require('child_process');\nfunction clean(dir) {\n  cp.exec(`rm -rf ${dir}`);\n}\n"},
        README,
    ),
    "uce-c17": (
        "commit",
        {"src/ops.js": "const { exec } = require('child_process');\nfunction go(cmd) {\n  exec(cmd);\n}\n"},
        README,
    ),
    "uce-c18": (
        "commit",
        {
            "src/ops.js": "const { spawn } = require('child_process');\n"
            "function go(cmd) {\n  return spawn(cmd, { shell: true });\n}\n"
        },
        README,
    ),
    "uce-c19": (
        "commit",
        {"src/ui.js": 'function later(code) {\n  setTimeout("doThing(" + code + ")", 100);\n}\n'},
        README,
    ),
    "uce-c20": (
        "commit",
        {
            "src/main/java/a/Ops.java": "package a;\n\npublic class Ops {\n"
            "  void go(String cmd) throws Exception {\n    Runtime.getRuntime().exec(cmd);\n  }\n}\n"
        },
        README,
    ),
    "uce-c21": (
        "commit",
        {
            "src/main/java/a/Ops.java": "package a;\n\npublic class Ops {\n"
            '  void go(String cmd) throws Exception {\n    new ProcessBuilder("sh", "-c", cmd).start();\n  }\n}\n'
        },
        README,
    ),
    "uce-c22": (
        "commit",
        {
            "ops.go": 'package main\n\nimport "os/exec"\n\n'
            'func run(cmd string) error {\n\treturn exec.Command("sh", "-c", cmd).Run()\n}\n'
        },
        README,
    ),
    "uce-c23": (
        "commit",
        {
            "src/ops.rs": "use std::process::Command;\n\n"
            'pub fn run(cmd: &str) {\n    Command::new("sh").arg("-c").arg(cmd).status().unwrap();\n}\n'
        },
        README,
    ),
    "uce-c24": ("commit", {"app/calc.rb": "def run(params)\n  eval(params[:code])\nend\n"}, README),
    "uce-c25": (
        "commit",
        {"app/img.rb": 'def convert(file)\n  system("convert #{file} out.png")\nend\n'},
        README,
    ),
    "uce-c26": (
        "commit",
        {"web/run.php": "<?php\nfunction run($code) {\n    return eval($code);\n}\n"},
        README,
    ),
    "uce-c27": ("commit", {"web/run.php": "<?php\necho shell_exec($_GET['cmd']);\n"}, README),
    "uce-c28": (
        "commit",
        {
            "src/Ops.cs": "using System.Diagnostics;\n\nclass Ops {\n"
            '    void Go(string input) {\n        Process.Start("cmd.exe", "/c " + input);\n    }\n}\n'
        },
        README,
    ),
    "uce-c29": ("commit", {"scripts/run.sh": '#!/bin/sh\nCMD="$1"\neval "$CMD"\n'}, README),
    "uce-c32": ("tool_use", {"app/calc.py": "def run(user_input):\n    return eval(user_input)\n"}, README),
    "uce-c33": ("stop", {"app/ops.py": "import os\n\n\ndef clean(d):\n    os.system('rm -rf ' + d)\n"}, README),
    "uce-c34": ("commit", {"ml/load.py": "import torch\n\n\ndef load(path):\n    return torch.load(path)\n"}, README),
    "uce-c35": (
        "commit",
        {
            "nb/explore.ipynb": '{\n "cells": [\n'
            '  {"cell_type": "code", "source": ["import os\\n", "os.system(cmd)\\n"]}\n'
            ' ],\n "nbformat": 4\n}\n'
        },
        README,
    ),
}
