"""agent-devenv-autoexec: git files (.gitmodules, .gitattributes, gitconfig) and the git config reader."""

from __future__ import annotations

import pytest
from policies import devenvkit
from policies.devenvkit import gate


def rules(path: str, text: str) -> list[tuple[str, str]]:
    """At tool use: the text is judged as written, without the raw-blob read commit adds (test_..._review)."""
    return devenvkit.rules(path, text, "tool_use")


MODULES, ATTRS, CONFIG = "dev-gitmodules-untrusted", "dev-gitattributes-filter", "dev-gitconfig-exec"
B = "block"
UNREAD = [("dev-unparseable", B)]
entries = gate.sys.modules["devenv.gitfiles"].entries


def module(name: str, **fields: str) -> str:
    return f'[submodule "{name}"]\n' + "".join(f"\t{k} = {v}\n" for k, v in fields.items())


@pytest.mark.parametrize(
    "url",
    ["ext::sh -c x", "http://x.example/a.git", "git://x.example/a", "file:///tmp/a", "-uhelp", "fd::3", "foo::bar"],
)
def test_untrusted_urls(url: str) -> None:
    assert rules(".gitmodules", module("a", path="a", url=url)) == [(MODULES, B)]


@pytest.mark.parametrize("path", ["../escape", "a/../../b", "-x", "/abs", "C:x", "a\tb"])
def test_untrusted_paths(path: str) -> None:
    assert rules(".gitmodules", module("a", path=f'"{path}"' if "\t" in path else path, url="https://x/a")) == [
        (MODULES, B)
    ]


def test_name_case_collision_update_and_cr() -> None:
    assert rules(".gitmodules", module("../../hooks", url="https://x/a")) == [(MODULES, B)]
    text = module("a", path="Lib", url="https://x/a") + module("b", path="lib", url="https://x/b")
    assert rules(".gitmodules", text) == [(MODULES, B)]
    assert rules(".gitmodules", module("a", update="!sh x")) == [(MODULES, B)]
    assert rules(".gitmodules", '[submodule "a"]\n\tpath = "lib\r"\n') == [(MODULES, B)]
    assert rules(".gitmodules", '[submodule "a"]\r\n\tpath = lib\r\n') == []


def test_ordinary_modules_and_other_sections() -> None:
    text = module("a", path="vendor/a", url="https://x/a.git", branch="main", update="rebase")
    assert rules(".gitmodules", text + "[core]\n\tbare = false\n") == []
    assert rules(".gitmodules", module("a", url="../sibling.git")) == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('[a]\nk = "x" ; c\n', [("a", "", "k", "x", 2)]),
        ("[a]\nflag\n", [("a", "", "flag", "true", 2)]),
        ("[a.Sub]\nk = 1\n", [("a", "sub", "k", "1", 2)]),
        ('[a "S"] k = v\n', [("a", "S", "k", "v", 1)]),
        ("[a]\nk = one \\\n two\n# c\n; d\n\n", [("a", "", "k", "one  two", 2)]),
        ('[a]\nk = "q\\"\\t\\\\" # c\n', [("a", "", "k", 'q"\t\\', 2)]),
    ],
)
def test_config_reader(text: str, expected: list) -> None:
    assert entries(text) == expected


@pytest.mark.parametrize(
    "text",
    ['[a]\nk = "open\n', "[a]\nk = x \\", "[a]\nk = \\q\n", "k = 1\n", "[a]\n= 1\n", "[a]\nflag extra\n"],
)
def test_config_reader_refuses(text: str) -> None:
    assert rules(".gitconfig", text) == UNREAD


def test_attributes() -> None:
    text = "# filter=x\n*.a filter=decode\n*.b diff=exif merge=custom\n*.c -diff !filter text\n*.py diff=python\n"
    assert rules(".gitattributes", text) == [(ATTRS, B), (ATTRS, "ask"), (ATTRS, B)]
    assert rules("sub/.gitattributes", "*.psd filter=lfs diff=lfs merge=lfs -text\n*.x merge=union\n") == []


@pytest.mark.parametrize(
    "line",
    [
        "[core]\n\tfsmonitor = ./watch",
        "[core]\n\tsshCommand = ssh -o ProxyCommand=x",
        "[core]\n\thooksPath = .hooks",
        '[alias]\n\tst = "!sh -c x"',
        "[credential]\n\thelper = !x",
        '[credential "https://x"]\n\thelper = store',
        '[filter "a"]\n\tsmudge = x',
        '[diff "a"]\n\ttextconv = x',
        '[merge "a"]\n\tdriver = x',
        "[include]\n\tpath = ../x",
        '[includeIf "gitdir:~/"]\n\tpath = x',
        '[url "https://evil/"]\n\tinsteadOf = https://github.com/',
        '[http "https://x/"]\n\textraHeader = A: b',
        "[http]\n\tsslVerify = false",
        "[transfer]\n\tfsckObjects = false",
        "[protocol]\n\tallow = always",
        '[protocol "file"]\n\tallow = always',
        "[safe]\n\tdirectory = *",
        "[pager]\n\tlog = x",
    ],
)
def test_config_exec_keys(line: str) -> None:
    assert rules("team.gitconfig", line + "\n") == [(CONFIG, B)]


def test_config_ordinary_and_cr() -> None:
    text = "[core]\n\tfsmonitor = true\n\tautocrlf = input\n[alias]\n\tco = checkout\n[http]\n\tsslVerify = true\n"
    assert rules(".gitconfig", text) == []
    assert rules(".git/config", '[core]\n\tbare = false\r\n\tx = "a\rb"\n') == [(CONFIG, B)]
