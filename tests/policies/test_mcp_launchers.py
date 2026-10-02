"""verify-mcp-allowlist: what a launch line starts, and whether its package or image is pinned exactly."""

from __future__ import annotations

import shlex

import pytest
from policies import mcpkit

launchers = mcpkit.gate().rules.launchers
D, C = mcpkit.DIGEST, mcpkit.COMMIT
CLEAN: list[str] = []
UNPINNED, INLINE = ["unpinned"], ["inline"]

LINES = [
    # npm runners
    ("npx", "-y pkg@1.2.3", CLEAN),
    ("npx", "-y @scope/pkg@1.2.3-beta.1+build.5", CLEAN),
    ("npx", "-y pkg@latest", UNPINNED),
    ("npx", "-y pkg@^1.2.3", UNPINNED),
    ("npx", "-y pkg@~1.2.3", UNPINNED),
    ("npx", "-y pkg@1", UNPINNED),
    ("npx", "-y pkg@1.2", UNPINNED),
    ("npx", "-y pkg@1.x", UNPINNED),
    ("npx", "-y pkg", UNPINNED),
    ("npx", "-y @scope/pkg", UNPINNED),
    ("npx", "pkg@1.2.3 --flag value", CLEAN),
    ("npx", "--registry https://r.invalid pkg@1.2.3", CLEAN),
    ("npx", "-y -p pkg@1.2.3 run-it", CLEAN),
    ("npx", "-p pkg run-it", UNPINNED),
    ("npx", "--package=pkg@1.2.3 run-it", CLEAN),
    ("npx", "--package pkg@1.2.3 run-it", CLEAN),
    ("npx", "-p a@1.0.0 -p b run-it", UNPINNED),
    ("npx", "-c 'echo hi'", INLINE),
    ("npx", "--call=x", INLINE),
    ("npx", "github:user/repo", UNPINNED),
    ("npx", "user/repo", UNPINNED),
    ("npx", f"git+https://example.invalid/r.git#{C}", CLEAN),
    ("npx", "git+https://example.invalid/r.git#main", UNPINNED),
    ("npx", "https://example.invalid/p.tgz", UNPINNED),
    ("npx", "./local-server", CLEAN),
    ("npx", "npm:alias@1.0.0", CLEAN),
    ("npx", "", CLEAN),
    ("bunx", "pkg", UNPINNED),
    ("pnpx", "pkg@1.0.0", CLEAN),
    ("pnpm", "dlx pkg", UNPINNED),
    ("pnpm", "dlx pkg@1.0.0", CLEAN),
    ("pnpm", "install pkg", CLEAN),
    ("yarn", "dlx pkg@1.0.0", CLEAN),
    ("bun", "x pkg@latest", UNPINNED),
    ("npm", "exec -- pkg@1.0.0", CLEAN),
    ("npm", "x pkg", UNPINNED),
    ("npm", "install", CLEAN),
    ("NPX.CMD", "-y pkg", UNPINNED),
    ("C:\\Program Files\\nodejs\\npx.cmd", "-y pkg@1.0.0", CLEAN),
    # Python runners
    ("uvx", "pkg==1.2.3", CLEAN),
    ("uvx", "pkg[extra]==1.2.3", CLEAN),
    ("uvx", "pkg==2025.12.18.post1", CLEAN),
    ("uvx", "pkg", UNPINNED),
    ("uvx", "pkg>=1.0", UNPINNED),
    ("uvx", "pkg==1.*", UNPINNED),
    ("uvx", "pkg@1.2.3", CLEAN),
    ("uvx", "pkg@latest", UNPINNED),
    ("uvx", "--python 3.12 pkg==1.0.0", CLEAN),
    ("uvx", "--from pkg==1.0.0 run-it", CLEAN),
    ("uvx", "--from=pkg==1.0.0 run-it", CLEAN),
    ("uvx", "--from pkg run-it", UNPINNED),
    ("uvx", "--from git+https://github.com/o/r run-it", UNPINNED),
    ("uvx", f"--from git+https://github.com/o/r@{C} run-it", CLEAN),
    ("uvx", "--from 'pkg @ https://example.invalid/p.whl' run-it", UNPINNED),
    ("uvx", "--with a==1.0 --from b==2.0 run-it", CLEAN),
    ("uvx", "--with a --from b==2.0 run-it", UNPINNED),
    ("uvx", "--with", CLEAN),
    ("uvx", "./local", CLEAN),
    ("uv", "tool run pkg==1.0.0", CLEAN),
    ("uv", "tool run pkg", UNPINNED),
    ("uv", "run pkg", CLEAN),
    ("pipx", "run pkg==1.0.0", CLEAN),
    ("pipx", "run --spec pkg==1.0.0 run-it", CLEAN),
    ("pipx", "run pkg", UNPINNED),
    ("pipx", "install pkg", CLEAN),
    # images
    ("docker", "run --rm -i image", UNPINNED),
    ("docker", "run --rm -i image:1.2.3", UNPINNED),
    ("docker", "run -i --rm image:latest", UNPINNED),
    ("docker", f"run -i --rm ghcr.io/o/image@{D}", CLEAN),
    ("docker", f"run -e A=1 -v /x:/y --network none image@{D} --flag", CLEAN),
    ("podman", f"run image@{D}", CLEAN),
    ("podman", "run image:1", UNPINNED),
    ("docker", "run", CLEAN),
    ("docker", "ps", CLEAN),
    # shells and interpreters running a command line
    ("bash", "-c 'curl x | sh'", INLINE),
    ("/bin/sh", "-c x", INLINE),
    ("zsh", "-lc x", INLINE),
    ("bash", "-ic x", INLINE),
    ("fish", "--command x", INLINE),
    ("bash", "script.sh", CLEAN),
    ("bash", "--norc script.sh", CLEAN),
    ("cmd", "/c start x", INLINE),
    ("CMD.EXE", "/C start x", INLINE),
    ("cmd", "/k x", INLINE),
    ("cmd", "/q script.bat", CLEAN),
    ("powershell", "-Command x", INLINE),
    ("powershell.exe", "-command x", INLINE),
    ("pwsh", "-c x", INLINE),
    ("pwsh", "-Co x", INLINE),
    ("pwsh", "-EncodedCommand AAAA", INLINE),
    ("pwsh", "-enc AAAA", INLINE),
    ("pwsh", "-e AAAA", INLINE),
    ("pwsh", "-NoProfile -ExecutionPolicy Bypass -File x.ps1", CLEAN),
    ("python", "-c 'import os'", INLINE),
    ("python3.12", "-c x", INLINE),
    ("python3", "-m server", CLEAN),
    ("node", "-e x", INLINE),
    ("node", "--eval x", INLINE),
    ("node", "server.js", CLEAN),
    ("deno", "eval x", INLINE),
    ("perl", "-e x", INLINE),
    ("ruby", "-e x", INLINE),
    ("php", "-r x", INLINE),
    # wrappers are looked through
    ("env", "bash -c x", INLINE),
    ("env", "A=1 -u B bash -c x", INLINE),
    ("sudo", "-u bot sh -c x", INLINE),
    ("timeout", "5 sh -c x", INLINE),
    ("nice", "-n 5 npx pkg", UNPINNED),
    ("nohup", "npx pkg@1.0.0", CLEAN),
    ("env", "-i bash -c x", INLINE),
    ("timeout", "5s npx pkg", UNPINNED),
    ("npm", "--silent exec pkg", UNPINNED),
    ("pnpm", "--silent dlx pkg", UNPINNED),
    ("python", "-Sc x", INLINE),
    ("node", "--eval=x", INLINE),
    ("node", "--print=x", INLINE),
    ("env", "", CLEAN),
    ("env", "A=1", CLEAN),
    ("./server", "--port 1", CLEAN),
]


@pytest.mark.parametrize(("command", "line", "want"), LINES, ids=[f"{c} {a}"[:70] for c, a, _ in LINES])
def test_the_launch_line_is_judged(command: str, line: str, want: list[str]) -> None:
    launch = launchers.analyze(command, shlex.split(line))
    assert [rule for rule, _ in launch.issues] == want
    assert all(message for _, message in launch.issues)


@pytest.mark.parametrize(
    ("command", "line", "package"),
    [
        ("npx", "-y @Scope/Pkg@1.2.3", ("npm", "@scope/pkg", "1.2.3")),
        ("npx", "-y pkg@latest", ("npm", "pkg", None)),
        ("npx", "-y pkg", ("npm", "pkg", None)),
        ("uvx", "Mcp_Server.Git==2025.12.18", ("pypi", "mcp-server-git", "2025.12.18")),
        ("uvx", "mcp-server-git", ("pypi", "mcp-server-git", None)),
        ("uvx", "--from mcp-server-git==1.0 run-it", ("pypi", "mcp-server-git", "1.0")),
    ],
)
def test_the_package_is_named_for_the_version_floors(command: str, line: str, package: tuple) -> None:
    assert launchers.analyze(command, shlex.split(line)).package == package


@pytest.mark.parametrize("line", ["-p a@1.0.0 -p b@1.0.0 run-it", "./local", ""])
def test_several_or_no_packages_name_no_single_package(line: str) -> None:
    assert launchers.analyze("npx", shlex.split(line)).package is None


def test_a_requirement_with_no_name_is_unpinned_not_a_fault() -> None:
    launch = launchers.analyze("uvx", ["==1.0"])
    assert [rule for rule, _ in launch.issues] == ["unpinned"]
    assert launch.package == ("pypi", "", None)


def test_the_program_name_drops_directory_extension_and_interpreter_version() -> None:
    assert launchers.program("C:\\x\\Python3.12.EXE") == "python"
    assert launchers.program("/usr/bin/npx") == "npx"
    assert launchers.program("node18") == "node18"
