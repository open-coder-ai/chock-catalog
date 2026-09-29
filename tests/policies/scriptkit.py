"""Shared helpers for driving a shipped implementation script: load it, run it, build a git repo."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import yaml
from trees import ROOT

GIT = shutil.which("git") or "git"


def load(policy: str, name: str) -> ModuleType:
    """Import `base/<policy>/implementations/<name>` (a hyphenated file name) as a module."""
    path = ROOT / "base" / policy / "implementations" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py").replace("-", "_"), path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def script_path(policy: str, name: str) -> Path:
    return ROOT / "base" / policy / "implementations" / name


def manifest(policy: str) -> dict:
    return yaml.safe_load((ROOT / "base" / policy / "manifest.yaml").read_text(encoding="utf-8"))


def git(repo: Path, *args: str) -> None:
    subprocess.run([GIT, *args], cwd=repo, check=True, capture_output=True)


def init_repo(path: Path, files: dict[str, str | bytes] | None = None) -> Path:
    """A git repository at `path`; `files` are committed as its HEAD when given."""
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "--initial-branch=main")
    git(path, "config", "user.email", "t@example.invalid")
    git(path, "config", "user.name", "t")
    git(path, "config", "commit.gpgsign", "false")
    if files:
        write(path, files)
        git(path, "add", "-A")
        git(path, "commit", "-q", "-m", "base")
    return path


def write(repo: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")


def run_script(
    policy: str, name: str, cwd: Path, stdin: str = "", env: dict[str, str] | None = None
) -> tuple[int, str]:
    """Run the script as a process the way a hook runner does; (exit code, stderr)."""
    proc = subprocess.run(
        [sys.executable, str(script_path(policy, name))],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return proc.returncode, proc.stderr
