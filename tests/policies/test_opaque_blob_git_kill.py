"""opaque-blob-guard: reading a git object past the hash cap kills git, and that works where signal.SIGKILL does not exist."""

from __future__ import annotations

import io

import pytest
from policies import blobkit

gate, ns = blobkit.load()


class FakeGit:
    """A git process that was killed after the hash cap (returncode 1, as on Windows) or ended with `code`."""

    def __init__(self, data: bytes, code: int) -> None:
        self.stdout = io.BytesIO(data)
        self.returncode = None
        self.killed = False
        self._code = code

    def kill(self) -> None:
        self.killed = True

    def communicate(self) -> tuple[bytes, bytes]:
        self.returncode = 1 if self.killed else self._code
        return b"", b""


def test_a_killed_process_with_any_exit_code_still_yields_the_blob(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows reports a killed process as exit code 1, and has no signal.SIGKILL to compare it with."""
    monkeypatch.setattr(ns.source, "HASH_CAP", 10)
    monkeypatch.setattr(ns.source.subprocess, "Popen", lambda *_args, **_kwargs: FakeGit(b"x" * 100, 0))
    blob = ns.source.read_git(".", ":big")
    assert blob is not None
    assert blob.sha is None


@pytest.mark.parametrize(("code", "found"), [(0, True), (128, False), (1, False)])
def test_a_process_that_ended_by_itself_yields_a_blob_only_on_success(
    monkeypatch: pytest.MonkeyPatch, code: int, found: bool
) -> None:
    monkeypatch.setattr(ns.source.subprocess, "Popen", lambda *_args, **_kwargs: FakeGit(b"small", code))
    assert (ns.source.read_git(".", ":small") is not None) is found
