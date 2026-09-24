"""The engine's own refusals: a registry that contradicts itself, and a gate whose engine fails.

Both are states no shipped build is in, which is the point: they are the states a broken copy or
a bad merge produces, and each must refuse loudly rather than run a partial rule set.
"""

from __future__ import annotations

import importlib.util
import io
import json
from types import ModuleType, SimpleNamespace

import pytest
from chock_security import rules as registry_module
from chock_security.decision import UNJUDGED
from chock_security.pack import Pack, Rule
from java_security.conftest import GATE


def _pack(pack_id: str, *rules: Rule) -> SimpleNamespace:
    return SimpleNamespace(PACK=Pack(id=pack_id, title=pack_id, covers=pack_id), RULES=rules)


def _rule(rule_id: str, pack: str) -> Rule:
    return Rule(id=rule_id, pack=pack, title=rule_id, suffixes=(".java",), scan=lambda _text: iter(()))


def test_a_rule_registered_under_another_pack_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry_module, "_PACKS", (_pack("java", _rule("x-one", "spring")),))
    with pytest.raises(ValueError, match="says pack 'spring' but is registered in 'java'"):
        registry_module.registry()


def test_a_rule_id_registered_twice_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    packs = (_pack("java", _rule("x-one", "java")), _pack("spring", _rule("x-one", "spring")))
    monkeypatch.setattr(registry_module, "_PACKS", packs)
    with pytest.raises(ValueError, match="registered twice"):
        registry_module.registry()


def _gate_module() -> ModuleType:
    """The shipped gate, imported rather than run, so its engine can be made to fail."""
    spec = importlib.util.spec_from_file_location("java_security_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_engine_that_fails_refuses_instead_of_allowing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    gate = _gate_module()

    def broken(_files: object, _verdicts: object) -> list:
        msg = "a rule raised"
        raise RuntimeError(msg)

    monkeypatch.setattr(gate, "evaluate", broken)
    payload = {"repo_root": str(tmp_path), "writes": {"A.java": "class A {}\n"}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    assert gate.main() == gate.REFUSE
    assert UNJUDGED.format(reason="RuntimeError: a rule raised") in capsys.readouterr().err
