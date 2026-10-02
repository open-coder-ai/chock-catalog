"""chock_scan.sniff: each kind's signals, at each confidence, and the YAML/JSON forms that must not hide a key.

Every case states the whole candidate set, so a case proves both what is found and what is not.
"""

from __future__ import annotations

from types import ModuleType

import pytest

BOM = chr(0xFEFF)
H, M, L = "high", "medium", "low"
K8S = "apiVersion: v1\nkind: Pod\n"
#: An unnamed key could be any key, so every kind it would complete stays a low candidate.
OPAQUE = {"kubernetes": L, "cloudformation": L, "openapi": L, "compose": L, "mcp-config": L}
SINGLE = {k: v for k, v in OPAQUE.items() if k != "kubernetes"}  # one unnamed key alone completes one-key kinds

CASES = {
    # kubernetes
    "k8s": (K8S, {"kubernetes": H}),
    "k8s-one-key-only": ("apiVersion: v1\nmetadata: {}\n", {}),
    "k8s-split-across-documents": ("apiVersion: v1\n---\nkind: Pod\n", {"kubernetes": L}),
    "k8s-nested-only": ("spec:\n  apiVersion: v1\n  kind: Pod\n", {"kubernetes": L}),
    "k8s-list-item": ("kind: List\nitems:\n- apiVersion: v1\n  kind: Pod\n", {"kubernetes": H}),
    "k8s-indented-root": ("  apiVersion: v1\n  kind: Pod\n", {"kubernetes": H}),
    "k8s-after-200-comment-lines": ("# pad\n" * 200 + K8S, {"kubernetes": H}),
    "k8s-after-200-blank-lines": ("\n" * 200 + K8S, {"kubernetes": H}),
    "k8s-commented-out": ("apiVersion: v1\n# kind: Pod\n", {}),
    "k8s-trailing-comment-is-loose": ("apiVersion: v1 # kind: Pod\n", {"kubernetes": L}),
    "k8s-crlf": (K8S.replace("\n", "\r\n"), {"kubernetes": H}),
    "k8s-cr-only": (K8S.replace("\n", "\r"), {"kubernetes": H}),
    "k8s-nel": (K8S.replace("\n", "\x85"), {"kubernetes": H}),
    "k8s-line-separator": (K8S.replace("\n", chr(0x2028)), {"kubernetes": H}),
    "k8s-double-quoted-keys": ('"apiVersion": v1\n"kind": Pod\n', {"kubernetes": H}),
    "k8s-single-quoted-keys": ("'apiVersion': v1\n'kind' : Pod\n", {"kubernetes": H}),
    "k8s-hex-escaped-key": ('apiVersion: v1\n"\\x6bind": Pod\n', {"kubernetes": H}),
    "k8s-unicode-escaped-key": ('apiVersion: v1\n"\\u006bind": Pod\n', {"kubernetes": H}),
    "k8s-long-escaped-key": ('apiVersion: v1\n"\\U0000006bind": Pod\n', {"kubernetes": H}),
    "k8s-tagged-key": ("apiVersion: v1\n!!str kind: Pod\n", {"kubernetes": H}),
    "k8s-anchored-key": ("&a apiVersion: v1\n&b kind: Pod\n", {"kubernetes": H}),
    "k8s-alias-key-resolved": ("x: &k kind\napiVersion: v1\n*k : Pod\n", {"kubernetes": H}),
    "k8s-alias-key-quoted-anchor": ("x: &k 'kind'\napiVersion: v1\n*k : Pod\n", {"kubernetes": H}),
    "k8s-alias-key-unresolved": ("apiVersion: v1\n*k : Pod\n", OPAQUE),
    "k8s-alias-glued-colon": ("x: &k kind\napiVersion: v1\n*k: Pod\n", {"kubernetes": H}),
    "alias-through-tagged-anchor": ("x-n: &k !!str services\n*k :\n  web: {}\n", {"compose": M}),
    "alias-through-block-anchor": ("x-n: &k >-\n  services\n*k :\n  web: {}\n", SINGLE),
    "alias-through-multi-word-anchor": ("x: &k foo bar\n*k : 1\n", SINGLE),
    "alias-through-anchored-key": ("x:\n  &k kind: 1\napiVersion: v1\n*k : Pod\n", {"kubernetes": H}),
    "anchor-reused-in-comment": ("x: &k kind\n# &k nope\napiVersion: v1\n*k : Pod\n", {"kubernetes": H}),
    "anchor-reused-in-string": (
        "x: &k kind\ny: 'a &k nope, b'\napiVersion: v1\n*k : Pod\n",
        SINGLE | {"kubernetes": L},
    ),
    "anchor-reused-in-block": (
        "x: &k kind\ns: |\n  run &k nope\napiVersion: v1\n*k : Pod\n",
        SINGLE | {"kubernetes": L},
    ),
    "anchor-hash-without-space": ("x: &k kind#x\napiVersion: v1\n*k : Pod\n", SINGLE | {"kubernetes": L}),
    "anchor-then-comment": ("x: &k kind # c\napiVersion: v1\n*k : Pod\n", {"kubernetes": H}),
    "anchor-in-flow": ("x: [&k kind, b]\napiVersion: v1\n*k : Pod\n", {"kubernetes": H}),
    "json-then-yaml-document": ("{}\n---\n" + K8S, {"kubernetes": H}),
    "tab-only-line-in-indented-root": ("  apiVersion: v1\n\t\n  kind: Pod\n", {"kubernetes": H}),
    "tab-comment-in-indented-root": ("  apiVersion: v1\n\t# c\n  kind: Pod\n", {"kubernetes": H}),
    "jsonc-comment-touching-key": ('{\n  /* c */"mcpServers": {}\n}', {"mcp-config": L}),
    "json-colon-on-next-line": ('{\n // c\n "mcpServers"\n  : {}\n}', {"mcp-config": L}),
    "k8s-alias-value-not-key": ("apiVersion: v1\nx:\n- *k\n", {}),
    "k8s-explicit-key": ("apiVersion: v1\n? kind\n: Pod\n", OPAQUE),
    "two-unnamed-keys": ("? a\n? b\nhosts: x\n", OPAQUE | {"github-actions": L, "ansible": L}),
    "k8s-flow-mapping": ("{apiVersion: v1, kind: Pod}\n", {"kubernetes": L}),
    "k8s-json": ('{\n  "apiVersion": "v1",\n  "kind": "Pod"\n}\n', {"kubernetes": H}),
    "k8s-json-escaped-key": ('{"apiVersion": "v1", "\\u006bind": "Pod"}', {"kubernetes": H}),
    "k8s-jsonc-is-loose": ('// manifest\n{\n  "apiVersion": "v1",\n  "kind": "Pod"\n}\n', {"kubernetes": L}),
    "k8s-json-root-array": ('[{"apiVersion": "v1", "kind": "Pod"}, 1]', {"kubernetes": H}),
    "k8s-bom-on-second-document": ("a: 1\n---\n" + BOM + K8S, {"kubernetes": H}),
    "k8s-directive": ("%YAML 1.2\n---\n" + K8S, {"kubernetes": H}),
    "k8s-document-end-marker": ("apiVersion: v1\n...\nkind: Pod\n", {"kubernetes": L}),
    "k8s-tab-indented-is-loose": ("\tapiVersion: v1\n\tkind: Pod\n", {"kubernetes": L}),
    "k8s-plain-key-without-space": ("apiVersion:v1\nkind:Pod\n", {"kubernetes": L}),
    "k8s-dedent-resets-root": ("    junk: 1\napiVersion: v1\nkind: Pod\n", {"kubernetes": H}),
    # cloudformation
    "cfn-version": ("AWSTemplateFormatVersion: '2010-09-09'\n", {"cloudformation": H}),
    "cfn-sam-transform": ("Transform: AWS::Serverless-2016-10-31\n", {"cloudformation": H}),
    "cfn-sam-transform-list": ("Transform:\n  - AWS::Serverless-2016-10-31\n", {"cloudformation": H}),
    "cfn-other-transform": ("Transform: AWS::Include\n", {}),
    "cfn-resources": ("Resources:\n  B:\n    Type: AWS::S3::Bucket\n", {"cloudformation": M}),
    "cfn-resources-json": ('{"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}', {"cloudformation": M}),
    "cfn-resources-type-unknown": ("Resources:\n  B:\n    Type: Custom\n", {"cloudformation": L}),
    "cfn-registry-type": ("Resources:\n  S:\n    Type: Alexa::ASK::Skill\n", {"cloudformation": M}),
    "cfn-type-on-next-line": ("Resources:\n  B:\n    Type:\n      AWS::S3::Bucket\n", {"cloudformation": M}),
    "cfn-json-escaped-type": ('{"Resources":{"B":{"Type":"\\u0041WS::S3::Bucket"}}}', {"cloudformation": L}),
    # openapi, compose, actions, mcp
    "openapi": ("openapi: 3.0.0\ninfo: {}\n", {"openapi": H}),
    "swagger": ('{"swagger": "2.0"}', {"openapi": H}),
    "compose": ("services:\n  web:\n    image: nginx\n", {"compose": M}),
    "actions": ("name: ci\non: push\njobs:\n  a: {}\n", {"github-actions": H}),
    "actions-quoted-on": ('"on": [push]\njobs: {}\n', {"github-actions": H}),
    "actions-on-only": ("on: push\n", {}),
    "mcp": ('{"mcpServers": {"x": {"command": "npx"}}}', {"mcp-config": H}),
    "mcp-nested-is-loose": ('{"x": {"mcpServers": {}}}', {"mcp-config": L}),
    # ansible
    "ansible": ("- hosts: all\n  tasks:\n    - ping:\n", {"ansible": H}),
    "ansible-name-first": ("---\n- name: p\n  hosts: all\n  tasks: []\n", {"ansible": H}),
    "ansible-bare-dash": ("-\n  hosts: all\n  tasks: []\n", {"ansible": H}),
    "ansible-tab-after-dash": ("-\thosts: all\n \ttasks: []\n", {"ansible": L}),
    "ansible-anchored-item": ("- &p hosts: all\n  tasks: []\n", {"ansible": H}),
    "ansible-roles": ("- hosts: all\n  roles: [a]\n", {"ansible": M}),
    "ansible-pre-tasks": ("- hosts: all\n  pre_tasks: []\n", {"ansible": M}),
    "ansible-post-tasks": ("- hosts: all\n  post_tasks: []\n", {"ansible": M}),
    "ansible-handlers": ("- hosts: all\n  handlers: []\n", {"ansible": M}),
    "ansible-two-plays": ("- hosts: a\n  roles: [r]\n- hosts: b\n  tasks: []\n", {"ansible": H}),
    "ansible-keys-in-different-plays": ("- hosts: a\n- tasks: []\n", {"ansible": L}),
    "ansible-nested-sequence": ("- - hosts: a\n    tasks: []\n", {"ansible": L}),
    # nothing
    "empty": ("", {}),
    "prose": ("Copy the file.\nThen run it.\n", {}),
    "only-comments": ("# kind: Pod\n# apiVersion: v1\n", {}),
    "key-after-colon-in-plain": ("a:b: 1\n", {}),
    "indicator-start": ("- [kind, apiVersion]\n", {}),
    "props-only-line": ("&a \n", {}),
}


@pytest.mark.parametrize(("text", "expected"), CASES.values(), ids=CASES.keys())
def test_mapped_kinds(sn: ModuleType, text: str, expected: dict[str, str]) -> None:
    result = sn.sniff(text.encode("utf-8"))
    assert {c.kind: c.confidence for c in result.candidates} == expected
    assert result.unknown is (not expected)


DOCKER = {
    "plain": ("FROM alpine\nRUN true\n", {"dockerfile": H}),
    "lowercase": ("from alpine\n", {"dockerfile": H}),
    "directives-and-comments": ("# syntax=docker/dockerfile:1\n\n# c\nFROM a\n", {"dockerfile": H}),
    "arg-first": ("ARG V=1\nFROM a:${V}\n", {"dockerfile": H}),
    "arg-continued": ("ARG V=\\\n  1\nFROM a\n", {"dockerfile": H}),
    "comment-in-continuation": ("ARG V=\\\n# note\n  1\nFROM a\n", {"dockerfile": H}),
    "escape-backtick": ("# escape=`\nARG V=`\n  1\nFROM a\n", {"dockerfile": H}),
    "escape-invalid-is-ignored": ("# escape=x\nARG V=\\\n  1\nFROM a\n", {"dockerfile": H}),
    "late-directive-is-comment": ("FROM a\n# escape=`\n", {"dockerfile": H}),
    "from-without-image": ("FROM\nRUN x\n", {}),
    "run-first-is-loose": ("RUN x\nFROM a\n", {"dockerfile": L}),
    "from-and-copy-anywhere": ("junk line\nFROM a\nCOPY . .\n", {"dockerfile": L}),
    "from-only-not-first": ("junk line\nFROM a\n", {}),
    "crlf": ("FROM a\r\nRUN x\r\n", {"dockerfile": H}),
    "only-arg": ("ARG V=1\n", {}),
    "keyword-split-by-continuation": ("FR\\\nOM alpine\nRU\\\nN x\n", {"dockerfile": H}),
    "image-on-continuation": ("FROM\\\n alpine\nRUN\\\n x\n", {"dockerfile": H}),
    "continuation-at-end": ("FROM a \\", {"dockerfile": H}),
    "lone-continuation": ("\\\n", {}),
}


@pytest.mark.parametrize(("text", "expected"), DOCKER.values(), ids=DOCKER.keys())
def test_dockerfile(sn: ModuleType, text: str, expected: dict[str, str]) -> None:
    assert {c.kind: c.confidence for c in sn.sniff(text.encode("utf-8")).candidates} == expected


def test_candidates_are_ranked_and_carry_their_signal(sn: ModuleType) -> None:
    text = "#!/bin/sh\nservices: {}\nAWSTemplateFormatVersion: x\n"
    result = sn.sniff(text.encode("utf-8"))
    assert [(c.kind, c.confidence) for c in result.candidates] == [
        ("cloudformation", H),
        ("script", H),
        ("shell", H),
        ("compose", M),
    ]
    assert result.candidates[0].signal == "top-level AWSTemplateFormatVersion"
    assert result.kinds() == {"cloudformation", "script", "shell", "compose"}
    assert result.kinds(H) == {"cloudformation", "script", "shell"}
    assert result.kinds(M) == {"cloudformation", "script", "shell", "compose"}


def test_signals_name_what_matched(sn: ModuleType) -> None:
    signals = {
        "openapi: 3\n*k : Pod\n": "top-level openapi",
        "apiVersion: v1\n*k : Pod\n": "top-level AWSTemplateFormatVersion, some keys unnamed",
        "a:\n  apiVersion: v1\n  kind: Pod\n": "apiVersion+kind anywhere",
        "RUN x\nFROM a\n": "FROM and build instruction lines",
        "FROM a\n": "first instruction FROM",
    }
    for text, signal in signals.items():
        assert sn.sniff(text.encode("utf-8")).candidates[0].signal == signal
