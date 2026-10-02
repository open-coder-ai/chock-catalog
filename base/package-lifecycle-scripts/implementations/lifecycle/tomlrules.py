"""pyproject.toml build hooks and Cargo.toml build scripts, read with tomllib."""

from __future__ import annotations

import json
import re
import tomllib

from lifecycle import ASK, BLOCK, Hit, line_of, norm

#: Crates that give a build script a network client (roadmap NP04: network build.rs is blocked).
NET_CRATES = {
    "reqwest", "ureq", "curl", "curl-sys", "hyper", "attohttpc", "isahc", "surf", "minreq", "http_req",
    "http-req", "ehttp", "awc", "ssh2", "native-tls", "rustls",
}  # fmt: skip
PINNED_URL = re.compile(r"@\s*git\+\S+@[0-9a-fA-F]{40}(?:#\S*)?\s*(?:;.*)?$")
#: A bound that stops a future release: `==`, `~=` or an upper `<`/`<=` (`!=` and `>=` alone do not).
UPPER = re.compile(r"(?:==|~=|<)")


def _load(path: str, text: str) -> tuple[dict | None, list[Hit]]:
    try:
        return tomllib.loads(text.removeprefix("\ufeff")), []
    except tomllib.TOMLDecodeError as exc:
        return None, [Hit(1, "manifest-unparseable", path.rsplit("/", 1)[-1], "", BLOCK, f"does not parse ({exc})")]


def _table(data: object, *keys: str) -> dict:
    for key in keys:
        data = data.get(key) if isinstance(data, dict) else None
    return data if isinstance(data, dict) else {}


def _dump(value: object) -> str:
    return norm(json.dumps(value, sort_keys=True, default=str))


def _requires(text: str, requires: object) -> list[Hit]:
    hits = []
    for entry in requires if isinstance(requires, list) else []:
        if not isinstance(entry, str):
            continue
        spec, line = norm(entry), line_of(text, entry.strip())
        if "@" in spec.split(";")[0]:
            if not PINNED_URL.search(spec):
                hits.append(
                    Hit(
                        line,
                        "py-build-requires",
                        "url",
                        spec,
                        BLOCK,
                        "build requirement fetched from a URL without a commit pin",
                    )
                )
        elif not UPPER.search(spec.split(";")[0]):
            name = re.split(r"[\s\[<>=!~;(]", spec, maxsplit=1)[0].lower()
            hits.append(
                Hit(
                    line, "py-build-requires", name, "unpinned", ASK, "build requirement unpinned or bounded below only"
                )
            )
    return hits


def pyproject(path: str, text: str) -> list[Hit]:
    data, hits = _load(path, text)
    if data is None:
        return hits
    system = _table(data, "build-system")
    hits += _requires(text, system.get("requires"))
    if "backend-path" in system:
        value = _dump([system.get("build-backend"), system["backend-path"]])
        hits.append(
            Hit(
                line_of(text, "backend-path"),
                "py-backend-path",
                "build-system.backend-path",
                value,
                ASK,
                "the build backend is code in this repository",
            )
        )
    for name, target in _table(data, "tool", "setuptools", "cmdclass").items():
        hits.append(
            Hit(
                line_of(text, "cmdclass"),
                "setup-cmdclass",
                f"tool.setuptools.cmdclass.{name}",
                norm(str(target)),
                ASK,
                "pyproject replaces a setuptools command",
            )
        )
    hooks = {"tool.hatch.build.hooks.custom": _table(data, "tool", "hatch", "build", "hooks").get("custom")}
    for target, conf in _table(data, "tool", "hatch", "build", "targets").items():
        hooks[f"tool.hatch.build.targets.{target}.hooks.custom"] = _table(conf, "hooks").get("custom")
    poetry = _table(data, "tool", "poetry")
    hooks["tool.poetry.build"] = poetry.get("build")
    pdm = _table(data, "tool", "pdm", "build")
    hooks["tool.pdm.build"] = {k: pdm[k] for k in ("setup-script", "run-setuptools") if k in pdm} or None
    for entry, conf in hooks.items():
        if conf is not None:
            hits.append(
                Hit(
                    line_of(text, entry.split(".")[-1]),
                    "py-build-hook",
                    entry,
                    _dump(conf),
                    ASK,
                    "a build hook runs repository code when the package is built",
                )
            )
    return hits


def cargo_toml(path: str, text: str) -> list[Hit]:
    data, hits = _load(path, text)
    if data is None:
        return hits
    build = _table(data, "package").get("build")
    if build not in (None, False):
        hits.append(
            Hit(
                line_of(text, "build"),
                "cargo-build-script",
                "package.build",
                norm(str(build)),
                ASK,
                "names a build script that runs on every build",
            )
        )
    lib = _table(data, "lib")
    if lib.get("proc-macro") is True or lib.get("proc_macro") is True:
        hits.append(
            Hit(
                line_of(text, "proc"),
                "cargo-proc-macro",
                "lib.proc-macro",
                "true",
                ASK,
                "a procedural macro runs at compile time",
            )
        )
    tables = [("", data)] + [(f"target.{k}.", v) for k, v in _table(data, "target").items()]
    for prefix, table in tables:
        for section in ("build-dependencies", "build_dependencies"):
            for crate, spec in _table(table, section).items():
                real = spec.get("package", crate) if isinstance(spec, dict) else crate
                level = BLOCK if str(real).lower() in NET_CRATES else ASK
                why = "gives the build script a network client" if level == BLOCK else "new build-time dependency"
                line = line_of(text, crate, line_of(text, section))
                entry = f"{prefix}{section}.{crate}"
                hits.append(Hit(line, "cargo-build-dependency", entry, str(real).lower(), level, why))
    return hits
