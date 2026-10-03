"""verify-dependency-exists: the JVM, .NET, Go, Elixir, Dart and Swift readers return the names they should, and only those."""

from __future__ import annotations

import pytest
from policies import depkit

_, r = depkit.load()
maven = r.maven
xmlsafe = r.xmlsafe
dotnet = r.dotnet
gradle = r.gradle
golang = r.golang
elixir = r.elixir
dart = r.dart
swift = r.swift


def names(reader, text: str) -> list[str]:
    return sorted(reader(text))


POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.spring</groupId><artifactId>parent</artifactId></parent>
  <dependencyManagement><dependencies>
    <dependency><groupId>g1</groupId><artifactId>managed</artifactId></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>g2</groupId><artifactId>direct</artifactId></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>sibling</artifactId></dependency>
    <dependency><artifactId>no-group</artifactId></dependency>
    <dependency><groupId>g3</groupId></dependency>
    <dependency><groupId>g4</groupId><artifactId>a</artifactId><exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions></dependency>
  </dependencies>
  <build><plugins>
    <plugin><artifactId>maven-compiler-plugin</artifactId></plugin>
    <plugin><groupId>com.acme</groupId><artifactId>acme-plugin</artifactId></plugin>
  </plugins><extensions><extension><groupId>g5</groupId><artifactId>ext</artifactId></extension></extensions></build>
</project>
"""


def test_pom_reads_dependencies_plugins_extensions_and_parent() -> None:
    assert names(maven.pom_names, POM) == sorted(
        [
            "org.spring:parent",
            "g1:managed",
            "g2:direct",
            "${project.groupId}:sibling",
            "g4:a",
            "org.apache.maven.plugins:maven-compiler-plugin",
            "com.acme:acme-plugin",
            "g5:ext",
        ]
    )
    assert maven.pom_names("<project/>") == []


@pytest.mark.parametrize(
    "text",
    [
        '<!DOCTYPE project [<!ENTITY a "b">]><project/>',
        '<?xml version="1.0"?>\n<!doctype project><project/>',
        '<project><!ENTITY x "y"></project>',
        "<! DOCTYPE x><project/>",
    ],
)
def test_xml_declarations_are_refused_before_parsing(text: str) -> None:
    with pytest.raises(xmlsafe.RefusedError):
        xmlsafe.parse(text)
    with pytest.raises(xmlsafe.RefusedError):
        maven.pom_names(text)


def test_xml_that_is_malformed_is_a_parse_error_not_a_refusal() -> None:
    with pytest.raises(xmlsafe.ET.ParseError):
        xmlsafe.parse("<project><dependencies>")
    assert xmlsafe.local("{ns}tag") == "tag"
    assert xmlsafe.local("tag") == "tag"
    assert xmlsafe.parse('\ufeff<?xml version="1.0" encoding="UTF-16"?><a/>').tag == "a"


def test_dotnet_reads_package_references_and_packages_config() -> None:
    proj = (
        '<Project Sdk="Microsoft.NET.Sdk" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13" /><PackageReference Update="Other" />'
        '<PackageVersion Include="Central" Version="1" /><GlobalPackageReference Include="Analyzer" Version="1" />'
        '<DotNetCliToolReference Include="Tool" Version="1" /><Reference Include="System.Xml" /><package id="ignored" /></ItemGroup></Project>'
    )
    assert names(dotnet.dotnet_names, proj) == ["Analyzer", "Central", "Newtonsoft.Json", "Tool"]
    config = '<?xml version="1.0"?><packages><package id="Legacy.Pkg" version="1" /><package version="2" /></packages>'
    assert dotnet.dotnet_names(config) == ["Legacy.Pkg"]
    with pytest.raises(xmlsafe.RefusedError):
        dotnet.dotnet_names('<!DOCTYPE packages [<!ENTITY e "x">]><packages/>')


def test_gradle_reads_coordinates_and_versioned_plugins() -> None:
    text = """
plugins {
    id 'java'
    id("org.springframework.boot") version "3.2.0"
    id 'com.example.thing' version '1' apply false
    id("org.jetbrains.kotlin.jvm")
}
dependencies {
    implementation 'org.acme:lib:1.0'
    api("com.acme:api:2.0")
    testImplementation platform("org.junit:junit-bom:5.10")
    debugRuntimeOnly "com.acme:debug"
    classpath 'com.android.tools.build:gradle:8.0'
    kapt 'com.google.dagger:dagger-compiler:2.50'
    compile group: 'org.old', name: 'legacy', version: '1'
    runtimeOnly(group = "org.kts", name = "mapped")
    println "not:adependency"
    implementation libs.some.alias
}
"""
    assert names(gradle.gradle_names, text) == sorted(
        [
            "org.acme:lib",
            "com.acme:api",
            "org.junit:junit-bom",
            "com.acme:debug",
            "com.android.tools.build:gradle",
            "com.google.dagger:dagger-compiler",
            "org.old:legacy",
            "org.kts:mapped",
            "plugin:org.springframework.boot",
            "plugin:com.example.thing",
        ]
    )


def test_version_catalog() -> None:
    text = """
[versions]
x = "1"
[libraries]
short = "org.a:b:1.0"
bare = "justone"
mod = { module = "org.m:mod", version.ref = "x" }
parts = { group = "org.g", name = "n", version = "1" }
nothing = { version = "1" }
weird = 7
[plugins]
p1 = { id = "org.plug.one", version = "1" }
p2 = "org.plug.two:1.0"
p3 = 3
"""
    assert names(gradle.version_catalog_names, text) == sorted(
        ["org.a:b", "org.m:mod", "org.g:n", "plugin:org.plug.one", "plugin:org.plug.two"]
    )
    assert gradle.version_catalog_names("[versions]\nx = '1'\n") == []


def test_go_mod_reads_require_forms_and_replace_targets() -> None:
    text = """module example.com/app

go 1.22
toolchain go1.22.1

require example.com/single v1.0.0
require (
\texample.com/a v1.2.3 // indirect
\t"example.com/quoted" v1.0.0
\t// example.com/commented v1
\t
)
replace example.com/a => example.com/fork v1.0.0
replace example.com/b => ../local
replace example.com/c => /abs/local
replace example.com/d => C:\\local
replace (
\texample.com/e => example.com/e-fork v2.0.0
\texample.com/f => ./f
\texample.com/g
)
replace example.com/h =>
exclude example.com/x v1
require
"""
    assert names(golang.go_mod_names, text) == sorted(
        ["example.com/single", "example.com/a", "example.com/quoted", "example.com/fork", "example.com/e-fork"]
    )


def test_go_mod_block_with_only_a_comment_line_yields_nothing() -> None:
    assert golang.go_mod_names("require (\n\t\n)\nrequire ()\n") == []


def test_mix_reads_dependency_tuples_in_any_layout() -> None:
    text = """defmodule App.MixProject do
  def project do
    [app: :app, deps: deps()]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      # {:commented, "~> 1"},
      {:ecto_sql, github: "elixir-ecto/ecto_sql", only: :test},
      {:"quoted", "~> 1"}
    ]
  end

  defp helper, do: {:ok, 1}
end
"""
    assert names(elixir.mix_names, text) == ["ecto_sql", "phoenix"]
    assert elixir.mix_names('def deps do\n  [{:a, "1"}]\n') == ["a"]
    assert elixir.mix_names('defp deps, do: [{:b, "1"},\n {:c,\n  github: "x/y"}, {:ok, "s"}, {:error, "e"}]\n') == [
        "b",
        "c",
    ]
    assert elixir.mix_names('def project, do: [deps: [{:d, "~> 1", only: :dev}]] # {:e, "1"}\n') == ["d", "e"]


def test_pubspec_reads_dependency_keys_and_skips_sdk_entries() -> None:
    text = """name: app
dependencies:
  flutter:
    sdk: flutter
  http: ^1.0.0
  git_dep:
    git:
      url: https://example.com/g.git
  empty:
dev_dependencies:
  flutter_test:
    sdk: flutter
  lints: ^3.0.0
dependency_overrides:
  http: ^1.1.0
"""
    assert names(dart.pubspec_names, text) == ["empty", "git_dep", "http", "http", "lints"]
    assert dart.pubspec_names("name: app\n") == []
    with pytest.raises(dart.yamlpath.ParseError):
        dart.pubspec_names("dependencies:\n\t- tab\n")


def test_swift_reads_url_and_registry_packages() -> None:
    text = """// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "App", dependencies: [
    .package(url: "https://github.com/acme/Alpha.git", from: "1.0.0"),
    .package(name: "Beta", url: "git@github.com:acme/beta.git", .upToNextMajor(from: "2.0.0")),
    .package(
        url: "https://user:tok@gitlab.example.com/grp/gamma/",
        branch: "main"),
    .package(id: "scope.delta", from: "1.0.0"),
    .package(path: "../Local"),
])
"""
    assert names(swift.package_swift_names, text) == sorted(
        ["github.com/acme/Alpha", "github.com/acme/beta", "gitlab.example.com/grp/gamma", "scope.delta"]
    )
