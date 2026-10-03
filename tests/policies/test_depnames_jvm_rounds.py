"""verify-dependency-exists: the JVM, .NET, Go, Elixir, Dart and Swift readers return the names they should, and only those."""

from __future__ import annotations

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


def test_review_round_forms() -> None:
    text = """
jar { exclude '**/*.class' }
dependencies {
    developmentOnly(
        "org.a:b:1")
    implementation "g.x:y:1", "g.x:evil:2"
    implementation(
        "evilpkg:evilpkg")
    api 'junit:junit:4.13'
    compile(name: "n", group: "org.g")
    libs = [name: 'lib', version: '1', group: 'com.evil']
    println("http://host:8080/x")
    jar { manifest { attributes 'Implementation-Title': 'my.app:thing' }}
    url = "my.host.com:8080"
}
plugins { kotlin("jvm") version "1.9" }
/* implementation "o.c:out:1"
   more */
"""
    assert names(gradle.gradle_names, text) == sorted(
        ["org.a:b", "g.x:y", "g.x:evil", "evilpkg:evilpkg", "junit:junit", "org.g:n", "com.evil:lib", "o.c:out",
         "plugin:org.jetbrains.kotlin.jvm"]
    )  # fmt: skip
    # a glob in a string must not open a comment that hides the code after it
    assert names(
        swift.package_swift_names,
        'let g = "**/*.md"\n.package(url: "https://github.com/e/e.git", from: "1.0.0")\n/* x */\n',
    ) == ["github.com/e/e"]
    assert names(
        dotnet.dotnet_names,
        '<Project><ItemGroup><PackageReference Include="A;B" /><PackageDownload Include="C" /></ItemGroup></Project>',
    ) == ["A", "B", "C"]
    local = '{:a, in_umbrella: true}, {:l, path: "../l"}, {:g, github: "x/y", path: "p"}, {:h, "~> 1", path: "q"}, {:n, "~> 1"}'
    assert names(elixir.mix_names, local) == ["g", "h", "n"]


def test_third_round_forms() -> None:
    odd = "implementation 'evil:pkg:Hoxton.SR1'\nimplementation(\"evil:two:latest.release\")\nimplementation 'evil:three:v1'\n"
    assert names(gradle.gradle_names, odd) == ["evil:pkg", "evil:three", "evil:two"]
    wrapped = "implementation(platform(\"evil:bom\"))\nimplementation platform('evil:bom2')\ntestFixturesApi 'evil:api'\nlintChecks 'evil:lint:1.0'\n"
    assert names(gradle.gradle_names, wrapped) == ["evil:api", "evil:bom", "evil:bom2", "evil:lint"]
    assert names(gradle.gradle_names, "/*\n// */ implementation 'evil:pkg:1'\n") == ["evil:pkg"]
    assert names(swift.package_swift_names, '/*\n// */ .package(url: "https://github.com/evil/pkg", from: "1")\n') == [
        "github.com/evil/pkg"
    ]
    assert names(elixir.mix_names, 'description: "A # B", deps: [{:evil, "~> 1"}]\n# {:gone, "1"}\n') == ["evil"]
