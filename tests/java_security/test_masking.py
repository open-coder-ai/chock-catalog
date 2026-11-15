"""The shared masking step: what no code runs through is blanked, and a rule's subject is kept."""

from __future__ import annotations

import pytest
from chock_security.decision import FileText
from chock_security.engine import evaluate
from chock_security.masking import mask
from java_security.conftest import ALL_DENY

JAVA = [
    ("a(); // b.c(d)\n", "a();          \n"),
    ("/** {@code x.y(z)} */ a();\n", "                      a();\n"),
    ('s = "Avoid: Cipher.getInstance(1)";\n', 's = "' + ' ' * 28 + '";\n'),
    ('s = "Do not call new XStream(1)";\n', 's = "' + ' ' * 26 + '";\n'),
    ('c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n', 'c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'),
    ('u = "jdbc:mysql://h/db?user=root";\n', 'u = "jdbc:mysql://h/db?user=root";\n'),
    ('q = "SELECT t.f(1) FROM t WHERE k = " + id;\n', 'q = "SELECT t.f(1) FROM t WHERE k = " + id;\n'),
    ('t = """\n  a.b(c)\n  """;\n', 't = """\n' + ' ' * 8 + '\n  """;\n'),
    ('t = """\n  select * from t where k = 1\n  """;\n', 't = """\n  select * from t where k = 1\n  """;\n'),
]


@pytest.mark.parametrize(("raw", "expected"), JAVA)
@pytest.mark.parametrize("path", ["A.java", "A.kt"])
def test_java_and_kotlin_blank_comments_and_literals_that_quote_code(path: str, raw: str, expected: str) -> None:
    assert mask(FileText(path, raw)).text == expected


@pytest.mark.parametrize("path", ["build.gradle", "build.gradle.kts"])
def test_gradle_blanks_comments_and_keeps_every_coordinate(path: str) -> None:
    raw = "// a:b:1\nimplementation 'a:b:2' // x\nimplementation(\"a.b:c:3\")\nu = \"http://h/p\"\n"
    expected = "        \nimplementation 'a:b:2'     \nimplementation(\"a.b:c:3\")\nu = \"http://h/p\"\n"
    assert mask(FileText(path, raw)).text == expected


def test_xml_blanks_a_comment_across_lines_and_keeps_the_newlines() -> None:
    raw = "<a><!-- x\n  ${y} --><b>${z}</b></a>\n"
    assert mask(FileText("pom.xml", raw)).text == "<a>      \n          <b>${z}</b></a>\n"


def test_properties_blank_a_hash_or_bang_line_only() -> None:
    raw = "# a=1\n  ! b=2\nc=3 # kept\n"
    assert mask(FileText("a.properties", raw)).text == "     \n       \nc=3 # kept\n"


@pytest.mark.parametrize("path", ["a.yml", "a.yaml"])
def test_yaml_blanks_a_comment_but_not_a_hash_in_a_value_or_quotes(path: str) -> None:
    raw = "# a: 1\nb: x # c\nd: \"y # z\"\ne: u#v\nf: '#' # g\n"
    expected = "      \nb: x    \nd: \"y # z\"\ne: u#v\nf: '#'    \n"
    assert mask(FileText(path, raw)).text == expected


def test_a_file_type_without_a_mask_is_read_as_written() -> None:
    markdown = FileText("CHANGELOG.md", "- `http.csrf().disable()` // x\n")
    assert mask(markdown) is markdown


def test_a_waiver_comment_still_waives_though_the_rules_never_see_it() -> None:
    waived = 'Cipher c = Cipher.getInstance("DES"); // chock: allow crypto-weak-cipher\n'
    assert [f.rule_id for f in evaluate([FileText("C.java", waived)], ALL_DENY)] == []
    bare = 'Cipher c = Cipher.getInstance("DES");\n'
    assert [f.rule_id for f in evaluate([FileText("C.java", bare)], ALL_DENY)] == ["crypto-weak-cipher"]
