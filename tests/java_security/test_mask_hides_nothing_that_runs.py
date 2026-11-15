"""The mask hides nothing that runs or resolves: text a compiler or a build reads stays visible to the rules."""

from __future__ import annotations

from chock_security.decision import FileText
from chock_security.masking import mask
from java_security.conftest import GateRun

BLOCKED = 1

KOTLIN_TEMPLATE = (
    'package app\nimport javax.crypto.Cipher\nfun f(): String = "${Cipher.getInstance("DES").algorithm}"\n'
)

POM_HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
    "  <modelVersion>4.0.0</modelVersion>\n"
    "  <groupId>com.acme</groupId>\n"
    "  <artifactId>orders</artifactId>\n"
    "  <version>1.4.0</version>\n"
)

VULNERABLE_DEPENDENCY = (
    "  <dependencies>\n"
    "    <dependency>\n"
    "      <groupId>org.apache.logging.log4j</groupId>\n"
    "      <artifactId>log4j-core</artifactId>\n"
    "      <version>2.14.1</version>\n"
    "    </dependency>\n"
    "  </dependencies>\n"
)

CDATA_OPENS_A_COMMENT = (
    POM_HEAD
    + "  <description><![CDATA[ <!-- ]]></description>\n"
    + VULNERABLE_DEPENDENCY
    + "  <name><![CDATA[ --> ]]></name>\n</project>\n"
)

COMMENT_HOLDING_CDATA_TEXT = (
    POM_HEAD + "  <!-- was: <![CDATA[ x\n" + VULNERABLE_DEPENDENCY + "  -->\n  <name>orders</name>\n</project>\n"
)


PI_OPENS_A_COMMENT = POM_HEAD + "  <?note <!-- ?>\n" + VULNERABLE_DEPENDENCY + "  <?note --> ?>\n</project>\n"

COMMENT_HOLDING_PI_TEXT = (
    POM_HEAD + "  <!-- was: <?note x\n" + VULNERABLE_DEPENDENCY + "  -->\n  <name>orders</name>\n</project>\n"
)


def test_a_comment_opener_inside_a_processing_instruction_is_text_and_hides_no_dependency(gate: GateRun) -> None:
    code, stderr = gate({"pom.xml": PI_OPENS_A_COMMENT})
    assert code == BLOCKED
    assert "build-vulnerable-dependency" in stderr


def test_a_real_comment_that_mentions_a_processing_instruction_is_still_blanked(gate: GateRun) -> None:
    code, stderr = gate({"pom.xml": COMMENT_HOLDING_PI_TEXT})
    assert code == 0, stderr


def test_the_processing_instruction_itself_is_kept_whole() -> None:
    raw = "<a><?x <!-- ?><!-- y --></a>\n"
    assert mask(FileText("a.xml", raw)).text == "<a><?x <!-- ?>" + " " * 10 + "</a>\n"


def test_a_kotlin_string_template_runs_its_code(gate: GateRun) -> None:
    code, stderr = gate({"src/main/kotlin/app/F.kt": KOTLIN_TEMPLATE})
    assert code == BLOCKED
    assert "crypto-weak-cipher" in stderr


def test_a_comment_opener_inside_cdata_is_text_and_hides_no_dependency(gate: GateRun) -> None:
    code, stderr = gate({"pom.xml": CDATA_OPENS_A_COMMENT})
    assert code == BLOCKED
    assert "build-vulnerable-dependency" in stderr


def test_a_real_comment_that_mentions_cdata_is_still_blanked(gate: GateRun) -> None:
    code, stderr = gate({"pom.xml": COMMENT_HOLDING_CDATA_TEXT})
    assert code == 0, stderr


def test_only_kotlin_runs_a_dollar_template() -> None:
    raw = 's = "Avoid ${x.y(1)}";\n'
    assert mask(FileText("A.kt", raw)).text == raw
    assert mask(FileText("A.java", raw)).text == 's = "' + " " * 15 + '";\n'


def test_the_cdata_section_itself_is_kept_whole() -> None:
    raw = "<a><![CDATA[ <!-- x ]]><!-- y --></a>\n"
    assert mask(FileText("a.xml", raw)).text == "<a><![CDATA[ <!-- x ]]>" + " " * 10 + "</a>\n"
