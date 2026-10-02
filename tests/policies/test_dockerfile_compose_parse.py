"""dockerfile-compose-security: the Dockerfile reader (directives, continuations, comments, heredocs, exec form)."""

from __future__ import annotations

from policies import dockerkit

dockerkit.load()

from dkscan import dockerfile  # noqa: E402


def parse(text: str) -> list[dockerfile.Instr]:
    return dockerfile.parse(text)


def test_keywords_flags_and_args() -> None:
    (instr,) = parse("run --mount=type=cache,target=/c --network=none  echo hi\n")
    assert instr.keyword == "RUN"
    assert instr.flags == {"mount": "type=cache,target=/c", "network": "none"}
    assert instr.args == "echo hi"
    assert instr.line == 1


def test_repeated_flags_are_kept_together() -> None:
    (instr,) = parse("RUN --mount=type=bind,from=a --mount=type=bind,from=b true\n")
    assert instr.flags["mount"] == "type=bind,from=a type=bind,from=b"


def test_flag_without_value() -> None:
    (instr,) = parse("COPY --link a b\n")
    assert instr.flags == {"link": ""}


def test_continuation_joins_and_places_each_part() -> None:
    (instr,) = parse("RUN apt-get update \\\n  && apt-get install -y x\n")
    assert instr.text == "RUN apt-get update    && apt-get install -y x"
    assert instr.lines == (1, 2)
    assert instr.line_at(0) == 1
    assert instr.line_at(instr.text.index("&&")) == 2


def test_comment_and_blank_lines_inside_a_continuation_are_dropped() -> None:
    (instr,) = parse("RUN a \\\n# note\n\n  b\n")
    assert instr.text == "RUN a    b"
    assert instr.lines == (1, 4)


def test_escape_directive_switches_to_backtick() -> None:
    instrs = parse("# escape=`\nFROM a\nRUN a `\n  b\nRUN c \\\nRUN d\n")
    assert [i.text for i in instrs] == ["FROM a", "RUN a    b", "RUN c \\", "RUN d"]


def test_directives_end_at_the_first_other_line() -> None:
    assert dockerfile.escape_char(["# syntax=x", "", "# escape=`"]) == "\\"
    assert dockerfile.escape_char(["# escape=`", "# escape=\\"]) == "`"
    assert dockerfile.escape_char(["# escape=x"]) == "\\"
    assert dockerfile.escape_char(["FROM a"]) == "\\"


def test_comment_above_is_remembered_only_when_adjacent() -> None:
    a, b, c = parse("# one\nFROM a\n# two\n\nRUN b\nRUN c\n")
    assert a.above == "# one"
    assert b.above == ""
    assert c.above == ""


def test_run_heredoc_bodies_are_appended_line_by_line() -> None:
    (instr, after) = parse("RUN <<EOF\napt-get update\n# kept\nEOF\nUSER app\n")
    assert instr.text == "RUN <<EOF\napt-get update\n# kept"
    assert instr.lines == (1, 2, 3)
    assert after.keyword == "USER"
    assert after.line == 5


def test_heredoc_dash_quotes_and_several_bodies() -> None:
    (instr,) = parse("RUN <<-'A' bash && <<\"B\" sh\n\tone\n\tA\ntwo\nB\n")
    assert instr.text.endswith("\none\ntwo")


def test_here_string_is_not_a_heredoc() -> None:
    instrs = parse("RUN cat <<<word\nUSER app\n")
    assert [i.keyword for i in instrs] == ["RUN", "USER"]


def test_copy_heredoc_body_is_file_content_not_shell() -> None:
    (instr, after) = parse("COPY <<EOF /etc/app.conf\nkey=value\nEOF\nRUN x\n")
    assert instr.text == "COPY <<EOF /etc/app.conf"
    assert after.line == 4


def test_unterminated_heredoc_runs_to_the_end() -> None:
    (instr,) = parse("RUN <<EOF\na\nb\n")
    assert instr.text == "RUN <<EOF\na\nb\n"


def test_exec_form() -> None:
    (instr, bad, nonlist) = parse('CMD ["a", "b"]\nCMD [broken\nCMD [1]\n')
    assert instr.exec_form() == ["a", "b"]
    assert bad.exec_form() is None
    assert nonlist.exec_form() is None
    (shell,) = parse("CMD a b\n")
    assert shell.exec_form() is None


def test_crlf_and_lone_cr() -> None:
    assert [i.line for i in parse("FROM a\r\nRUN b\rUSER c\n")] == [1, 2, 3]


def test_a_line_that_is_no_instruction_is_skipped() -> None:
    assert [i.keyword for i in parse("  \n123 abc\nFROM a\n")] == ["FROM"]


def test_continuation_at_end_of_file() -> None:
    (instr,) = parse("RUN a \\")
    assert instr.text == "RUN a "


def test_heredoc_opens_only_at_an_unquoted_word_start() -> None:
    text = 'RUN echo "x<<EOF" && echo $((1<<BITS)) && a=b<<C\nFROM b\nUSER root\n'
    assert [i.keyword for i in parse(text)] == ["RUN", "FROM", "USER"]
    assert dockerfile.heredoc_words("cat 3<<'A' <<-B 'x<<C' \\<<D $((1<<E") == [(False, "A"), (True, "B")]
    assert dockerfile.heredoc_words('echo "a\\"<<X"') == []


def test_bom_is_dropped() -> None:
    (instr,) = parse("\ufeffFROM a\n")
    assert instr.keyword == "FROM"
