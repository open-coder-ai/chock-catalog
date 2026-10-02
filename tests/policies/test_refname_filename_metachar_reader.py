"""refname-filename-metachar: how the guard's shell reader agrees with bash on quoting, heredocs and substitutions."""

from __future__ import annotations

import pytest
from policies import guardkit

POLICY = "refname-filename-metachar"
guard = guardkit.load_guard(POLICY)
BLOCK, OK = 1, 0

CASES = [
    # Review round 3: here-strings, heredocs inside substitutions, ${...} operators, deep eval, case in $( ).
    ("cat <<< x\ntouch $'a\\x3bb'", BLOCK),
    ("tr a b <<<'x'\ngit checkout -b \"feat/${TICKET}\"", OK),
    ("cat <<E\"O\"F > a.txt\nit's\nEOF\ntouch 'a;b'", BLOCK),
    ("git commit -m \"$(cat <<'EOF'\nfix: it's fine\nEOF\n)\" && touch 'a;b'", BLOCK),
    ("git commit -m \"$(cat <<'EOF'\nfix: don't crash when count > 0.\nEOF\n)\"", OK),
    ("echo $(ls # it's a comment\n) > out.txt", OK),
    ('mv "$f" "${f// /_}"', OK),
    ('mkdir -p "${DIR:-./build}"', OK),
    ('touch "${x:-a|b}"', OK),
    ("touch \"${x:-$(touch 'a;b')}\"", BLOCK),
    ("echo ${#arr[@]} ${a:-{b}} > n.txt", OK),
    ("eval eval eval eval eval touch foo.", BLOCK),
    ("eval " * 60 + "touch ok", BLOCK),
    ("eval " * 15000, BLOCK),
    ("echo $(case $x in a) touch 'a;b';; esac)", BLOCK),
    ("echo $(case $x in a) echo ok;; esac) > out.txt", OK),
    ("echo " + " ".join(f"$(date +%s{i})" for i in range(65)), OK),
    ('echo "' + "'x'" * 3000, BLOCK),
    ("touch ${unterminated", BLOCK),
    # Review round 4: ${...} closes at the first brace and holds no comment or heredoc; case only as a command.
    ("touch ${a:- #} 'x;y'", BLOCK),
    ("touch ${a:-<<EOF} 'x;y'", BLOCK),
    ("touch ${a:-{}'x;y'}", BLOCK),
    ("touch $(echo case) 'x;y'", BLOCK),
    ("touch <(echo esac) 'x;y'", BLOCK),
    ("echo $(if true; then case $x in (a) echo ok;; esac; fi) > out.txt", OK),
    ('echo "${a#*#}" "${y:-\'}\'}" > out.txt', OK),
    ("cat" + "<<a" * 300 + "\n" + "a\n" * 300, BLOCK),
    # Scanner review against bash's grammar: comments after metacharacters, arithmetic, heredocs, time, backticks.
    ("(:)#'\ntouch $'a\\x3bb'\n", BLOCK),
    ("((x<<1))\necho \"'\"\ntouch $'a\\x3bb'", BLOCK),
    ("echo $(( $(touch 'a;b') + 1 ))", BLOCK),
    ("echo $((a>-1)) > n.txt", OK),
    ("(( count > max )) && echo ok", OK),
    ("cat $(cat <<EOF)\n'\nEOF\ntouch $'a\\x3bb'", BLOCK),
    ("cat <<EOF\nEOF\r\n'\nEOF\ntouch $'a\\x3bb'", BLOCK),
    ("echo $(time -p case a in *) touch 'a;b';; esac)", BLOCK),
    ("echo $(case x in esac) > out.txt", OK),
    ("echo $(x;" + " " * 80 + "case a in *) touch 'a;b';; esac)", BLOCK),
    ("echo $(echo" + " " * 80 + "case) > x.txt", OK),
    ("echo `echo \\`touch 'a;b'\\``", BLOCK),
    ("echo `touch \\$'a\\x3bb'`", BLOCK),
    ("cat <<EOF\n$(touch 'a;b')\n\\$(not) `touch 'c;d'`\nEOF", BLOCK),
    ("cat <<'EOF'\n$(touch 'a;b')\nEOF", OK),
    # Scanner review, second pass: arithmetic needs `))`, CRLF delimiters, heredoc order, case-in, quoted backticks.
    ("((cd x); touch 'a;b')", BLOCK),
    ("echo $((cd x); touch 'a;b')", BLOCK),
    ("echo $(( (1)+(2) )) > n.txt", OK),
    ("cat <<EOF\r\nx\r\nEOF\r\ngit branch 'a;b'\r\n", BLOCK),
    ("cat <<A; x=$(cat <<B)\nB\nA\ntouch 'a;b'", BLOCK),
    ("echo $(case x in a) echo in esac;; b) touch 'a;b';; esac)", BLOCK),
    ("echo $(time" + " " * 70 + "-p case x in a) touch 'a;b';; esac)", BLOCK),
    ("git update-ref --stdin <<'EOF'\ncreate refs/heads/'a;b' HEAD\nEOF", BLOCK),
    ("git update-ref --stdin <<'EOF'\ncreate refs/heads/feature HEAD\nEOF", OK),
    ('touch $(pwd)#"${HOME}"', OK),
    ('echo "`git branch \\"a;b\\"`"', BLOCK),
    ("cat <<EOF > notes.md\nVersion: $(git describe)\nDate: `date`\nEOF", OK),
    ("Set-Content 'C:/work/notes.txt' 'a;b'", OK),
    # Verification of 1dfe060: case after a newline, quoted case words, arithmetic only when `(` closes into `))`.
    ("\"$(\ncase y in a) git branch 'a;b' ;; esac)\"", BLOCK),
    ("x=$(case y in\nesac); git branch ok", OK),
    ('x=$(case "a b" in esac); git branch ok', OK),
    ("x=$((true)&&(git branch 'a;b'))", BLOCK),
    ("((true)&&(git branch 'a;b'))", BLOCK),
    ("((x=1))# it's\ngit branch 'a;b'", BLOCK),
    ("echo $(( (1)+((2)) )) $(( (a) )) > n.txt", OK),
    ("echo $((x) ) > n.txt", OK),
]


@pytest.mark.parametrize(("command", "want"), CASES, ids=[c[:80] for c, _ in CASES])
def test_the_reader_verdict(command: str, want: int, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CHOCK_RAW_COMMAND", command)
        patch.setenv("CHOCK_TOOL", "bash")
        code = guard.run(command.split())
    err = capsys.readouterr().err
    assert code == want, err
    assert err.startswith("BLOCKED: ") if want else err == ""
