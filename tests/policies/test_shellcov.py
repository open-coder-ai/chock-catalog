"""The coverage reader itself: which lines are statements, and which bash reported."""

from __future__ import annotations

import subprocess
from pathlib import Path

from policies.shellcov import statements, tracing, uncovered

SCRIPT = """set -eu
# a comment
f() {
    local a=1
    echo one \\
        two
    case "$1" in
        x | y)
            echo xy ;;
        skip) ;;
        *) echo other
            ;;
    esac
    if [[ "$a" == 1 ]] &&
       [[ -n "$1" ]]; then
        v=$(printf '%s' "$1" |
            tr a b)
    else
        echo 'never # not a comment'
    fi
    arr=(
      p
      q
    )
    cat <<'X'
echo in a heredoc
X
    while read -r l; do echo "$l"; done <<< "zz"
    return 0
}
f x
"""


def test_statements_group_continued_lines_and_skip_syntax() -> None:
    assert statements(SCRIPT) == [
        (1,),
        (4,),
        (5, 6),
        (7,),
        (9,),
        (11,),
        (14, 15),
        (16, 17),
        (19,),
        (21, 22, 23, 24),
        (25, 26, 27),
        (28,),
        (29,),
        (31,),
    ]


def test_uncovered_names_what_bash_never_ran(tmp_path: Path) -> None:
    script = tmp_path / "s.sh"
    script.write_text(SCRIPT, encoding="utf-8")
    with tracing(tmp_path) as trace:
        subprocess.run(["bash", str(script)], check=True, capture_output=True)  # noqa: S607
    assert [s[0] for s in uncovered(script, trace)] == [11, 19]


def test_nothing_traced_means_everything_uncovered(tmp_path: Path) -> None:
    script = tmp_path / "s.sh"
    script.write_text("echo a\necho b\n", encoding="utf-8")
    assert uncovered(script, tmp_path / "absent.txt") == [(1,), (2,)]
