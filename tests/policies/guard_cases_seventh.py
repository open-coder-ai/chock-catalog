"""protect-agent-config: commands of the seventh review round, each refused or allowed."""

from __future__ import annotations

F1_REFUSED = [
    "eval -- 'rm AGENTS.md'",
    "eval -- 'cp x .mcp.json'",
    "eval -- 'sed -i s/a/b/ AGENTS.md'",
    "builtin eval -- 'rm AGENTS.md'",
    "command eval -- 'rm AGENTS.md'",
    "bash -c -- 'rm AGENTS.md'",
    "sh -c -- 'rm AGENTS.md'",
    "bash -c -x 'rm AGENTS.md'",
    "bash -c -e -- 'rm AGENTS.md'",
    "bash -c +e 'rm AGENTS.md'",
    "bash -c -O extglob 'rm AGENTS.md'",
    "bash -c -o pipefail 'rm AGENTS.md'",
    "sh -c -xv \"echo x > $'\\x2e'mcp.json\"",
    "eval 'rm AGENTS.md'",
]

F1_ALLOWED = ["eval -- 'rm src/a.py'", "bash -c -- 'ls src'", "eval -- 'cat .mcp.json'", "bash -c -x 'ls src'"]

F2_REFUSED = [
    "eval \"echo x > $'\\x2e'mcp.json\"",
    "bash -c \"echo x > $'\\x2e'mcp.json\"",
    "sh -c \"echo x > $'\\x2e'mcp.json\"",
    "env sh -c \"echo x > $'\\x2e'mcp.json\"",
    "timeout 5 bash -c \"echo x > $'\\x2e'mcp.json\"",
    "nohup sh -c \"echo x > $'\\x2e'mcp.json\"",
    "xargs -0 sh -c \"echo x > $'\\x2e'mcp.json\"",
    "eval 'echo x > $'\\''\\x2e'\\''mcp.json'",
]

F2_ALLOWED = ["eval \"echo x > $'\\x41'.txt\"", "bash -c \"echo $'a\\tb' > notes.txt\""]

F3_REFUSED = [
    "x=$(mktemp); f(){ x=.mcp.json; }; f; echo z > $x",
    "x=$(mktemp); f(){ read x <<< .mcp.json; }; f; echo z > $x",
    "x=$(mktemp); f(){ local x=.mcp.json; echo z > $x; }; f",
    "x=$(mktemp); f(){ declare x=.mcp.json; echo z > $x; }; f",
    "x=1; f(){ x=.mcp.json; }; f; echo z > $x",
    'x=safe; f(){ read x <<< .mcp.json; }; f; rm "$x"',
    'x=safe; read x <<< .mcp.json; rm "$x"',
    'x=safe; for x in .mcp.json; do rm "$x"; done',
    'x=safe; printf -v x .mcp.json; rm "$x"',
    'x=safe; mapfile -t x <<< .mcp.json; rm "$x"',
    'x=safe; : ${x:=.mcp.json}; unset x; read x <<< .mcp.json; rm "$x"',
    'x=safe; declare -n r=x; r=.mcp.json; rm "$x"',
    'x=safe; { x=.mcp.json; }; rm "$x"',
]

F3_ALLOWED = [
    "x=a; x=b; echo hi > $x",
    "d=build; d=out; rm -rf $d/cache",
    "x=safe; read y <<< .mcp.json; echo hi > $x",
    "{ echo hi; } > out.txt",
    "x=$(mktemp); f(){ echo hi; }; f; echo z > $x",
    "f(){ echo hi; }; f > out.txt",
]

F4A_REFUSED = [
    "x=$(mktemp); y=$x; read y <<< .mcp.json; echo z > $y",
    "x=$(mktemp); y=$x; printf -v y .mcp.json; echo z > $y",
    "x=$(mktemp); y=$x; for y in .mcp.json; do echo z > $y; done",
    'x=$(mktemp); y=$x; (( y = 1 )); echo z > "$y"',
    'x=$(mktemp); y="$x"; read y <<< .mcp.json; echo z > "$y"',
]

F4A_ALLOWED = ["x=$(mktemp); y=$x; echo z > $y"]

F4B_REFUSED = [
    "x=$(mktemp); declare -n r; r=x; r=.mcp.json; echo z > $x",
    "x=$(mktemp); typeset -n r; r=x; r=.mcp.json; echo z > $x",
    "x=$(mktemp); local -n r; r=x; r=.mcp.json; echo z > $x",
    "x=$(mktemp); declare -n r; r=x; read r <<< .mcp.json; echo z > $x",
    "x=$(mktemp); declare -n r; r=x; for r in .mcp.json; do :; done; echo z > $x",
    "x=$(mktemp); declare -n r; r=x; printf -v r .mcp.json; echo z > $x",
    "x=$(mktemp); declare -n r; r=x; declare r=.mcp.json; echo z > $x",
    "x=$(mktemp); declare -n a; declare -n b; a=b; b=x; a=.mcp.json; echo z > $x",
    "x=$(mktemp); n=x; declare -n r; r=$n; r=.mcp.json; echo z > $x",
    "x=$(mktemp); r=x; declare -n r; r=.mcp.json; echo z > $x",
    "x=$(mktemp); declare -n r=y; y=x; r=.mcp.json; echo z > $x",
]

F4B_ALLOWED = ["x=$(mktemp); declare -n r; r=other; echo z > $x"]

F5_REFUSED = [
    "x=(.mcp.json); echo z > $x",
    "a=(AGENTS.md); echo z > $a",
    "declare a=(AGENTS.md); echo z > $a",
    "declare -a a=(AGENTS.md); echo z > $a",
    "local a=(AGENTS.md); echo z > $a",
    "a=([0]=AGENTS.md); echo z > $a",
    "f=(AGENTS.md); truncate -s0 $f",
    "x=(.mcp.json); cp a $x",
    "x=(.mcp.json); mv a $x",
    "x=(.mcp.json); sed -i s/a/b/ $x",
    "x=(.mcp.json); echo z | tee $x",
    "x=(.mcp.json); : > $x",
    "x=(.mcp.json); > $x",
    "x=(.mcp.json); echo z >> $x",
    'x=(.mcp.json); echo z > "$x"',
    "a=(.claude); echo z > $a/settings.json",
    "a=(.claude); cd $a; echo z > settings.json",
    "f=(AGENTS.md); touch $f",
    "f=(AGENTS.md); chmod 0 $f",
    "f=(AGENTS.md); ln -sf x $f",
    "f=(AGENTS.md); echo z | dd of=$f",
    'x=.mc; x+=p.json; rm "$x"',
    'x=.mc; x+="p.json"; rm "$x"',
    'x=.mcp; x+=.json; rm "$x"',
    'x=safe; x+=.mcp.json; rm "$x"',
    'x=safe; x[0]=.mcp.json; rm "$x"',
    "x=(a); x+=(.mcp.json); echo z > $x",
]

F5_ALLOWED = [
    'x=(a b c); for f in "${x[@]}"; do echo $f; done',
    "files=(a.txt b.txt); echo ${#files[@]}",
    "x=src; x+=/a.py; echo hi > out.txt",
]

F6_REFUSED = [
    "git config alias.x 'ls-remote --u=sh origin'",
    "git config alias.x 'ls-remote --up=sh origin'",
    "git config alias.x 'archive --e=sh --remote=origin HEAD'",
    "git config alias.x 'push --e=sh origin'",
    "git config alias.x 'clone --u=sh origin d'",
    "git config alias.x 'clone --up=sh origin d'",
    "git config alias.x 'clone --co=core.fsmonitor=sh origin d'",
    "git config alias.x 'clone --te=tpl origin d'",
    "git config alias.x 'init --t=tpl d'",
    "git config alias.x 'init --te=tpl d'",
    "git config alias.x 'ls-remote \"--upload-pack=sh\" origin'",
]

F6_ALLOWED = [
    "git config alias.x 'fetch --unshallow'",
    "git config alias.x 'push --force-with-lease'",
    "git config alias.x 'clone --depth 1 --recurse-submodules'",
    "git config alias.x 'pull --rebase --autostash'",
]

F10_REFUSED = [
    'git config alias.x "log --format=%h --output=.mcp.json"',
    "git config alias.x \"log --format='%h' --exec=sh\"",
    'git config alias.x "log --pretty=format:%h* *"',
]

F10_ALLOWED = [
    "git config alias.hist \"log --pretty=format:'%h %ad | %s%d [%an]' --graph --date=short\"",
    "git config alias.f 'log --format=\"%h [%an]\"'",
    "git config alias.tree 'log --graph --format=%h*'",
    'git config alias.recent "for-each-ref --sort=-committerdate refs/heads/"',
    'git config alias.lt "ls-tree -r HEAD"',
    'git config alias.sr "show-ref --heads"',
    "git config alias.fe \"for-each-ref --format='%(refname:short) [%(objectname:short)]'\"",
]

F13_REFUSED = ["git co -- A*.md", "cd .claude && git co -- settings.json", "git co AGENTS.md"]

F13_ALLOWED = ["git st", "git co $branch", "echo AGENTS.md > notes.txt; git st"]

F7_REFUSED = [
    "echo 'echo x > AGENTS.md' | tclsh",
    "tclsh <<< 'exec rm AGENTS.md'",
    'Rscript -e \'writeLines("x","AGENTS.md")\'',
    'julia -e \'write("AGENTS.md","x")\'',
    'groovy -e \'new File("AGENTS.md").text="x"\'',
    "osascript -e 'do shell script \"rm AGENTS.md\"'",
    "echo '.shell rm AGENTS.md' | sqlite3",
    "echo 'shell rm AGENTS.md' | gdb",
    "gdb -batch -ex 'shell rm AGENTS.md' prog",
    "chronic sh -c 'rm AGENTS.md'",
    "tsp sh -c 'rm AGENTS.md'",
    "tsp -L job sh -c 'rm AGENTS.md'",
    'pypy3 -c "$x" .mcp.json',
    'pypy3 -c \'open(".mcp.json","w")\'',
]

F7_ALLOWED = [
    "Rscript -e 'print(1)'",
    "julia -e 'println(1)'",
    "echo select 1 | sqlite3 db.sqlite",
    "sqlite3 db.sqlite 'select 1'",
    "gdb -batch -ex bt prog",
    "chronic make test",
    "tsp make",
    "tclsh script.tcl",
    "osascript -e 'beep'",
    "pypy3 -c 'print(1)'",
]

GIT_REFUSED = [
    "git rebase -x 'rm AGENTS.md' HEAD~1",
    'git rebase -i --exec "echo x > .mcp.json" HEAD~1',
    "git rebase --exec='rm AGENTS.md' HEAD~1",
    "git rebase -ix 'rm AGENTS.md' HEAD~1",
    "git rebase -x'rm AGENTS.md' HEAD~1",
    "git bisect run rm AGENTS.md",
    "git filter-branch --tree-filter 'rm AGENTS.md' HEAD",
    "git filter-branch --msg-filter 'cat > .mcp.json' HEAD",
    "git submodule foreach 'rm AGENTS.md'",
    "git submodule foreach --recursive 'rm AGENTS.md'",
    "git difftool -x 'rm AGENTS.md'",
    "git difftool --extcmd='rm AGENTS.md'",
    "GIT_EDITOR='rm AGENTS.md' git commit",
    "GIT_PAGER='tee .mcp.json' git log",
    "GIT_SEQUENCE_EDITOR='rm AGENTS.md' git rebase -i HEAD~2",
    "git log --output=AGENTS.md",
    "git diff --output=AGENTS.md",
    "git diff --output AGENTS.md",
    "git show --output=.mcp.json HEAD",
    "git log --outp=AGENTS.md",
    "git format-patch -o .claude HEAD~1",
    "git format-patch --output-directory .claude HEAD~1",
    "git format-patch -o.claude HEAD~1",
    "cd .claude && git log --output=settings.json",
    "x=AGENTS.md; git log --output=$x",
]

GIT_ALLOWED = [
    "git rebase -x 'make test' HEAD~3",
    "git rebase -i HEAD~3",
    "git rebase --exec 'npm test' main",
    "git bisect run make test",
    "git bisect start",
    "git filter-branch --tree-filter 'rm secrets.txt' HEAD",
    "git submodule foreach 'git pull'",
    "git submodule update --init",
    "git difftool -x vimdiff",
    "GIT_EDITOR=true git commit",
    "GIT_EDITOR=: git rebase -i HEAD~2",
    "PAGER=cat git log",
    "GIT_SSH_COMMAND='ssh -i key' git fetch",
    "EDITOR=$(which vim) git commit",
    "git log --output=out.txt",
    "git diff --output=changes.patch",
    "git format-patch -o patches HEAD~1",
    "git log --oneline -5",
    "git diff --stat",
    "git rebase -x 'echo $x' HEAD",
]

WIN_REFUSED = [
    "echo x > .claude.\\settings.json",
    'echo x > ".claude \\settings.json"',
    'robocopy build "C:\\Users\\me\\repo " /MIR',
    "robocopy build C:\\Users\\me\\repo. /MIR",
    "robocopy build C:\\Users\\me\\repo.\\ /MIR",
    "robocopy build \\\\?\\C:\\Users\\me\\repo /MIR",
    "robocopy build \\\\.\\C:\\Users\\me\\repo /MIR",
    "echo x > \\\\?\\C:\\Users\\me\\repo\\AGENTS.md",
    "mklink AGENTS.md x",
    "mklink /d .claude x",
    "attrib -r AGENTS.md",
    "icacls AGENTS.md /deny Everyone:W",
]

WIN_ALLOWED = [
    "echo x > src\\a.py",
    "attrib +h src\\a.py",
    "mklink link.txt target.txt",
    "icacls src /grant Everyone:R",
    "robocopy build out /MIR",
    'echo x > "src. \\a.py"',
    "git checkout HEAD~1",
]
