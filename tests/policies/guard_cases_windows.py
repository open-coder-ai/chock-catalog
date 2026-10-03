"""protect-agent-config: Windows copy tools and a trailing backslash (fourth review round), each refused or allowed."""

from __future__ import annotations

WINDOWS_REFUSED = [
    "robocopy src . /MIR",
    "robocopy src . /PURGE",
    "robocopy src .\\ /MIR",
    "robocopy src ./ /MIR",
    "robocopy src .. /MIR",
    "robocopy src ..\\.. /E",
    'robocopy src "%CD%" /MIR',
    'robocopy src "%cd%\\" /E',
    "robocopy src $PWD /MIR",
    "robocopy src . /E",
    "robocopy src .\\ /E",
    "robocopy src .",
    "robocopy src . .mcp.json",
    "robocopy src . /XD build /E",
    "robocopy src .cursor /XD x",
    "robocopy src .cursor /XF *.tmp /E",
    "robocopy src .claude /XD a b c /E",
    "robocopy src .git/hooks /IF x y",
    "robocopy src .git\\hooks /MIR",
    "xcopy src . /e",
    "xcopy src\\* . /y",
    "xcopy src .\\ /s",
    "xcopy a.txt .cursor\\",
    "xcopy a.txt .cursor\\ /y",
    "xcopy .mcp.json out\\",
    "cd .cursor && xcopy src . /e",
    "cmd /c robocopy src . /MIR",
]

WINDOWS_ALLOWED = [
    "robocopy src build /XD x /E",
    "robocopy src build /XF *.tmp /E /R:3 /W:5 /LEV:2",
    "robocopy src build /MIR",
    "robocopy src build /XD .cursor .claude /E",
    "robocopy src build /XF .mcp.json /E",
    "robocopy src build /IF a.txt",
    "robocopy src build\\ /E /A-:R /MT:8",
    "robocopy src ..\\sibling /E",
    "robocopy src . x.txt",
    "xcopy a.txt .",
    "xcopy /y a.txt build\\",
    "xcopy /s /e /y src\\* build\\",
    "xcopy a.txt src\\ /y",
    "copy a.txt build\\",
    "move build\\a.txt dist\\",
    "del build\\",
    "rd build\\",
    "echo hi > build\\",
    "cmd /c xcopy /y a.txt build\\",
]

TRAILING_REFUSED = [
    "rd .cursor\\",
    "rmdir .claude\\",
    "del .mcp.json\\",
    "copy a.txt .claude\\settings.json\\",
    "echo x > .mcp.json\\",
]
