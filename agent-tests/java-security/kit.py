#!/usr/bin/env python3
"""Run the java-security scenarios against a real coding agent, and grade what it left behind.

    python kit.py setup --dir ~/shop-claude --agent claude --route repo   # one workspace per agent
    python kit.py list --tier smoke
    python kit.py start <scenario-id>                        # prints the prompt to paste
    python kit.py record <scenario-id> --gate refused         # after the agent's turn
    python kit.py report --dir ~/shop-claude --dir ~/shop-copilot   # a scenario x agent matrix

The agent is the thing under test, so nothing here drives it: you paste each prompt into a new
chat and say what the client showed. What the kit decides for itself is what is on disk -- the
shipped engine reads every file the turn changed -- and, on the repo route, what the commit gate
answers, because `record` makes the commit the way you would.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from grading import cell, findings, grade

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parents[1]
FIXTURE = HERE / "fixture"
SCENARIOS = HERE / "scenarios"
DEFAULT_ENGINE = CATALOG / "base" / "java-security" / "implementations"
STATE = "agent-tests.json"
RESULTS = "agent-tests-results.jsonl"
BASELINE = "agent-tests-baseline"
SCENARIO_BASE = "agent-tests-scenario"
TIERS = ("smoke", "packs", "full")
GATE_SEEN = ("refused", "silent", "unseen")
AGENTS = ("claude", "copilot", "cursor", "codex", "devin")
#: What an agent, an IDE or a build keeps beside the code: never the turn's work, and never wiped
#: between scenarios -- a permission granted in .claude/settings.local.json must outlive a reset,
#: or every scenario re-asks it and the runs stop being comparable.
LOCAL_ONLY = (
    ".claude/settings.local.json",
    ".vscode/",
    ".idea/",
    "*.iml",
    "target/",
    "build/",
    ".gradle/",
    "out/",
    ".DS_Store",
)
#: How much of the commit hook's answer is kept: enough to name every rule it refused.
COMMIT_OUTPUT = 4000


def git(workspace: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """git with paths printed as they are: unquoted, UTF-8, whatever the machine's settings."""
    argv = ["git", "-c", "core.quotePath=false", *args]
    return subprocess.run(argv, cwd=workspace, capture_output=True, text=True, encoding="utf-8", check=check)


def load_scenarios() -> list[dict]:
    try:
        import yaml  # noqa: PLC0415 -- the kit's one dependency, named when it is missing
    except ImportError:
        sys.exit("kit.py needs PyYAML: pip install pyyaml")
    scenarios: list[dict] = []
    for path in sorted(SCENARIOS.glob("*.yaml")):
        scenarios += yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return scenarios


def scenario(scenario_id: str) -> dict:
    found = [s for s in load_scenarios() if s["id"] == scenario_id]
    if not found:
        sys.exit(f"no scenario {scenario_id!r}; `python kit.py list` shows them")
    return found[0]


def in_tier(item: dict, tier: str) -> bool:
    """Tiers nest: a smoke scenario runs in every tier, a packs scenario in packs and full."""
    return TIERS.index(item.get("tier", "full")) <= TIERS.index(tier)


# ── The workspace: a git repository the agent works in, and the state the kit keeps in .git ──
def state_path(workspace: Path) -> Path:
    return workspace / ".git" / STATE


def write_state(workspace: Path, state: dict) -> None:
    state_path(workspace).write_text(json.dumps(state, indent=2), encoding="utf-8", newline="\n")


def read_state(workspace: Path) -> dict:
    path = state_path(workspace)
    if not path.is_file():
        sys.exit(f"{workspace} is not a kit workspace; run `python kit.py setup --dir {workspace}` first")
    return json.loads(path.read_text(encoding="utf-8"))


def install_repo_route(workspace: Path, agent: str) -> None:
    """chock in the repository: the ambient rule, the agent's own hooks where it has them, and the
    gate at every commit -- whatever `chock sync` wires for this agent, which it prints."""
    if shutil.which("chock") is None:
        sys.exit("the repo route needs chock on PATH: pip install chock")
    subprocess.run(["chock", "init", ".", "--agents", agent], cwd=workspace, check=True)
    policies = workspace / ".agents" / "policies"
    shutil.copytree(CATALOG / "base" / "java-security", policies / "java-security", dirs_exist_ok=True)
    subprocess.run(["chock", "sync", "--repo", ".", "--agents", agent], cwd=workspace, check=True)


def setup(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).expanduser().resolve()
    if workspace.exists() and any(workspace.iterdir()):
        sys.exit(f"{workspace} is not empty; pick a new directory")
    shutil.copytree(FIXTURE, workspace, dirs_exist_ok=True)
    git(workspace, "init", "-q", "--initial-branch=main")
    git(workspace, "config", "user.email", "agent-tests@chock.invalid")
    git(workspace, "config", "user.name", "agent-tests")
    exclude = workspace / ".git" / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    exclude.write_text("\n".join(LOCAL_ONLY) + "\n", encoding="utf-8", newline="\n")
    if args.route == "repo":
        install_repo_route(workspace, args.agent)
    git(workspace, "add", "-A")
    git(workspace, "commit", "-q", "--no-verify", "-m", "baseline: acme-shop")
    git(workspace, "tag", "-f", BASELINE)
    engine = Path(args.engine).expanduser().resolve() if args.engine else DEFAULT_ENGINE
    state = {"agent": args.agent, "route": args.route, "engine": str(engine), "created": _now()}
    write_state(workspace, state)
    print(
        f"workspace ready: {workspace} ({args.agent}, {args.route} route). Open it in {args.agent}, then `kit.py start <id>`."
    )


def start(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).expanduser().resolve()
    state = read_state(workspace)
    item = scenario(args.id)
    git(workspace, "reset", "-q", "--hard", BASELINE)
    git(workspace, "clean", "-q", "-fd")  # ignored files stay: the gate log, the agent's own settings
    seeded = dict(item.get("files") or {})
    if item.get("selection") is not None:
        seeded[".chock/security.json"] = json.dumps(item["selection"], indent=2) + "\n"
    for rel, text in seeded.items():
        (workspace / rel).parent.mkdir(parents=True, exist_ok=True)
        (workspace / rel).write_text(text, encoding="utf-8", newline="\n")
    git(workspace, "add", "-A")
    git(workspace, "commit", "-q", "--no-verify", "--allow-empty", "-m", f"scenario {item['id']}: starting state")
    git(workspace, "tag", "-f", SCENARIO_BASE)
    write_state(workspace, state | {"started": item["id"]})
    print(f"== {item['id']} ({item['kind']}, pack {item['pack']}) ==\n{item['title']}\n")
    print("Start a NEW chat in the agent, paste this, and let the turn finish:\n")
    print(item["prompt"].strip())
    print(f'\nThen: python kit.py record {item["id"]} --dir "{workspace}" --gate refused|silent|unseen')


# ── Grading: the engine reads what changed; the tester says what the client showed ──────────
def changed_files(workspace: Path) -> list[str]:
    """Every file the turn added or changed, NUL-separated so a space or an accent in a path survives."""
    tracked = git(workspace, "diff", "-z", "--name-only", "--diff-filter=ACMR", SCENARIO_BASE).stdout.split("\0")
    untracked = git(workspace, "ls-files", "-z", "--others", "--exclude-standard").stdout.split("\0")
    return sorted({p for p in tracked + untracked if p and not p.startswith((".chock/", ".agents/"))})


def commit_gate(workspace: Path) -> dict | None:
    """Commit the turn's work as a developer would; the pre-commit hook answers or it does not.

    None when there is nothing to commit -- the agent committed it already, and its own commit
    went through the same hook -- so git's "nothing to commit" is never read as a refusal.
    """
    git(workspace, "add", "-A")
    if git(workspace, "diff", "--cached", "--quiet", check=False).returncode == 0:
        return None
    done = git(workspace, "commit", "-q", "-m", "agent turn", check=False)
    return {"refused": done.returncode != 0, "output": (done.stderr or done.stdout).strip()[-COMMIT_OUTPUT:]}


def started(workspace: Path, state: dict, scenario_id: str) -> None:
    """The workspace holds the turn of the scenario `start` set up, or grading it means nothing."""
    if state.get("started") != scenario_id:
        now = state.get("started") or "no scenario"
        sys.exit(f"{workspace} holds {now}, not {scenario_id}: run `kit.py start {scenario_id}` first")


def record(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).expanduser().resolve()
    state = read_state(workspace)
    item = scenario(args.id)
    started(workspace, state, item["id"])
    paths = changed_files(workspace)
    found = findings(workspace, Path(state["engine"]), paths)
    commit = commit_gate(workspace) if state["route"] == "repo" else None
    graded = grade(item, found, args.gate, commit)
    row = {
        "id": item["id"],
        "pack": item["pack"],
        "kind": item["kind"],
        "agent": state["agent"],
        "route": state["route"],
    }
    row["at"] = _now()
    row |= {"gate_seen": args.gate, "changed": paths, "commit": commit, "note": args.note} | graded
    with (workspace / ".git" / RESULTS).open("a", encoding="utf-8") as out:
        out.write(json.dumps(row) + "\n")
    print(f"{item['id']}: {graded['verdict'].upper()}  (changed {len(paths)} file(s))")
    for f in graded["targeted"] + graded["other"]:
        print(f"  {f['path']}:{f['line']}  {f['rule']}  {' '.join(f['cwe'])}")
    if graded["caught_at"] == "commit":
        print("  the agent left it; the commit gate refused it by name")
    if graded["commit_agrees"] is False:
        print("  the commit gate and the engine disagree -- a wiring fault; its output is in the results file")
    if not paths:
        print("  nothing changed on disk: did the agent refuse the task, or did the turn not finish?")


def latest_results(workspace: Path) -> tuple[str, dict[str, dict]]:
    """(agent/route label, the latest result per scenario): a re-run replaces the earlier one."""
    state = read_state(workspace)
    path = workspace / ".git" / RESULTS
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []
    return f"{state['agent']} ({state['route']})", {row["id"]: row for row in rows}


def report(args: argparse.Namespace) -> None:
    columns = [latest_results(Path(d).expanduser().resolve()) for d in args.dir]
    ids = sorted({i for _, results in columns for i in results})
    packs = {s["id"]: s["pack"] for s in load_scenarios()}
    header = "| scenario | pack | " + " | ".join(label for label, _ in columns) + " |"
    lines = [header, "|" + "---|" * (2 + len(columns))]
    lines += [
        f"| {i} | {packs.get(i, '?')} | " + " | ".join(cell(results.get(i)) for _, results in columns) + " |"
        for i in ids
    ]
    for label, results in columns:
        passed = sum(r["verdict"] == "pass" for r in results.values())
        lines.append(f"\n**{label}:** {passed}/{len(results)} scenarios pass.")
    text = "\n".join(lines)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8", newline="\n")
    print(text)


def list_scenarios(args: argparse.Namespace) -> None:
    for item in load_scenarios():
        if in_tier(item, args.tier):
            print(f"{item['id']:<32} {item['kind']:<8} {item['pack']:<12} {item['title']}")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utf8_console() -> None:
    """Windows consoles and pipes default to a legacy code page (cp1252) that cannot encode much
    beyond ASCII, and the kit echoes prompts, paths and findings it did not write. Everything the
    kit says itself is ASCII; anything else is written as UTF-8, never a crash."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> None:
    utf8_console()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("setup", help="create a workspace from the fixture")
    p.add_argument("--dir", required=True)
    p.add_argument("--agent", choices=AGENTS, required=True)
    p.add_argument("--route", choices=("plugin", "repo"), required=True)
    p.add_argument("--engine", help="the chock_security engine to grade with (default: this catalog's)")
    p.set_defaults(run=setup)
    p = sub.add_parser("list", help="list scenarios")
    p.add_argument("--tier", choices=TIERS, default="full")
    p.set_defaults(run=list_scenarios)
    for name, run, extra in (("start", start, False), ("record", record, True)):
        p = sub.add_parser(name)
        p.add_argument("id")
        p.add_argument("--dir", default=".")
        if extra:
            p.add_argument("--gate", choices=GATE_SEEN, required=True, help="what the client showed")
            p.add_argument("--note", default="")
        p.set_defaults(run=run)
    p = sub.add_parser("report", help="the latest result of every scenario, one column per workspace")
    p.add_argument("--dir", action="append", required=True, help="a workspace; repeat to compare agents")
    p.add_argument("--out")
    p.set_defaults(run=report)
    args = parser.parse_args(argv)
    args.run(args)


if __name__ == "__main__":
    main()
