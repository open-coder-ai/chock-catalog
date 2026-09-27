"""Run the scenarios with Claude Code headless: `start`, one `claude -p` turn, `record` -- unattended.

    python kit.py auto --out ~/kit-runs/today --route repo --tier full --workers 4
    python kit.py auto --out ~/kit-runs/today --route plugin --plugin-dir <built plugin> --tier smoke

The manual loop stays the reference: it is how every other agent is tested, and how a person sees
what an agent really shows. This runs the same loop for Claude Code, which has a print mode and
reports its hooks' answers as events, so the gate it showed is read from the turn rather than
typed in. Each worker owns one workspace; every turn's raw stream-json is kept beside the results,
and `report.md` merges the routes run into the same --out.

A run is resumable: a scenario already recorded under --out is not run again.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from grading import cell
from workspace import RESULTS, read_state

KIT = Path(__file__).resolve().parent / "kit.py"
ROUTES = ("repo", "plugin")

#: What wires a Claude Code process to the session that started it. A turn run from inside one
#: (a cloud session, CI driven by Claude) would otherwise report into its parent.
SESSION_VARS = frozenset(
    {
        "CLAUDECODE",
        "CLAUDE_PID",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_CODE_REMOTE_SESSION_ID",
        "CLAUDE_CODE_CHILD_SESSION",
        "CLAUDE_CODE_SESSION_ATTENDED",
        "CLAUDE_CODE_MESSAGING_SOCKET",
        "CLAUDE_CODE_MESSAGING_TOKEN",
        "CLAUDE_CODE_TEE_SDK_STDOUT",
        "CLAUDE_CODE_POST_FOR_SESSION_INGRESS_V2",
        "CLAUDE_CODE_SYNC_SESSION_REFS",
        "CLAUDE_CODE_SYNC_SKILLS",
        "CLAUDE_CODE_DIAGNOSTICS_FILE",
        "CLAUDE_CODE_WORKER_EPOCH",
        "CLAUDE_CODE_REMOTE_SEND_KEEPALIVES",
        "CLAUDE_CODE_HOLD_UNANSWERED_PARKED_PERMISSION",
        "CLAUDE_AFTER_LAST_COMPACT",
        "SESSION_INGRESS_URL",
    }
)


def child_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in SESSION_VARS}


def _refused(event: dict) -> bool:
    """A hook's answer that stopped the agent: a non-zero exit, or a deny, ask or block decision."""
    if event.get("exit_code") not in (0, None):
        return True
    said = f"{event.get('stdout', '')}{event.get('output', '')}"
    return any(decision in said for decision in ('"deny"', '"ask"', '"block"'))


#: Headless Claude Code emits `hook_response` only for SessionStart. A PreToolUse refusal reaches
#: the stream as the blocked tool's error result ("PreToolUse:Edit hook error: ..."), a Stop one as
#: the feedback the client hands the model ("Stop hook feedback: ...").
PRE_TOOL_MARK = "PreToolUse:"
STOP_MARK = "Stop hook feedback"


def _text(content: object) -> str:
    """A message or tool result's text, whether a plain string or a list of text blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            _text(block.get("text", block.get("content", ""))) for block in content if isinstance(block, dict)
        )
    return ""


def _client_refusals(event: dict) -> set[str]:
    """Where a user-turn event carries a hook's refusal: a blocked tool's error, or Stop feedback."""
    places: set[str] = set()
    content = (event.get("message") or {}).get("content")
    blocks = content if isinstance(content, list) else [{"type": "text", "text": content}]
    # Only the client's own text: a tool result (a file the agent read) may say anything.
    said = _text([b for b in blocks if isinstance(b, dict) and b.get("type") == "text"])
    if said.lstrip().startswith(STOP_MARK):
        places.add("at Stop")
    for block in blocks:
        is_blocked = isinstance(block, dict) and block.get("type") == "tool_result" and block.get("is_error")
        if is_blocked and PRE_TOOL_MARK in _text(block.get("content")):
            places.add("before the write")
    return places


def gate_seen(stream: str) -> tuple[str, str]:
    """(refused|silent, where): read off the client's own hook events and tool errors, never off
    text the agent read -- INDEX.md quotes the refusal message, and reading it is not a refusal."""
    places: set[str] = set()
    for raw in stream.splitlines():
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "system" and event.get("subtype") == "hook_response":
            hook = event.get("hook_event")
            if hook in ("PreToolUse", "Stop") and _refused(event):
                places.add("before the write" if hook == "PreToolUse" else "at Stop")
        elif event.get("type") == "user":
            places |= _client_refusals(event)
    return ("refused", ", ".join(sorted(places))) if places else ("silent", "")


def turn_result(stream: str) -> dict:
    for raw in reversed(stream.splitlines()):
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        if event.get("type") == "result":
            return event
    return {}


def _kit(*args: str) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(KIT), *args]
    return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)


def claude_argv(args: argparse.Namespace, prompt: str) -> list[str]:
    argv = [args.claude, "-p", prompt, "--output-format", "stream-json", "--verbose"]
    # acceptEdits: writes go through, as a user approving them would; anything else is refused
    # rather than asked, since nobody is there to answer. The hooks run either way.
    argv += ["--permission-mode", "acceptEdits", "--max-turns", str(args.max_turns)]
    # The workspace's own settings, never the tester's: user-level hooks and output styles are
    # not the thing under test.
    argv += ["--setting-sources", "project,local"]
    if args.model:
        argv += ["--model", args.model]
    if args.route == "plugin":
        argv += ["--plugin-dir", str(Path(args.plugin_dir).expanduser().resolve())]
    return argv


def run_one(args: argparse.Namespace, workspace: Path, item: dict) -> dict:
    started = _kit("start", item["id"], "--dir", str(workspace))
    if started.returncode:
        return {"id": item["id"], "error": (started.stdout + started.stderr).strip()[-800:]}
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            claude_argv(args, item["prompt"].strip()),
            cwd=workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout,
            check=False,
            stdin=subprocess.DEVNULL,
            env=child_env(),
        )
        stream = proc.stdout
    except subprocess.TimeoutExpired as exc:
        stream = exc.stdout if isinstance(exc.stdout, str) else ""
    turns = Path(args.out) / "transcripts"
    turns.mkdir(parents=True, exist_ok=True)
    (turns / f"{args.route}-{item['id']}.jsonl").write_text(stream, encoding="utf-8")
    seen, where = gate_seen(stream)
    recorded = _kit("record", item["id"], "--dir", str(workspace), "--gate", seen, "--note", where)
    result = turn_result(stream)
    return {
        "id": item["id"],
        "route": args.route,
        "gate": seen,
        "where": where,
        "seconds": round(time.monotonic() - t0),
        "cost_usd": result.get("total_cost_usd", 0),
        "turn_error": bool(result.get("is_error")) or not result,
        "record": recorded.stdout.strip() or recorded.stderr.strip()[-400:],
    }


def _worker(n: int, args: argparse.Namespace, jobs: queue.Queue, log: Path, lock: threading.Lock) -> None:
    workspace = Path(args.out) / f"{args.route}-{n}"
    if not workspace.exists():
        made = _kit("setup", "--dir", str(workspace), "--agent", "claude", "--route", args.route)
        if made.returncode:
            print(f"setup {workspace} failed:\n{made.stdout}{made.stderr}", file=sys.stderr)
            return
    while True:
        try:
            item = jobs.get_nowait()
        except queue.Empty:
            return
        row = run_one(args, workspace, item)
        with lock:
            with log.open("a", encoding="utf-8") as out:
                out.write(json.dumps(row) + "\n")
            first = (row.get("record") or row.get("error") or "").splitlines()
            print(f"[{args.route}#{n}] {first[0] if first else item['id']}", flush=True)


def _done(log: Path) -> set[str]:
    if not log.is_file():
        return set()
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    return {row["id"] for row in rows if "error" not in row and not row.get("turn_error")}


def report(out: Path, packs: dict[str, str]) -> str:
    """One column per route run into --out, merged across that route's workers."""
    columns: dict[str, dict[str, dict]] = {}
    for workspace in sorted(p for p in out.iterdir() if (p / ".git" / RESULTS).is_file()):
        route = read_state(workspace)["route"]
        rows = (workspace / ".git" / RESULTS).read_text(encoding="utf-8").splitlines()
        columns.setdefault(route, {}).update({row["id"]: row for row in map(json.loads, rows)})
    routes = [r for r in ROUTES if r in columns]
    ids = sorted({i for results in columns.values() for i in results})
    lines = ["| scenario | pack | " + " | ".join(f"claude ({r})" for r in routes) + " |"]
    lines.append("|" + "---|" * (2 + len(routes)))
    lines += [
        f"| {i} | {packs.get(i, '?')} | " + " | ".join(cell(columns[r].get(i)) for r in routes) + " |" for i in ids
    ]
    for r in routes:
        passed = sum(row["verdict"] == "pass" for row in columns[r].values())
        lines.append(f"\n**claude ({r}):** {passed}/{len(columns[r])} scenarios pass.")
    return "\n".join(lines) + "\n"


def command(args: argparse.Namespace, scenarios: list[dict], in_tier: Callable[[dict, str], bool]) -> None:
    if args.route == "plugin" and not args.plugin_dir:
        sys.exit("--route plugin needs --plugin-dir: the built Claude Code plugin to load")
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    args.out = str(out)
    wanted = set(args.only.split(",")) if args.only else None
    items = [s for s in scenarios if in_tier(s, args.tier) and (wanted is None or s["id"] in wanted)]
    log = out / f"turns-{args.route}.jsonl"
    done = _done(log)
    jobs: queue.Queue = queue.Queue()
    for item in items:
        if item["id"] not in done:
            jobs.put(item)
    print(f"{args.route}: {jobs.qsize()} to run, {len(items) - jobs.qsize()} already recorded", flush=True)
    lock = threading.Lock()
    threads = [threading.Thread(target=_worker, args=(n, args, jobs, log, lock)) for n in range(max(1, args.workers))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    text = report(out, {s["id"]: s["pack"] for s in scenarios})
    (out / "report.md").write_text(text, encoding="utf-8", newline="\n")
    print(text)


def add_parser(sub, scenarios: Callable[[], list[dict]], in_tier: Callable[[dict, str], bool], tiers) -> None:
    """kit.py hands over its scenarios rather than this module importing kit: no import cycle."""
    p = sub.add_parser("auto", help="run scenarios with Claude Code headless, unattended")
    p.add_argument("--out", required=True, help="a directory for the workspaces, transcripts and report")
    p.add_argument("--route", choices=ROUTES, required=True)
    p.add_argument("--plugin-dir", help="plugin route: the built Claude Code plugin to load")
    p.add_argument("--tier", choices=tiers, default="smoke")
    p.add_argument("--only", help="comma-separated scenario ids")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--model", help="the model to run (default: Claude Code's own)")
    p.add_argument("--max-turns", type=int, default=40)
    p.add_argument("--timeout", type=int, default=1200, help="seconds per scenario")
    p.add_argument("--claude", default="claude", help="the Claude Code executable")
    p.set_defaults(run=lambda args: command(args, scenarios(), in_tier))
