#!/usr/bin/env python3
"""Claude Code hook for local-llm-mcp (stdlib only; always exits 0; ~ms).

Installed for two events in ~/.claude/settings.json:

  SessionStart  — record  <state>/pidmap/<claude_pid> = this session's id so
                  the MCP server spawned by the same Claude process (or by a
                  later --resume of it) lands on the same running context; and
                  tell an already-running server the id over its control socket.
  PreCompact    — tell the running server to compact ITS context, because the
                  caller's is about to be compacted. Fire-and-forget: the
                  server compacts in the background; the hook never blocks
                  the caller's own compaction for more than a socket round trip.

Both find the server the same way the server finds its session: by walking
the process tree. Nothing here ever reads the transcript or the prompt.
"""
import json
import os
import socket
import sys
import time

STATE = os.path.expanduser(os.environ.get("LOCAL_LLM_MCP_STATE_DIR", "~/.local/state/local-llm-mcp"))


def sock_dir():
    # Must mirror local_llm_mcp.config.default_sock_dir(): same env, same answer.
    d = os.environ.get("LOCAL_LLM_MCP_SOCK_DIR")
    if d:
        return os.path.expanduser(d)
    run = os.environ.get("XDG_RUNTIME_DIR")
    if run and os.path.isdir(run):
        return os.path.join(run, "local-llm-mcp")
    return os.path.join(STATE, "sock")
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "ksh"}


def ancestors(max_depth=10):
    pid = os.getppid()
    out = []
    for _ in range(max_depth):
        if pid <= 1:
            break
        try:
            with open(f"/proc/{pid}/stat") as fh:
                ppid = int(fh.read().rsplit(")", 1)[1].split()[1])
            with open(f"/proc/{pid}/comm") as fh:
                comm = fh.read().strip()
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").lower()
        except Exception:
            break
        out.append((pid, comm, cmd))
        pid = ppid
    return out


def is_claude_process(cmd):
    # Mirror local_llm_mcp.session.is_claude_process: judge the EXECUTABLE only.
    argv0 = cmd.split(" ", 1)[0] if cmd else ""
    base = os.path.basename(argv0)
    if base == "claude" or base.startswith("claude-code"):
        return True
    if "/ccd-cli/" in argv0 or "/.claude/local/" in argv0:
        return True
    if base.startswith("node") and "claude-code" in cmd and "cli.js" in cmd:
        return True
    return False


def claude_pid(chain):
    for pid, comm, cmd in chain:
        if comm in SHELLS or "local-llm-mcp" in cmd or "local_llm_mcp" in cmd:
            continue
        if is_claude_process(cmd):
            return pid
    for pid, comm, cmd in chain:
        if comm not in SHELLS:
            return pid
    return os.getppid()


def send(pid, req, timeout=3.0):
    path = os.path.join(sock_dir(), f"{pid}.sock")
    if not os.path.exists(path):
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(path)
        s.sendall((json.dumps(req) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data or b"{}")
    except Exception:
        return None


def write_pidmap(pid, session_id, extra):
    d = os.path.join(STATE, "pidmap")
    os.makedirs(d, mode=0o700, exist_ok=True)
    rec = {"session_id": session_id, "ts": time.time(), **extra}
    tmp = os.path.join(d, f".{pid}.tmp")
    with open(tmp, "w") as fh:
        json.dump(rec, fh)
    os.replace(tmp, os.path.join(d, str(pid)))
    # Opportunistic hygiene: drop mappings older than a week whose pid is gone.
    try:
        now = time.time()
        for name in os.listdir(d):
            p = os.path.join(d, name)
            if name.isdigit() and now - os.path.getmtime(p) > 7 * 86400 and not os.path.exists(f"/proc/{name}"):
                os.unlink(p)
    except Exception:
        pass


def main():
    try:
        p = json.load(sys.stdin)
    except Exception:
        return 0
    event = p.get("hook_event_name") or ""
    sid = str(p.get("session_id") or "")
    chain = ancestors()
    cpid = claude_pid(chain)
    pids = [cpid] + [x[0] for x in chain if x[0] != cpid]
    if event == "SessionStart":
        if sid:
            write_pidmap(cpid, sid, {"cwd": p.get("cwd") or "", "source": p.get("source") or ""})
            for pid in pids:
                if send(pid, {"op": "session", "session_id": sid, "source": p.get("source") or "startup"}):
                    break
    elif event == "PreCompact":
        for pid in pids:
            if send(pid, {"op": "compact", "trigger": p.get("trigger") or "unknown", "session_id": sid}):
                break
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
