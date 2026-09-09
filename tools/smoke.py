#!/usr/bin/env python3
"""End-to-end smoke test: real MCP client over stdio, real local model, isolated state dir.

    .venv/bin/python tools/smoke.py [state_dir]

Exercises initialize (instructions), tool listing, status, a calculation, a
command digest, a PII delegation (asserts the email/password never come back),
placeholder rehydration through a shell command, artifact slicing, compaction
over the control socket (as the PreCompact hook does), and a mode switch.
"""
import asyncio
import json
import os
import re
import socket
import sys
import tempfile
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent


def text(res) -> str:
    return "\n".join(c.text for c in res.content if getattr(c, "type", "") == "text")


def ctl(sock_path: str, req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall((json.dumps(req) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data or b"{}")


async def main() -> int:
    state = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="local-llm-mcp-smoke-"))
    sock_dir = tempfile.mkdtemp(prefix="llm-mcp-smoke-", dir=os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
    env = {**os.environ,
           "LOCAL_LLM_MCP_STATE_DIR": str(state),
           "LOCAL_LLM_MCP_SOCK_DIR": sock_dir,
           "LOCAL_LLM_MCP_SESSION": f"smoke-{int(time.time())}",
           "LOCAL_LLM_MCP_MODE": "pii",
           "LOCAL_LLM_MCP_OBSERVER": "",
           "LOCAL_LLM_MCP_AUTO_COMPACT_CHARS": "10000000"}
    params = StdioServerParameters(command=sys.executable, args=["-m", "local_llm_mcp"], env=env)
    failures = 0

    def check(cond: bool, label: str) -> None:
        nonlocal failures
        print(("  PASS " if cond else "  FAIL ") + label)
        if not cond:
            failures += 1

    t_all = time.monotonic()
    import mcp.types as mtypes
    asked: list[str] = []
    answer = ["continue"]  # what the "user" picks in the disclosure dialog

    async def on_elicit(context, req):
        asked.append(str(getattr(req, "message", "")))
        a = answer[0]
        if a in ("cancel", "decline"):
            return mtypes.ElicitResult(action=a)
        return mtypes.ElicitResult(action="accept", content={"choice": a})

    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, elicitation_callback=on_elicit) as s:
            init = await s.initialize()
            instr = init.instructions or ""
            print(f"[init] server={init.serverInfo.name} instructions={len(instr)} chars")
            check("ACTIVE MODE: PII" in instr, "instructions carry the active mode")
            tools = await s.list_tools()
            names = sorted(t.name for t in tools.tools)
            print("[tools]", names)
            check(names == ["local_llm_artifact", "local_llm_compact", "local_llm_delegate", "local_llm_disclosure", "local_llm_run",
                            "local_llm_set_mode", "local_llm_status"], "seven tools registered")

            st = json.loads(text(await s.call_tool("local_llm_status", {})))
            print(f"[status] key={st['session_key']} mode={st['mode']} sock={st['control_socket']}")
            check(st["mode"] == "pii" and st["control_socket"], "status shows pii mode + control socket")

            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_delegate", {
                "task": "Compute 17*23 + 5. First line: only the number. Second line: the working."}))
            print(f"[math {time.monotonic()-t0:.1f}s]\n{out}\n")
            check("396" in out, "calculation delegated and answered")

            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_run", {
                "command": "ls -la /etc | head -60",
                "task": "How many lines are listed, and which three entries have the largest size column? Name them exactly."}))
            print(f"[run {time.monotonic()-t0:.1f}s]\n{out}\n")
            check("rc 0" in out and re.search(r"ref a_[0-9a-f]{8}", out) is not None, "command digest with rc + ref")

            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_delegate", {
                "task": "Who must be contacted, by when, and what credential is mentioned? Report all three.",
                "material": ("Ticket 4411: contact Dana Smoke at dana.smoke@example.net before 2026-09-12. "
                             "VPN password: Tr0ub4dor&3 (do not share). Backup contact +1 (555) 010-2233.")}))  # gitleaks:allow
            print(f"[pii {time.monotonic()-t0:.1f}s]\n{out}\n")
            low = out.lower()
            check("dana.smoke@example.net" not in low and "tr0ub4dor" not in low and "010-2233" not in out,
                  "PII and secret never returned")
            check(re.search(r"\[(EMAIL|PERSON|PHONE|SECRET)-\d+\]", out) is not None,
                  "private values replaced by placeholders")
            m = re.search(r"ref (a_[0-9a-f]{8})", out)
            pii_ref = m.group(1) if m else ""

            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_run", {
                "command": "printf 'to: [EMAIL-1]\\n' | tr a-z A-Z",
                "task": "Repeat the output line exactly as printed."}))
            print(f"[rehydrate {time.monotonic()-t0:.1f}s]\n{out}\n")
            check("dana.smoke@example.net" not in out.lower(), "rehydrated value did not leak back")
            check("[EMAIL-" in out, "uppercased echo was re-scrubbed to a placeholder")

            if pii_ref:
                out = text(await s.call_tool("local_llm_artifact", {"ref": pii_ref, "offset": 0, "limit": 400}))
                print(f"[artifact]\n{out}\n")
                check("dana.smoke@example.net" not in out.lower() and "[EMAIL-1]" in out and "[SECRET-" in out,
                      "artifact slice is scrubbed")

            before = json.loads(text(await s.call_tool("local_llm_status", {})))
            res = ctl(before["control_socket"], {"op": "compact", "trigger": "manual", "session_id": ""})
            print("[socket compact]", res)
            check(res.get("ok") and res.get("queued"), "control socket queued a compaction")
            deadline = time.monotonic() + 180
            after = before
            while time.monotonic() < deadline:
                await asyncio.sleep(2)
                after = json.loads(text(await s.call_tool("local_llm_status", {})))
                if after["compactions"] > before["compactions"] and not after["compaction_in_progress"]:
                    break
            print(f"[compacted] compactions={after['compactions']} summary_chars={after['summary_chars']} "
                  f"turns_since={after['turns_since_compaction']}")
            print("[summary]\n" + after.get("summary", "") + "\n")
            check(after["compactions"] == before["compactions"] + 1 and after["turns_since_compaction"] == 0,
                  "hook-style compaction happened in the background")
            sl = after.get("summary", "").lower()
            check(sl and "dana.smoke@example.net" not in sl and "tr0ub4dor" not in sl, "summary is scrubbed")

            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_delegate", {
                "task": "From your session memory only: what ticket number was mentioned earlier and what was its deadline? One line."}))
            print(f"[continuity {time.monotonic()-t0:.1f}s]\n{out}\n")
            check("4411" in out and "2026-09-12" in out, "continuity across compaction")

            # verbatim: the worker locates, the server quotes exactly
            src = Path(state) / "sample_module.py"
            body = ["import os", "", "def helper(x):", "    return x + 1", ""] + [f"# filler line {i}" for i in range(120)] + [
                "def target_function(a, b):", "    \"\"\"Adds with a twist.\"\"\"", "    total = a + b  # exact-marker-7731",
                "    if total > 10:", "        return total * 2", "    return total", ""] + [f"# more filler {i}" for i in range(60)]
            src.write_text("\n".join(body))
            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_delegate", {
                "task": "The complete definition of target_function, nothing else.", "paths": [str(src)], "verbatim": True}))
            print(f"[verbatim {time.monotonic()-t0:.1f}s]\n{out}\n")
            check("def target_function(a, b):" in out and "exact-marker-7731" in out and "return total * 2" in out,
                  "verbatim mode quoted the function exactly")
            check("def helper" not in out and "filler line 3" not in out, "verbatim mode left unrelated lines out")
            m = re.search(r"ref (a_[0-9a-f]{8})", out)
            if m:
                out2 = text(await s.call_tool("local_llm_artifact", {"ref": m.group(1), "line_start": 3, "line_end": 4}))
                check("3: def helper(x):" in out2 and "4:     return x + 1" in out2, "artifact line slicing is exact")
            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_delegate", {
                "task": "How many lines does the command print, and what is on the last line? Answer in one line.",
                "command": "printf 'alpha\\nbeta\\ngamma\\n'"}))
            print(f"[delegate+command {time.monotonic()-t0:.1f}s]\n{out}\n")
            check("gamma" in out and "rc 0" in out, "delegate accepts a command as material")

            out = text(await s.call_tool("local_llm_set_mode", {"mode": "assist"}))
            check("ACTIVE MODE: ASSIST" in out, "mode switch returns the new instructions")
            res = ctl(before["control_socket"], {"op": "status"})
            check(res.get("mode") == "assist", "control socket sees the new mode")

            # ---- disclosure lifecycle (ASSIST): first personal data asks the user through the client
            material = "Contact: Priya Testcase <priya.testcase@example.org>, card 4111 1111 1111 1111, ref PR 77"  # gitleaks:allow
            t0 = time.monotonic()
            out = text(await s.call_tool("local_llm_delegate", {
                "task": "Give the contact's email address and the card number exactly as written, in one line.", "material": material}))
            print(f"[disclosure/continue {time.monotonic()-t0:.1f}s]\n{out}\n")
            check(len(asked) == 1 and "1 CARD" in asked[0] and "1 EMAIL" in asked[0] and "priya" not in asked[0].lower(),
                  "first personal data in ASSIST asked the user (counts and kinds only)")
            check("priya.testcase@example.org" in out and "4111 1111 1111 1111" not in out and "[CARD-" in out,
                  "after 'continue': identity shown, card number masked")
            check("disclosure: asked → continue" in out and "The user chose to continue" in out,
                  "the trailer and a notice record the decision")
            out = text(await s.call_tool("local_llm_delegate", {"task": "Repeat the contact's email exactly.", "material": material}))
            check(len(asked) == 1 and "priya.testcase@example.org" in out, "asked once per session; identity stays open")
            st = json.loads(text(await s.call_tool("local_llm_status", {})))
            check(st["disclosure"]["identity"] == "open" and st["disclosure"]["numbers"] == "masked"
                  and st["disclosure"]["client_can_ask"] is True and "EMAIL" in st["disclosure"]["open_kinds"],
                  "status shows the disclosure state")
            d = json.loads(text(await s.call_tool("local_llm_disclosure", {"identity": "masked", "reason": "smoke"})))
            out = text(await s.call_tool("local_llm_delegate", {"task": "Repeat the contact's email exactly.", "material": material}))
            check(d["identity"] == "masked" and "priya.testcase@example.org" not in out and "[EMAIL-" in out,
                  "the tool masks identity again without a dialog")
            await s.call_tool("local_llm_disclosure", {"identity": "ask"})
            answer[0] = "cancel"
            out = text(await s.call_tool("local_llm_delegate", {"task": "Repeat the contact's email exactly.", "material": material}))
            st = json.loads(text(await s.call_tool("local_llm_status", {})))
            check(len(asked) == 2 and "priya.testcase@example.org" not in out and "did not answer" in out
                  and st["disclosure"]["identity"] == "undecided" and st["disclosure"]["asked"] == 2,
                  "a cancelled dialog masks the result and leaves the question open")
            answer[0] = "switch"
            out = text(await s.call_tool("local_llm_delegate", {"task": "Repeat the contact's email exactly.", "material": material}))
            st = json.loads(text(await s.call_tool("local_llm_status", {})))
            check(len(asked) == 3 and "[EMAIL-" in out and "switched this session to PII mode" in out and st["mode"] == "pii"
                  and "ACTIVE MODE: PII" in out, "choosing 'switch' moves the session to PII mode and returns the new instructions")

    import json as _json, pathlib as _pl  # the server flushes its token measurements at shutdown; read the ledger after
    ledger = _pl.Path(str(state)) / "savings.jsonl"
    rows = [_json.loads(l) for l in ledger.read_text().splitlines() if l.strip()] if ledger.is_file() else []
    check(len(rows) >= 5 and all(str(r.get("turn") or "").startswith("t_") for r in rows),
          f"savings ledger has one row per counted turn, each with its turn id ({len(rows)} rows)")
    check(any(isinstance(r.get("gathered_tokens"), int) and r["gathered_tokens"] > 0 for r in rows),
          "worker-measured token counts reached the ledger")
    print(f"\n{'ALL PASS' if not failures else f'{failures} FAILURE(S)'} in {time.monotonic()-t_all:.1f}s; state={state}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
