#!/usr/bin/env python3
"""Leak check: delegate a REAL secrets file through a fresh PII-mode server and assert
that no value from it reaches the caller.

    python tools/leakcheck.py /path/to/secrets.env [more files...]

The file is read here only to build the list of values to guard (KEY=VALUE lines,
values of 8+ characters that are not URLs, paths or references). Nothing from it is
printed; the digest is shown only when it provably contains none of those values,
not even a 12-character fragment. Exit code 1 on any leak.
"""
import asyncio
import os
import re
import sys
import tempfile
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*['\"]?([^'\"\n]+?)['\"]?\s*$")


def guarded_values(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE_RE.match(line)
        if m and len(m.group(2)) >= 8 and not m.group(2).startswith(("http", "/", "$", "~")):
            out.append(m.group(2))
    return out


async def check(path: Path) -> bool:
    values = guarded_values(path)
    print(f"[material] {path}: {len(values)} secret-shaped values >= 8 chars to guard")
    run = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    env = {"LOCAL_LLM_MCP_ARM": "on", **os.environ, "LOCAL_LLM_MCP_MODE": "pii", "LOCAL_LLM_MCP_OBSERVER": "",
           "LOCAL_LLM_MCP_STATE_DIR": tempfile.mkdtemp(prefix="llm-mcp-leakcheck-"),
           "LOCAL_LLM_MCP_SOCK_DIR": tempfile.mkdtemp(prefix="llm-mcp-lc-", dir=run),
           "LOCAL_LLM_MCP_SESSION": f"leakcheck-{int(time.time())}"}
    params = StdioServerParameters(command=sys.executable, args=["-m", "local_llm_mcp"], env=env)
    with open(os.devnull, "w") as devnull:
        async with stdio_client(params, errlog=devnull) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                t0 = time.time()
                res = await s.call_tool("local_llm_delegate", {
                    "task": ("List every variable NAME defined in this file, one per line, marking each as "
                             "SECRET (key/token/password/credential) or CONFIG (url/flag/name/number). Never print a value."),
                    "paths": [str(path)], "max_output_chars": 4000})
                out = "\n".join(c.text for c in res.content if getattr(c, "type", "") == "text")
    leaks = [v for v in values if v in out]
    partial = [v for v in values if len(v) >= 16 and (v[:12] in out or v[-12:] in out)]
    print(f"[result] {len(out)} chars in {time.time() - t0:.1f}s; full-value leaks={len(leaks)} partial(12-char)={len(partial)}")
    if leaks or partial:
        print("[FAIL] a value leaked — digest withheld")
        return False
    print("[PASS] no value from the file reached the caller; digest follows:")
    print(out)
    return True


async def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    ok = True
    for arg in sys.argv[1:]:
        ok = await check(Path(arg).expanduser()) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
