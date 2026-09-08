"""Unix-socket control channel: how the caller's hooks reach a running server.

One JSON object per line in, one out. Ops: ``compact`` (queue a compaction),
``session`` (announce the caller's session id), ``status``. The socket lives at
``$XDG_RUNTIME_DIR/local-llm-mcp/<claude_pid>.sock`` (dir 0700, socket 0600;
``LOCAL_LLM_MCP_SOCK_DIR`` overrides, ``<state>/sock`` when no runtime dir) so only this user's
processes can reach it, and the hook finds it by walking its own ancestry.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Awaitable, Callable

log = logging.getLogger("local_llm_mcp.control")

Handler = Callable[[dict], Awaitable[dict]]


def socket_path(sock_dir: Path, claude_pid: int) -> Path:
    sock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = sock_dir / f"{claude_pid}.sock"
    if len(str(p).encode()) > 100:
        log.warning("socket path %s is near the AF_UNIX 108-byte limit; set LOCAL_LLM_MCP_SOCK_DIR shorter", p)
    return p


async def start(path: Path, handlers: dict[str, Handler]) -> asyncio.AbstractServer:
    if path.exists():
        path.unlink()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        resp: dict
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            req = json.loads(line.decode("utf-8") or "{}")
            op = str(req.get("op") or "")
            h = handlers.get(op)
            if h is None:
                resp = {"ok": False, "error": f"unknown op {op!r}", "ops": sorted(handlers)}
            else:
                resp = await h(req)
        except Exception as exc:
            resp = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        try:
            writer.write((json.dumps(resp) + "\n").encode("utf-8"))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    server = await asyncio.start_unix_server(handle, path=str(path))
    os.chmod(path, 0o600)
    log.info("control socket %s", path)
    return server
