"""Gather material for the local model: run a command, read files, cap size."""
from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def cap(text: str, max_chars: int) -> tuple[str, bool]:
    """Keep the head and the tail of over-long material, with a marker."""
    if len(text) <= max_chars:
        return text, False
    head = int(max_chars * 0.7)
    tail = max_chars - head
    dropped = len(text) - head - tail
    return text[:head] + f"\n\n[... {dropped} chars omitted from the middle ...]\n\n" + text[-tail:], True


@dataclass
class CommandResult:
    rc: int | None
    output: str
    truncated: bool
    timed_out: bool
    secs: float
    bytes_read: int


async def run_command(cmd: str, *, cwd: str | None, timeout: float, max_chars: int) -> CommandResult:
    env = {**os.environ, "TERM": "dumb", "NO_COLOR": "1", "PAGER": "cat", "GIT_PAGER": "cat",
           "SYSTEMD_PAGER": "cat", "LESS": "-FRX", "PYTHONUNBUFFERED": "1"}
    t0 = time.monotonic()
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=cwd or None,
        env=env,
        executable="/bin/bash",
    )
    limit = max_chars * 4  # bytes; head+tail capping happens after decode
    buf = bytearray()
    truncated = False
    timed_out = False

    async def pump() -> None:
        nonlocal truncated
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            if len(buf) < limit:
                buf.extend(chunk)
            else:
                truncated = True  # keep draining so the child never blocks on a full pipe

    try:
        await asyncio.wait_for(pump(), timeout=timeout)
        rc = await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        rc = None
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass
    text = strip_ansi(bytes(buf).decode("utf-8", "replace"))
    text, capped = cap(text, max_chars)
    return CommandResult(rc=rc, output=text, truncated=truncated or capped, timed_out=timed_out,
                         secs=round(time.monotonic() - t0, 2), bytes_read=len(buf))


def read_paths(paths: list[str], *, max_chars: int, cwd: str | None = None) -> tuple[str, list[dict]]:
    """Concatenate files with headers; directories become listings; errors stay inline."""
    parts: list[str] = []
    meta: list[dict] = []
    budget = max_chars
    for raw in paths:
        p = Path(os.path.expanduser(raw))
        if not p.is_absolute() and cwd:
            p = Path(cwd) / p
        try:
            if p.is_dir():
                entries = sorted(p.iterdir(), key=lambda e: e.name)
                lines = []
                for e in entries[:500]:
                    try:
                        st = e.stat()
                        lines.append(f"{'d' if e.is_dir() else '-'} {st.st_size:>10}  {e.name}")
                    except OSError:
                        lines.append(f"?            ?  {e.name}")
                if len(entries) > 500:
                    lines.append(f"... {len(entries) - 500} more entries")
                body = "\n".join(lines)
                parts.append(f"### DIRECTORY: {p} ({len(entries)} entries)\n{body}\n")
                meta.append({"path": str(p), "kind": "dir", "entries": len(entries)})
            elif p.is_file():
                data = p.read_bytes()
                text = data.decode("utf-8", "replace")
                text, capped = cap(text, min(budget, max_chars))
                parts.append(f"### FILE: {p} ({len(data)} bytes{', truncated' if capped else ''})\n{text}\n")
                meta.append({"path": str(p), "kind": "file", "bytes": len(data), "truncated": capped})
            else:
                parts.append(f"### MISSING: {p} (no such file or directory)\n")
                meta.append({"path": str(p), "kind": "missing"})
        except PermissionError:
            parts.append(f"### DENIED: {p} (permission denied)\n")
            meta.append({"path": str(p), "kind": "denied"})
        except OSError as exc:
            parts.append(f"### ERROR: {p} ({exc})\n")
            meta.append({"path": str(p), "kind": "error", "error": str(exc)})
        budget = max(1000, max_chars - sum(len(x) for x in parts))
    text, capped = cap("\n".join(parts), max_chars)
    if capped:
        meta.append({"kind": "capped", "max_chars": max_chars})
    return text, meta
