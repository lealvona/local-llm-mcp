"""FastMCP server: the tools, the delegation pipeline, compaction, control socket.

Invariant that everything here is arranged around:
  * everything that goes TO the worker or the shell is REHYDRATED (placeholders -> values);
  * everything that LEAVES the server (tool results, artifacts, status, summaries)
    is SCRUBBED (values -> placeholders) — fully in PII mode, secrets-only in ASSIST mode.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, AsyncIterator

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from . import prompts
from .config import MODES, Config
from .control import socket_path, start as start_control
from .llm import LLMError, LocalLLM
from .material import cap, read_paths, run_command
from .observers import load_observer
from .scrub import ScrubResult, Scrubber
from .session import Session

log = logging.getLogger("local_llm_mcp.server")


class App:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = Session(cfg)
        self.llm = LocalLLM(cfg)
        self.scrubber = Scrubber(cfg.rules_path, cfg.private_terms_path, strict=cfg.strict_pii)
        self.observer = load_observer(cfg)
        self.lock = asyncio.Lock()
        self.compacting: asyncio.Task | None = None
        self.control_server: asyncio.AbstractServer | None = None
        self.control_path = None

    # ---- boundaries ------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self.session.mode

    def outbound(self, text: str) -> ScrubResult:
        """Everything that leaves the server passes through here."""
        return self.scrubber.scrub(text, self.session.vault, secrets_only=(self.mode != "pii"))

    def inbound(self, text: str) -> str:
        """Everything that goes to the worker or the shell passes through here."""
        return self.session.vault.rehydrate(text)

    # ---- pipeline --------------------------------------------------------------

    @staticmethod
    def _trailer(parts: list[str]) -> str:
        return "\n\n— local-llm · " + " · ".join(p for p in parts if p)

    async def delegate(self, *, kind: str, task: str, material: str, source: str,
                       max_output_chars: int, extra: dict | None = None) -> str:
        t0 = time.monotonic()
        mode = self.mode
        extra = extra or {}
        async with self.lock:
            # Everything detectable in the material gets a placeholder BEFORE the
            # worker sees it, so an exact echo in the answer is caught even
            # when the answer's own context would not have matched a rule.
            self.scrubber.register_material(material, self.session.vault, secrets_only=(mode != "pii"))
            entities = 0
            if mode == "pii" and material and self.cfg.entity_pass:
                entities = await self.entity_pass(material)
            context = self.inbound(self.session.context_block(self.cfg.context_chars))
            system = prompts.worker_system(mode, max_output_chars, context)
            error = ""
            answer = ""
            usage = None
            finalized = False
            try:
                answer, usage = await self.llm.digest(
                    system, self.inbound(task), material, source,
                    max_output_chars=max_output_chars,
                    render_user=prompts.render_user, render_reduce=prompts.render_reduce)
                if prompts.needs_finalize(answer):
                    final, u2 = await self.llm.chat(
                        system, prompts.render_finalize(self.inbound(task), answer, max_output_chars),
                        max_tokens=self.llm.tokens_for(max_output_chars), temperature=0.1)
                    usage.add(u2)
                    answer, finalized = final, True
            except LLMError as exc:
                error = str(exc)
            secs = round(time.monotonic() - t0, 2)
            ref = self.session.store_artifact(material, {"kind": kind, "source": source[:300], "chars": len(material),
                                                         "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
                                                         **{k: v for k, v in extra.items() if k in ("rc", "timed_out", "truncated")}}) if material else ""
            scrubbed = self.outbound(answer) if answer else ScrubResult("", 0, {})
            # What the worker SAW is part of its memory too, not only what it said —
            # bounded, and scrubbed like everything else that is written down.
            excerpt = self.outbound(material[:self.cfg.excerpt_chars]).text if material else ""
            turn = {
                "kind": kind, "mode": mode, "task": task[:2000], "source": source[:300], "excerpt": excerpt,
                "result": scrubbed.text[:6000] if not error else f"ERROR: {error[:500]}",
                "ref": ref, "raw_chars": len(material), "out_chars": len(scrubbed.text), "secs": secs,
                "model": self.cfg.model, **extra,
            }
            tid = self.session.append_turn(turn)
            self.observer.event("execute_tool", f"local_llm.{kind}", {
                "mode": mode, "turn": tid, "ref": ref, "raw_chars": len(material), "out_chars": len(scrubbed.text),
                "secs": secs, "model": self.cfg.model, "rc": extra.get("rc"), "error": bool(error),
                "scrubbed": scrubbed.replaced, "chunks": getattr(usage, "chunks", 1) if usage else 0,
                "finalized": finalized, "entities": entities, "session": self.session.key,
            })
            if error:
                trailer = self._trailer([mode, f"turn {tid}", f"ref {ref}" if ref else "", f"{secs}s"])
                return f"Error: {error}{trailer}"
            trailer = self._trailer([
                mode, f"turn {tid}", f"ref {ref}" if ref else "",
                f"rc {extra['rc']}" if "rc" in extra else "",
                f"raw {len(material)} chars" + (" (truncated)" if extra.get("truncated") else "") if material else "no material",
                f"{usage.chunks} chunks" if usage and usage.chunks > 1 else "",
                "finalized" if finalized else "",
                self.cfg.model, f"{secs}s", scrubbed.trailer(),
            ])
            result = scrubbed.text + trailer
        self.maybe_autocompact()
        return result

    async def entity_pass(self, material: str) -> int:
        """Ask the worker what private values the material holds; register them.
        Bounded to the first two chunks; failures cost nothing (the shape rules,
        the private terms and the worker's own placeholder discipline still apply)."""
        try:
            sample, _ = cap(material, self.cfg.chunk_chars * 2)
            text, _u = await self.llm.chat(prompts.ENTITY_SYSTEM, prompts.ENTITY_USER.format(material=sample),
                                           max_tokens=2048, temperature=0.0)
            found = prompts.parse_entities(text)
            return self.scrubber.register_entities(found, material, self.session.vault)
        except Exception as exc:
            log.warning("entity pass failed: %s", exc)
            return 0

    # ---- compaction ------------------------------------------------------------

    def schedule_compaction(self, reason: str) -> asyncio.Task:
        if self.compacting and not self.compacting.done():
            return self.compacting
        self.compacting = asyncio.get_running_loop().create_task(self.compact(reason))
        return self.compacting

    def maybe_autocompact(self) -> None:
        try:
            if self.session.uncompacted_chars() > self.cfg.auto_compact_chars:
                self.schedule_compaction("auto: running context grew past the threshold")
        except Exception as exc:  # never let bookkeeping break a result
            log.warning("autocompact check failed: %s", exc)

    async def compact(self, reason: str) -> dict:
        t0 = time.monotonic()
        mode = self.mode
        async with self.lock:
            turns = [t for t in self.session.turns_since_compaction() if t.get("kind") != "compaction"]
            previous = self.session.summary()
            if not turns:
                return {"ok": True, "skipped": "no new turns since the last compaction", "summary_chars": len(previous)}
            turns_text = "\n".join(Session.render_turn(t, task_chars=1500, result_chars=3500,
                                                        excerpt_chars=self.cfg.excerpt_chars) for t in turns)
            turns_text, _ = cap(turns_text, self.cfg.chunk_chars * 2)
            system, user = prompts.compaction_prompts(mode, self.inbound(previous), self.inbound(turns_text),
                                                      self.cfg.summary_chars)
            try:
                summary, usage = await self.llm.chat(system, user, max_tokens=self.llm.tokens_for(self.cfg.summary_chars),
                                                     temperature=0.1)
            except LLMError as exc:
                self.observer.event("session", "compaction_failed", {"error": str(exc)[:200], "session": self.session.key})
                return {"ok": False, "error": str(exc)}
            scrubbed = self.outbound(summary)
            self.session.write_summary(scrubbed.text)
            secs = round(time.monotonic() - t0, 2)
            self.session.meta["compactions"] = int(self.session.meta.get("compactions", 0)) + 1
            self.session.meta["last_compaction"] = datetime.now().astimezone().isoformat(timespec="seconds")
            self.session.append_turn({"kind": "compaction", "task": reason, "mode": mode,
                                      "result": f"compacted {len(turns)} turns into {len(scrubbed.text)} chars",
                                      "secs": secs, "model": self.cfg.model})
            self.observer.event("session", "compaction", {
                "reason": reason[:120], "turns": len(turns), "summary_chars": len(scrubbed.text), "secs": secs,
                "scrubbed": scrubbed.replaced, "session": self.session.key})
            log.info("compacted %d turns -> %d chars in %.1fs (%s)", len(turns), len(scrubbed.text), secs, reason)
            return {"ok": True, "turns": len(turns), "summary_chars": len(scrubbed.text), "secs": secs,
                    "compactions": self.session.meta["compactions"], "scrubbed": scrubbed.replaced}

    # ---- control socket --------------------------------------------------------

    async def ctl_compact(self, req: dict) -> dict:
        sid = str(req.get("session_id") or "")
        if sid:
            self.session.adopt_session_id(sid, source="hook")
        trigger = str(req.get("trigger") or "unknown")
        self.schedule_compaction(f"caller compaction ({trigger})")
        return {"ok": True, "queued": True, "session": self.session.key}

    async def ctl_session(self, req: dict) -> dict:
        sid = str(req.get("session_id") or "")
        changed = self.session.adopt_session_id(sid, source=str(req.get("source") or "hook"))
        return {"ok": True, "session": self.session.key, "changed": changed, "mode": self.mode}

    async def ctl_status(self, req: dict) -> dict:
        return {"ok": True, **self.session.status()}

    async def start_control(self) -> None:
        self.control_path = socket_path(self.cfg.sock_dir, self.session.claude_pid)
        try:
            self.control_server = await start_control(self.control_path, {
                "compact": self.ctl_compact, "session": self.ctl_session, "status": self.ctl_status})
        except Exception as exc:
            log.warning("control socket unavailable (%s); hook-driven compaction disabled", exc)

    async def stop_control(self) -> None:
        if self.control_server:
            self.control_server.close()
            try:
                await self.control_server.wait_closed()
            except Exception:
                pass
        if self.control_path and self.control_path.exists():
            try:
                self.control_path.unlink()
            except OSError:
                pass


APP: App | None = None


def _app() -> App:
    assert APP is not None, "server not built"
    try:
        if APP.session.refresh_identity():
            APP.observer.event("session", "id_change", {"session": APP.session.key,
                                                          "claude_session_id": APP.session.claude_session_id})
    except Exception as exc:  # identity is bookkeeping; never fail a tool call on it
        log.warning("identity refresh failed: %s", exc)
    return APP


def build(cfg: Config) -> FastMCP:
    global APP
    APP = App(cfg)
    app = APP

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[dict]:
        app.lock = asyncio.Lock()
        await app.start_control()
        try:
            await app.observer.start({"session": app.session.key, "claude_session_id": app.session.claude_session_id,
                                      "mode": app.mode, "model": cfg.model, "endpoint": cfg.base_url})
        except Exception as exc:
            log.debug("observer start failed: %s", exc)
        try:
            yield {}
        finally:
            app.observer.event("session", "end", {"session": app.session.key,
                                                    "turns": app.session.meta.get("turns", 0)})
            await app.stop_control()
            try:
                await app.observer.end("done")
            except Exception:
                pass
            await app.llm.aclose()

    mcp = FastMCP(
        "local_llm_mcp",
        instructions=prompts.client_instructions(app.mode, cfg.model, cfg.base_url),
        lifespan=lifespan,
        log_level=cfg.log_level if cfg.log_level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO",
    )

    def _budget(v: int) -> int:
        return v if v > 0 else cfg.max_output_chars

    @mcp.tool(
        name="local_llm_run",
        title="Run a command here and receive a digest of its output",
        description=(
            "Execute a shell command on this host (bash -c, this user's privileges, stdin closed) and have the local "
            "worker model digest the output for you. You receive the digest plus a trailer (turn id, artifact ref, "
            "exit code, raw size); the raw output is stored as an artifact you can slice with local_llm_artifact. "
            "Use this instead of your own shell tool whenever the command would print more than you need to read "
            "(logs, tests, builds, listings, git output, grep results). Placeholders such as [SECRET-1] in the command "
            "are expanded server-side before execution and never appear in the result."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False),
    )
    async def local_llm_run(
        command: Annotated[str, Field(min_length=1, description="The shell command to run, e.g. 'journalctl -u nginx --since -1h' or 'pytest -q'.")],
        task: Annotated[str, Field(description="What to report from the output. Default: outcome, every error/warning verbatim, key values.")] = "",
        cwd: Annotated[str, Field(description="Working directory for the command. Default: the server's own cwd.")] = "",
        timeout_s: Annotated[int, Field(ge=0, le=3600, description="Kill the command after this many seconds (0 = server default).")] = 0,
        max_output_chars: Annotated[int, Field(ge=0, le=20000, description="Soft budget for the digest (0 = server default).")] = 0,
    ) -> str:
        a = _app()
        res = await run_command(a.inbound(command), cwd=cwd or None,
                                timeout=float(timeout_s or cfg.command_timeout), max_chars=cfg.material_max_chars)
        task_text = task.strip() or prompts.DEFAULT_RUN_TASK
        if res.timed_out:
            task_text += f" NOTE: the command was killed after {timeout_s or int(cfg.command_timeout)}s; say so."
        if res.rc not in (0, None):
            task_text += f" NOTE: exit code {res.rc}."
        material = res.output
        if not material.strip():
            material = f"(no output; exit code {res.rc}{', timed out' if res.timed_out else ''})"
        return await a.delegate(kind="run", task=task_text, material=material, source=f"command: {command[:200]}",
                                max_output_chars=_budget(max_output_chars),
                                extra={"rc": res.rc, "timed_out": res.timed_out, "truncated": res.truncated,
                                       "cmd_secs": res.secs})

    @mcp.tool(
        name="local_llm_delegate",
        title="Delegate a task with inline material and/or files",
        description=(
            "Hand a task to the local worker model with optional inline material and/or file paths it should read "
            "(directories are listed). Use for reading or summarizing files and documents, research and synthesis over "
            "provided text, calculations, format transformations, parsing, boilerplate drafting, and — in PII mode — "
            "anything that touches private data (the worker reads it; you receive placeholders). The worker also "
            "carries its own running memory of this conversation, so follow-up tasks can refer to earlier results "
            "by turn id (t_xxxxxx) or artifact ref (a_xxxxxxxx)."),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=False),
    )
    async def local_llm_delegate(
        task: Annotated[str, Field(min_length=1, description="What to do, precisely: what to extract, what to report, thresholds, output shape.")],
        material: Annotated[str, Field(description="Inline text to work on (pasted output, a document, data). Optional.")] = "",
        paths: Annotated[list[str], Field(description="Files or directories to read as material (~ expands). Optional.")] = [],
        cwd: Annotated[str, Field(description="Base directory for relative paths.")] = "",
        max_output_chars: Annotated[int, Field(ge=0, le=20000, description="Soft budget for the answer (0 = server default).")] = 0,
    ) -> str:
        a = _app()
        pieces: list[str] = []
        sources: list[str] = []
        if material:
            pieces.append(material)
            sources.append(f"inline ({len(material)} chars)")
        if paths:
            text, meta = read_paths([a.inbound(p) for p in paths], max_chars=cfg.material_max_chars, cwd=cwd or None)
            pieces.append(text)
            sources.append("paths: " + ", ".join(p[:80] for p in paths[:8]) + (" …" if len(paths) > 8 else ""))
        joined = "\n\n".join(pieces)
        joined, truncated = cap(joined, cfg.material_max_chars)
        return await a.delegate(kind="delegate", task=task, material=joined, source="; ".join(sources) or "none",
                                max_output_chars=_budget(max_output_chars), extra={"truncated": truncated} if truncated else {})

    @mcp.tool(
        name="local_llm_artifact",
        title="Read a slice of a stored raw output",
        description=(
            "Return a slice of the raw material behind an earlier result, by its artifact ref (a_xxxxxxxx from a "
            "trailer). Use when the digest left out something you need exactly. In PII mode the slice is scrubbed "
            "(placeholders); in ASSIST mode only secrets are scrubbed. Paginate with offset/limit."),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_artifact(
        ref: Annotated[str, Field(pattern=r"^a_[0-9a-f]{8}$", description="Artifact ref from a result trailer, e.g. a_1f2e3d4c.")],
        offset: Annotated[int, Field(ge=0, description="Character offset to start from.")] = 0,
        limit: Annotated[int, Field(ge=100, le=20000, description="Maximum characters to return.")] = 4000,
    ) -> str:
        a = _app()
        raw = a.session.read_artifact(ref)
        if raw is None:
            return f"Error: no artifact {ref} in this session (refs are per conversation; see local_llm_status)."
        piece = raw[offset:offset + limit]
        scrubbed = a.outbound(piece)
        has_more = offset + limit < len(raw)
        trailer = App._trailer([f"artifact {ref}", f"chars {offset}-{min(offset + limit, len(raw))} of {len(raw)}",
                                f"next offset {offset + limit}" if has_more else "end", scrubbed.trailer()])
        return scrubbed.text + trailer

    @mcp.tool(
        name="local_llm_status",
        title="Show the worker's session state",
        description="Mode, session identity, model, turns since compaction, context size, compaction count, placeholder counts, artifact count.",
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_status() -> str:
        a = _app()
        st = a.session.status()
        st["summary"] = a.outbound(a.session.summary()).text
        st["control_socket"] = str(a.control_path) if a.control_server else None
        st["observer"] = a.observer.name
        st["observer_run"] = a.observer.run_id or None
        st["compaction_in_progress"] = bool(a.compacting and not a.compacting.done())
        return json.dumps(st, indent=1)

    @mcp.tool(
        name="local_llm_compact",
        title="Compact the worker's running context now",
        description=(
            "Ask the worker to compress its running memory of this conversation into a fresh summary. Normally "
            "automatic (a PreCompact hook triggers it when your own context is compacted, and the server compacts on "
            "its own when its context grows large); call it only if you compacted manually and the hook is absent."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_compact(
        reason: Annotated[str, Field(description="Why (recorded in the context log).")] = "requested by caller",
    ) -> str:
        a = _app()
        res = await a.compact(reason)
        return json.dumps(res, indent=1)

    @mcp.tool(
        name="local_llm_set_mode",
        title="Switch between PII and ASSIST mode",
        description=(
            "Switch the server's mode for the rest of this conversation and return the instructions that apply in the "
            "new mode. 'pii': delegate everything that may touch private data; results are fully sanitized. "
            "'assist': delegate anything context-free whose output would be larger than its digest; only secrets are scrubbed."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_set_mode(
        mode: Annotated[str, Field(pattern=r"^(pii|assist)$", description="'pii' or 'assist'.")],
    ) -> str:
        a = _app()
        if mode not in MODES:
            return f"Error: mode must be one of {MODES}"
        previous = a.mode
        a.session.set_mode(mode)
        a.session.append_turn({"kind": "mode", "task": f"mode {previous} -> {mode}", "result": "", "mode": mode})
        a.observer.event("session", "mode_change", {"from": previous, "to": mode, "session": a.session.key})
        return f"Mode is now {mode} (was {previous}).\n\n" + prompts.client_instructions(mode, cfg.model, cfg.base_url)

    return mcp
