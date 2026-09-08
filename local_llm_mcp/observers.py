"""Observers: optional, pluggable attribution of what the server does.

An observer receives scalar-only events (tool name, sizes, seconds, exit code,
scrub counts — never content). Three ways to get one:

* nothing (``LOCAL_LLM_MCP_OBSERVER`` unset) — the no-op ``Observer``;
* ``webhook`` — ``WebhookObserver`` POSTs one JSON object per event to
  ``LOCAL_LLM_MCP_OBSERVER_URL``;
* ``module:Class`` — your own subclass of ``Observer``, imported from
  ``LOCAL_LLM_MCP_OBSERVER_PATH`` (a directory added to ``sys.path``). This is
  where a deployment keeps its registrar-specific code, outside this package.

Every observer is fire-and-forget and may never raise into a tool call.
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import sys
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config

log = logging.getLogger("local_llm_mcp.observers")


class Observer:
    """No-op base class. Subclasses override what they need."""

    name = "none"

    def __init__(self, cfg: "Config | None" = None):
        self.cfg = cfg

    async def start(self, info: dict) -> None:
        """Called once the server is up. ``info`` carries session/mode/model/endpoint."""

    def event(self, span: str, kind: str, attrs: dict) -> None:
        """Called on every tool call, compaction and identity change. Must not block."""

    async def end(self, state: str = "done") -> None:
        """Called on shutdown."""

    @property
    def run_id(self) -> str:
        return ""


class WebhookObserver(Observer):
    """POST one JSON object per event to a URL. 2 s timeout, never raises."""

    name = "webhook"

    def __init__(self, cfg: "Config"):
        super().__init__(cfg)
        self.url = cfg.observer_url
        self.info: dict = {}
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(2.0, connect=1.0))
        self._tasks: set[asyncio.Task] = set()

    async def _post(self, body: dict) -> None:
        if not self.url:
            return
        try:
            await self._client.post(self.url, json=body)
        except Exception as exc:
            log.debug("webhook %s failed: %s", self.url, exc)

    def _fire(self, body: dict) -> None:
        try:
            task = asyncio.get_running_loop().create_task(self._post(body))
        except RuntimeError:
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def start(self, info: dict) -> None:
        self.info = dict(info)
        await self._post({"event": "start", **self.info})

    def event(self, span: str, kind: str, attrs: dict) -> None:
        self._fire({"event": "event", "span": span, "kind": kind, "attrs": attrs,
                    "session": self.info.get("session")})

    async def end(self, state: str = "done") -> None:
        await self._post({"event": "end", "state": state, "session": self.info.get("session")})
        for t in list(self._tasks):
            t.cancel()
        await self._client.aclose()


def load_observer(cfg: "Config") -> Observer:
    spec = (cfg.observer or "").strip()
    if not spec:
        return Observer(cfg)
    if spec == "webhook":
        return WebhookObserver(cfg)
    mod_name, _, cls_name = spec.partition(":")
    try:
        if cfg.observer_path:
            p = str(cfg.observer_path)
            if p not in sys.path:
                sys.path.insert(0, p)
        module = importlib.import_module(mod_name)
        cls = getattr(module, cls_name or "Observer")
        obs = cls(cfg)
        if not isinstance(obs, Observer):
            raise TypeError(f"{spec} is not an Observer")
        return obs
    except Exception as exc:
        log.warning("observer %r unavailable (%s); running unobserved", spec, exc)
        return Observer(cfg)
