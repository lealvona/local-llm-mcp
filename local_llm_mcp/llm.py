"""OpenAI-compatible client for the local vLLM, with chunked digests."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

from .config import Config

log = logging.getLogger("local_llm_mcp.llm")


class LLMError(RuntimeError):
    pass


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    chunks: int = 1

    def add(self, u: dict | None) -> None:
        self.calls += 1
        if u:
            self.prompt_tokens += int(u.get("prompt_tokens") or 0)
            self.completion_tokens += int(u.get("completion_tokens") or 0)


class LocalLLM:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
        self.client = httpx.AsyncClient(
            base_url=cfg.base_url,
            headers=headers,
            timeout=httpx.Timeout(cfg.llm_timeout, connect=10.0),
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    def tokens_for(self, max_output_chars: int) -> int:
        return max(400, min(self.cfg.max_tokens_cap, max_output_chars // 3 + 256))

    async def chat(self, system: str, user: str, *, max_tokens: int, temperature: float = 0.2) -> tuple[str, dict]:
        body: dict = {
            "model": self.cfg.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if not self.cfg.thinking:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        last_exc: Exception | None = None
        for attempt in (1, 2):
            try:
                r = await self.client.post("/chat/completions", json=body)
                if r.status_code == 401:
                    raise LLMError("local model rejected the API key (401); check LOCAL_LLM_MCP_API_KEY_FILE")
                if r.status_code >= 400:
                    raise LLMError(f"local model returned HTTP {r.status_code}: {r.text[:300]}")
                data = r.json()
                choice = (data.get("choices") or [{}])[0]
                msg = choice.get("message") or {}
                content = (msg.get("content") or "").strip()
                if not content:
                    reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
                    if reasoning:
                        raise LLMError("local model spent its budget on reasoning and returned no content; "
                                       "raise max_output_chars or keep LOCAL_LLM_MCP_THINKING=0")
                    raise LLMError(f"local model returned empty content (finish_reason={choice.get('finish_reason')})")
                return content, (data.get("usage") or {})
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                if attempt == 1:
                    await asyncio.sleep(1.0)
                    continue
                raise LLMError(f"local model unreachable at {self.cfg.base_url}: {type(exc).__name__}: {exc}") from exc
        raise LLMError(str(last_exc))

    @staticmethod
    def split_chunks(text: str, chunk_chars: int) -> list[str]:
        if len(text) <= chunk_chars:
            return [text]
        chunks: list[str] = []
        pos = 0
        n = len(text)
        while pos < n:
            end = min(n, pos + chunk_chars)
            if end < n:
                nl = text.rfind("\n", pos + chunk_chars // 2, end)
                if nl > 0:
                    end = nl + 1
            chunks.append(text[pos:end])
            pos = end
        return chunks

    async def digest(self, system: str, task: str, material: str, source: str, *,
                     max_output_chars: int, render_user, render_reduce) -> tuple[str, Usage]:
        """Answer ``task`` over ``material``; map-reduce when the material exceeds one chunk."""
        usage = Usage()
        max_tokens = self.tokens_for(max_output_chars)
        chunks = self.split_chunks(material, self.cfg.chunk_chars)
        usage.chunks = len(chunks)
        if len(chunks) == 1:
            text, u = await self.chat(system, render_user(task, material, source, None), max_tokens=max_tokens)
            usage.add(u)
            return text, usage
        sem = asyncio.Semaphore(self.cfg.parallel_chunks)

        async def one(i: int, chunk: str) -> str:
            async with sem:
                part_note = f"part {i + 1} of {len(chunks)}"
                text, u = await self.chat(system, render_user(task, chunk, source, part_note),
                                          max_tokens=max_tokens)
                usage.add(u)
                return text

        parts = await asyncio.gather(*(one(i, c) for i, c in enumerate(chunks)))
        final, u = await self.chat(system, render_reduce(task, parts, source), max_tokens=max_tokens)
        usage.add(u)
        return final, usage
