"""The delegation pipeline with the worker stubbed: verbatim quoting, and the digest fallback when nothing matches."""
import asyncio
import json

from local_llm_mcp.config import Config
from local_llm_mcp.llm import Usage
from local_llm_mcp.server import App


def make_app(monkeypatch, tmp_path) -> App:
    for k in ("FALLBACK_BASE_URL", "API_KEY", "API_KEY_FILE", "RULES", "OBSERVER"):
        monkeypatch.delenv("LOCAL_LLM_MCP_" + k, raising=False)
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRICES", str(tmp_path / "prices.json"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRIVATE_TERMS", str(tmp_path / "terms.json"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SESSION", "t-delegate")
    monkeypatch.setenv("LOCAL_LLM_MCP_MODE", "assist")
    app = App(Config.from_env())

    async def count_tokens(text):
        return len(text.split())

    async def digest(system, task, material, source, *, max_output_chars, render_user, render_reduce):
        return f"digested: {task} over {len(material)} chars", Usage()

    app.llm.count_tokens = count_tokens
    app.llm.digest = digest
    return app


def run(app: App, **kw) -> str:
    async def go():
        out = await app.delegate(**kw)
        await app.flush_measurements()
        return out
    return asyncio.run(go())


def test_verbatim_quotes_when_lines_match(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)

    async def locate(task, material, source, max_output_chars):
        return "2: beta", []
    app.locate_and_quote = locate
    out = run(app, kind="run", task="the beta line", material="alpha\nbeta\ngamma\n", source="command: x",
              max_output_chars=500, verbatim=True)
    assert out.startswith("2: beta") and "· verbatim" in out and "digested instead" not in out
    turn = app.session.turns()[-1]
    assert turn["verbatim"] is True and "verbatim_fallback" not in turn


def test_verbatim_with_no_match_is_digested_instead(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)

    async def locate(task, material, source, max_output_chars):
        return "", []
    app.locate_and_quote = locate
    out = run(app, kind="run", task="How many lines?", material="alpha\nbeta\ngamma\n", source="command: x",
              max_output_chars=500, verbatim=True)
    assert out.startswith("digested: How many lines? over 17 chars")
    assert "verbatim: no lines matched, digested instead" in out and "· verbatim ·" not in out
    turn = app.session.turns()[-1]
    assert turn["verbatim"] is False and turn["verbatim_fallback"] is True and turn["result"].startswith("digested:")
    rows = [json.loads(l) for l in (tmp_path / "state" / "savings.jsonl").read_text().splitlines()]
    assert rows[-1]["turn"] == turn["id"] and rows[-1]["verbatim"] is False  # counted as a digest, not a quote
