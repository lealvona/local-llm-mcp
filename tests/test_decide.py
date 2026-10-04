"""The optional decision tools, answered by the server's own workers through the vendored decision engine.
A scripted fake worker stands in for vLLM; no model is needed."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from local_llm_mcp.governance import POLICIES, advise

CHOICES = {"digest": "Summarize", "review": "Review"}


class FakeWorker:
    """OpenAI-compatible: answers every request with `reply` (a JSON reason+choice when the reasoning schema
    is asked for), and records each request body."""

    def __init__(self, choice="digest", status=200):
        self.bodies, self.choice, self.status = [], choice, status
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.bodies.append(body)
                if fake.status != 200:
                    self.send_response(fake.status); self.end_headers(); return
                so = body.get("structured_outputs") or {}
                content = json.dumps({"reason": "decisive fact", "choice": fake.choice}) if "json" in so else fake.choice
                data = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self):
        self.server.shutdown(); self.server.server_close()


@pytest.fixture
def workers():
    made = []
    def make(**kw):
        w = FakeWorker(**kw); made.append(w); return w
    yield make
    for w in made:
        w.close()


def _env(monkeypatch, tmp_path, **extra):
    for k in ("FALLBACK_BASE_URL", "FALLBACK_MODEL", "API_KEY", "API_KEY_FILE", "FALLBACK_API_KEY_FILE", "RULES", "OBSERVER",
              "DECIDE", "DECIDE_PREFER", "DECIDE_REASONING", "DECIDE_TIMEOUT_S"):
        monkeypatch.delenv("LOCAL_LLM_MCP_" + k, raising=False)
    for k, v in {"STATE_DIR": tmp_path / "state", "SOCK_DIR": tmp_path / "sock", "PRICES": tmp_path / "prices.json",
                 "PRIVATE_TERMS": tmp_path / "terms.json", "RUN_ALLOW": tmp_path / "run-allow.txt",
                 "SESSION": "t-decide", "MODE": "assist", **extra}.items():
        monkeypatch.setenv("LOCAL_LLM_MCP_" + k, str(v))


def _server(monkeypatch, tmp_path, **extra):
    from local_llm_mcp import server
    from local_llm_mcp.config import Config
    _env(monkeypatch, tmp_path, **extra)
    mcp = server.build(Config.from_env())
    async def armed(*a, **kw): return True, ""
    if server.APP.decider:
        server.APP.ensure_armed = armed
    return server, mcp, {t.name for t in asyncio.run(mcp.list_tools())}


def _call(mcp, name, args):
    out = asyncio.run(mcp.call_tool(name, args))
    blocks = out[0] if isinstance(out, tuple) else out
    return json.loads(blocks[0].text)


def test_off_by_default_exposes_nothing(monkeypatch, tmp_path):
    server, mcp, tools = _server(monkeypatch, tmp_path)
    assert not {"local_llm_decide", "local_llm_governance"} & tools
    assert "local-llm://decision-policies" not in {str(r.uri) for r in asyncio.run(mcp.list_resources())}
    assert server.APP.decider is None


def test_on_uses_the_servers_own_workers_primary_first(monkeypatch, tmp_path, workers):
    primary, fallback = workers(choice="digest"), workers(choice="review")
    server, mcp, tools = _server(monkeypatch, tmp_path, DECIDE="1", BASE_URL=primary.url, MODEL="big",
                                 FALLBACK_BASE_URL=fallback.url, FALLBACK_MODEL="small")
    assert {"local_llm_decide", "local_llm_governance"} <= tools
    r = _call(mcp, "local_llm_decide", {"state": "a long log", "question": "How?", "choices": CHOICES})
    assert (r["status"], r["choice"], r["worker"], r["mode"]) == ("ok", "digest", "big", "reasoned")
    assert r["reason"] == "decisive fact" and r["advisory_only"] is True
    assert len(primary.bodies) == 1 and not fallback.bodies
    assert primary.bodies[0]["chat_template_kwargs"] == {"enable_thinking": False}  # THINKING defaults off


def test_prefer_fallback_puts_the_fallback_worker_first(monkeypatch, tmp_path, workers):
    primary, fallback = workers(choice="digest"), workers(choice="review")
    server, mcp, _ = _server(monkeypatch, tmp_path, DECIDE="1", DECIDE_PREFER="fallback", BASE_URL=primary.url, MODEL="big",
                             FALLBACK_BASE_URL=fallback.url, FALLBACK_MODEL="small")
    r = _call(mcp, "local_llm_decide", {"state": "x", "question": "q", "choices": CHOICES})
    assert (r["choice"], r["worker"]) == ("review", "small")
    assert not primary.bodies
    assert [w["model"] for w in server.APP.decider.status()["workers"]] == ["small", "big"]


def test_a_dead_first_worker_fails_over(monkeypatch, tmp_path, workers):
    dead, good = workers(status=500), workers(choice="review")
    server, mcp, _ = _server(monkeypatch, tmp_path, DECIDE="1", DECIDE_PREFER="fallback", BASE_URL=good.url, MODEL="big",
                             FALLBACK_BASE_URL=dead.url, FALLBACK_MODEL="small")
    r = _call(mcp, "local_llm_decide", {"state": "x", "question": "q", "choices": CHOICES})
    assert (r["status"], r["choice"], r["worker"]) == ("ok", "review", "big")
    assert r["attempts"][0] == "small:http500"


def test_no_worker_answers_means_unavailable_not_an_error(monkeypatch, tmp_path, workers):
    dead = workers(status=503)
    server, mcp, _ = _server(monkeypatch, tmp_path, DECIDE="1", BASE_URL=dead.url, MODEL="big")
    r = _call(mcp, "local_llm_decide", {"state": "x", "question": "q", "choices": CHOICES})
    assert (r["status"], r["choice"]) == ("unavailable", None)


def test_answer_only_mode_when_reasoning_is_off(monkeypatch, tmp_path, workers):
    w = workers(choice="review")
    server, mcp, _ = _server(monkeypatch, tmp_path, DECIDE="1", DECIDE_REASONING="0", BASE_URL=w.url, MODEL="big")
    r = _call(mcp, "local_llm_decide", {"state": "x", "question": "q", "choices": CHOICES})
    assert (r["choice"], r["mode"], r["reason"]) == ("review", "restricted", None)
    assert w.bodies[0]["structured_outputs"] == {"choice": list(CHOICES)}


def test_each_field_is_scrubbed_before_it_reaches_the_worker(monkeypatch, tmp_path, workers):
    """Scrubbing the JSON encoding instead hid quoted secrets (escaped quotes defeat the shapes) and let a
    masked PEM block swallow the JSON around it. Now each field is scrubbed on its own."""
    w = workers(choice="digest")
    server, mcp, _ = _server(monkeypatch, tmp_path, DECIDE="1", BASE_URL=w.url, MODEL="big")
    pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----"  # gitleaks:allow (synthetic fixture: proves the scrubber masks it)
    secrets = ["hunter2-very-secret", "abc123def456ghi789jkl0", "MIIBVQIBADANBgkq"]  # gitleaks:allow (synthetic fixture)
    state = f'config has password: "{secrets[0]}" and API_KEY="{secrets[1]}"\n{pem}'
    r = _call(mcp, "local_llm_decide", {"state": state, "question": "Choose",
                                         "choices": {"digest": "Summarize", "review": f"password: {secrets[0]}"}})
    assert r["choice"] == "digest"
    sent = json.dumps(w.bodies)
    assert not any(s in sent for s in secrets) and "[SECRET-" in sent
    w.bodies.clear()
    r = _call(mcp, "local_llm_governance", {"policy": "failure_triage", "evidence": state})
    assert r["policy"] == "failure_triage" and r["policy_version"] == 2
    assert w.bodies and not any(s in json.dumps(w.bodies) for s in secrets)


def test_the_opt_in_gate_still_applies(monkeypatch, tmp_path, workers):
    w = workers()
    server, mcp, _ = _server(monkeypatch, tmp_path, DECIDE="1", BASE_URL=w.url, MODEL="big")
    async def refused(*a, **kw): return False, "not turned on"
    server.APP.ensure_armed = refused
    out = asyncio.run(mcp.call_tool("local_llm_decide", {"state": "x", "question": "q", "choices": CHOICES}))
    assert "not turned on" in str(out) and not w.bodies


def test_invalid_prefer_is_a_configuration_error(monkeypatch, tmp_path):
    from local_llm_mcp.config import Config, ConfigError
    _env(monkeypatch, tmp_path, DECIDE="1", DECIDE_PREFER="sideways")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_governance_presets_are_versioned():
    class Engine:
        def decide(self, state, question, choices):
            from local_llm_mcp.decision_engine import Decision
            assert set(choices) == set(POLICIES["completion_review"]["choices"])
            return Decision("ok", "verify")
    r = advise(Engine(), "completion_review", "exit 0, nothing checked")
    assert (r["choice"], r["policy_version"]) == ("verify", 2)
    with pytest.raises(ValueError):
        advise(Engine(), "no_such_policy", "x")
