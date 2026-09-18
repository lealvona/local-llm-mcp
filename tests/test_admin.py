"""Admin API contract: auth, terms CRUD, scrub tester, sessions, purges, traversal refusal."""
import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from local_llm_mcp.admin import make_server
from local_llm_mcp.config import Config


@pytest.fixture
def server(tmp_path, monkeypatch):
    state = tmp_path / "state"
    (state / "sessions" / "sess-1" / "artifacts").mkdir(parents=True)
    d = state / "sessions" / "sess-1"
    (d / "meta.json").write_text(json.dumps({"key": "sess-1", "mode": "pii", "turns": 2, "compactions": 1, "claude_pid": 999999,
                                             "previous_keys": ["pid-1"]}))
    (d / "placeholders.json").write_text(json.dumps({"placeholders": {"[EMAIL-1]": {"kind": "EMAIL", "value": "a@example.org"}}}))
    (d / "context.jsonl").write_text(json.dumps({"id": "t_1", "kind": "delegate", "task": "x", "result": "[EMAIL-1] ok"}) + "\n"
                                     + json.dumps({"id": "t_2", "kind": "run", "task": "y", "result": "ok", "gathered_chars": 38000, "out_chars": 1900}) + "\n")
    (d / "summary.md").write_text("memory")
    (d / "artifacts" / "a_0123abcd.txt").write_text("raw")
    terms = tmp_path / "terms.json"
    terms.write_text(json.dumps({"terms": [{"kind": "PERSON", "values": ["Jane Q. Example"]}]}))
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(state))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRIVATE_TERMS", str(terms))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRICES", str(tmp_path / "prices-override.json"))
    (state / "savings.jsonl").write_text(
        json.dumps({"ts": "2026-09-01T00:00:00", "session": "sess-1", "kind": "run", "gathered_chars": 38000, "out_chars": 1900}) + "\n"
        + json.dumps({"ts": "2026-09-02T00:00:00", "session": "gone", "kind": "delegate", "gathered_chars": 0, "out_chars": 760}) + "\n"
        + json.dumps({"ts": "2026-08-30T00:00:00", "session": "pid-1", "kind": "run", "gathered_chars": 3800, "out_chars": 190,
                      "gathered_tokens": 1000, "returned_tokens": 50}) + "\n")
    monkeypatch.delenv("LOCAL_LLM_MCP_RULES", raising=False)
    cfg = Config.from_env()
    srv = make_server("127.0.0.1", 0, cfg, "tok-secret")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def call(base, method, path, body=None, token="tok-secret"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_ping_and_auth(server):
    code, d = call(server, "GET", "/api/ping", token=None)
    assert code == 200 and d["auth_required"] is True and d["authed"] is False
    assert call(server, "GET", "/api/overview", token=None)[0] == 401
    assert call(server, "GET", "/api/overview", token="wrong")[0] == 401
    code, d = call(server, "GET", "/api/overview")
    assert code == 200 and d["sessions"] == 1 and d["terms"]["PERSON"] == 1 and d["rules_count"] >= 5


def test_index_served_without_token(server):
    with urllib.request.urlopen(server + "/", timeout=10) as r:
        assert r.status == 200 and b"<title>" in r.read()


def test_terms_crud_and_scrub(server):
    code, d = call(server, "POST", "/api/terms", {"items": [{"kind": "ADDRESS", "value": "12 Example Lane"}, {"kind": "PERSON", "value": "jane q. example"}]})
    assert code == 200 and d["added"] == 1  # the duplicate (case-insensitive) is skipped
    code, d = call(server, "POST", "/api/scrub-test", {"text": "Jane Q. Example lives at 12 Example Lane; key sk-abcdefghijklmnopqrstuvwxyz0123", "mode": "pii"})  # gitleaks:allow
    assert code == 200 and "[PERSON-1]" in d["scrubbed"] and "[ADDRESS-1]" in d["scrubbed"] and "[SECRET-1]" in d["scrubbed"]
    assert {s["kind"] for s in d["spans"]} == {"PERSON", "ADDRESS", "SECRET"}
    code, d = call(server, "POST", "/api/scrub-test", {"text": "Jane Q. Example, key sk-abcdefghijklmnopqrstuvwxyz0123", "mode": "assist"})  # gitleaks:allow
    assert "Jane Q. Example" in d["scrubbed"] and "[SECRET-1]" in d["scrubbed"]  # assist: secrets only
    code, d = call(server, "DELETE", "/api/terms", {"kind": "ADDRESS", "value": "12 Example Lane"})
    assert code == 200 and d["removed"] is True
    assert call(server, "DELETE", "/api/terms", {"kind": "ADDRESS", "value": "nope"})[0] == 404


def test_sessions_detail_and_purges(server):
    code, d = call(server, "GET", "/api/sessions")
    assert code == 200 and d["sessions"][0]["key"] == "sess-1" and d["sessions"][0]["live"] is False
    assert d["sessions"][0]["placeholder_total"] == 1 and d["sessions"][0]["artifacts"] == 1
    code, det = call(server, "GET", "/api/sessions/sess-1")
    assert code == 200 and det["placeholders"][0]["value"] == "a@example.org" and det["summary"] == "memory" and len(det["turns"]) == 2
    code, d = call(server, "DELETE", "/api/sessions/sess-1/artifacts")
    assert code == 200 and d["deleted"] == 1
    code, d = call(server, "DELETE", "/api/sessions/sess-1/placeholders")
    assert code == 200 and d["ok"] is True
    assert call(server, "GET", "/api/sessions/sess-1")[1]["placeholders"] == []
    code, d = call(server, "DELETE", "/api/sessions/sess-1")
    assert code == 200 and d["ok"] is True
    assert call(server, "GET", "/api/sessions/sess-1")[0] == 404


def test_traversal_and_bad_keys_refused(server):
    assert call(server, "GET", "/api/sessions/..%2F..%2Fetc")[0] in (400, 404)
    assert call(server, "GET", "/api/sessions/has%20space")[0] == 400
    assert call(server, "GET", "/api/nothing")[0] == 404


def test_savings_and_prices_api(server):
    code, d = call(server, "GET", "/api/savings")
    assert code == 200 and d["all_time"]["turns"] == 3 and d["all_time"]["sessions"] == 3
    assert d["all_time"]["avoided_input"] == 9500 + 950 and d["all_time"]["avoided_output"] == 200  # 3.8 chars/token + one measured
    assert d["all_time"]["measured_turns"] == 1 and d["prices_stale"] is False and d["prices_age_days"] is not None
    assert d["caller_model"] and d["all_time"]["cost"]["with_carry_usd"] > 0
    row = next(r for r in d["sessions"] if r["key"] == "sess-1")
    assert row["turns"] == 2 and row["avoided_input"] == 9500 + 950 and row["with_carry_usd"] > 0 and not row["purged"]
    assert not any(r["key"] == "pid-1" for r in d["sessions"])  # folded into sess-1 through previous_keys
    gone = next(r for r in d["sessions"] if r["key"] == "gone")
    assert gone["purged"] and gone["mode"] == "?" and gone["avoided_output"] == 200
    code, p = call(server, "GET", "/api/prices")
    assert code == 200 and not p["override_present"] and len(p["models"]) >= 20 and p["default_model_ids"]
    assert p["stale"] is False and isinstance(p["age_days"], int)
    first = p["models"][0]["model_id"]
    code, p2 = call(server, "POST", "/api/prices", {"assumptions": {"context_reuse_calls": 0, "caller_model": first},
                                                   "models": [{"model_id": first, "input_per_m": 100, "output_per_m": 1}]})
    assert code == 200 and p2["override_present"] and p2["assumptions"]["context_reuse_calls"] == 0
    assert next(m for m in p2["models"] if m["model_id"] == first)["input_per_m"] == 100
    code, d2 = call(server, "GET", "/api/savings")
    assert d2["caller_model"] == first and d2["all_time"]["carried"] == 0
    f = d2["all_time"]["cost"]["tokenizer_factor"]  # the caller model's tokenizer factor scales the priced tokens
    assert f >= 1 and d2["all_time"]["cost"]["direct_usd"] == round(f * (10450 * 100 / 1e6 + 200 * 1 / 1e6), 4)
    code, o = call(server, "GET", "/api/overview")
    assert code == 200 and o["savings"]["caller_model"] == first and o["savings"]["with_carry_usd"] == d2["all_time"]["cost"]["with_carry_usd"]
    code, p3 = call(server, "DELETE", "/api/prices")
    assert code == 200 and p3["reset"] and not p3["override_present"]
    assert call(server, "GET", "/api/savings", token="")[0] == 401


# ---- a non-loopback bind with no token must not silently start (was: logged, then served) ----


def _bare_env(tmp_path, monkeypatch):
    """Enough env for Config.from_env() to succeed, nothing that opens a port."""
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRICES", str(tmp_path / "prices-override.json"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRIVATE_TERMS", str(tmp_path / "terms.json"))
    monkeypatch.delenv("LOCAL_LLM_MCP_RULES", raising=False)
    monkeypatch.delenv("LOCAL_LLM_MCP_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("LOCAL_LLM_MCP_ADMIN_TOKEN_FILE", raising=False)
    monkeypatch.delenv("LOCAL_LLM_MCP_ADMIN_ALLOW_NO_TOKEN", raising=False)
    # main() calls load_env_file() for real; without this it reads the machine's own
    # deployment dotenv, which may set an ADMIN_TOKEN_FILE and silently pass the test.
    monkeypatch.setenv("LOCAL_LLM_MCP_ENV_FILE", str(tmp_path / "no-such-env-file"))


def test_loopback_needs_no_token(tmp_path, monkeypatch, capsys):
    from local_llm_mcp.admin import main
    _bare_env(tmp_path, monkeypatch)
    assert main(["--bind", "127.0.0.1", "--backfill-savings"]) == 0  # exits before binding; proves no refusal fires


def test_non_loopback_with_no_token_refuses_to_start(tmp_path, monkeypatch, capsys):
    from local_llm_mcp.admin import main
    _bare_env(tmp_path, monkeypatch)
    rc = main(["--bind", "0.0.0.0", "--port", "0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "refusing to bind" in err and "ADMIN_ALLOW_NO_TOKEN" in err


def test_non_loopback_with_a_token_is_fine(tmp_path, monkeypatch):
    from local_llm_mcp.admin import make_server
    from local_llm_mcp.config import Config
    _bare_env(tmp_path, monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_MCP_ADMIN_TOKEN", "tok")
    cfg = Config.from_env()
    srv = make_server("0.0.0.0", 0, cfg, "tok")
    srv.server_close()


def test_the_override_lets_it_start_anyway(tmp_path, monkeypatch):
    _bare_env(tmp_path, monkeypatch)
    monkeypatch.setenv("LOCAL_LLM_MCP_ADMIN_ALLOW_NO_TOKEN", "1")
    from local_llm_mcp.admin import make_server
    from local_llm_mcp.config import Config
    cfg = Config.from_env()
    srv = make_server("0.0.0.0", 0, cfg, "")
    srv.server_close()
