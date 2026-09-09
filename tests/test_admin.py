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
    (d / "meta.json").write_text(json.dumps({"key": "sess-1", "mode": "pii", "turns": 2, "compactions": 1, "claude_pid": 999999}))
    (d / "placeholders.json").write_text(json.dumps({"placeholders": {"[EMAIL-1]": {"kind": "EMAIL", "value": "a@example.org"}}}))
    (d / "context.jsonl").write_text(json.dumps({"id": "t_1", "kind": "delegate", "task": "x", "result": "[EMAIL-1] ok"}) + "\n")
    (d / "summary.md").write_text("memory")
    (d / "artifacts" / "a_0123abcd.txt").write_text("raw")
    terms = tmp_path / "terms.json"
    terms.write_text(json.dumps({"terms": [{"kind": "PERSON", "values": ["Jane Q. Example"]}]}))
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(state))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRIVATE_TERMS", str(terms))
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
    assert code == 200 and det["placeholders"][0]["value"] == "a@example.org" and det["summary"] == "memory" and len(det["turns"]) == 1
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
