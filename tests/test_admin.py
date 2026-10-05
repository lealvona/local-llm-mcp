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


# ---- onboarding: suggestions, review, rejections by hash, backup status --------------------------------

@pytest.fixture
def onboard(tmp_path, monkeypatch):
    terms = tmp_path / "terms.json"
    terms.write_text(json.dumps({"terms": [{"kind": "PERSON", "values": ["Jane Q. Example"]}]}))
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"suggestions": [
        {"kind": "PERSON", "value": "Robin Example", "source": "test seed", "confidence": "high"},
        {"kind": "person", "value": "jane q. example", "source": "already saved, other case"},
        {"kind": "EMAIL", "value": "robin@example.org", "confidence": "medium"},
        {"kind": "NOT-A-KIND", "value": "Example Corp", "note": "employer"},
        {"kind": "PII", "value": "x"},
    ]}))
    stamp = tmp_path / "terms.sha256"
    gitcfg = tmp_path / "gitconfig"
    gitcfg.write_text("[user]\n\tname = Git Example\n\temail = git@example.org\n")
    for k, v in {"STATE_DIR": tmp_path / "state", "SOCK_DIR": tmp_path / "sock", "PRIVATE_TERMS": terms, "PRICES": tmp_path / "p.json",
                 "TERMS_SEED": seed, "TERMS_BACKUP_STAMP": stamp, "ENV_FILE": tmp_path / "no-env"}.items():
        monkeypatch.setenv("LOCAL_LLM_MCP_" + k, str(v))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitcfg))  # never read the real machine's identity in a test
    monkeypatch.delenv("LOCAL_LLM_MCP_RULES", raising=False)
    srv = make_server("127.0.0.1", 0, Config.from_env(), "tok-secret")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", tmp_path, terms, stamp
    srv.shutdown()


def _values(sug):
    return {(s["kind"], s["value"]) for s in sug["suggestions"]}


def test_onboard_page_is_served_and_its_api_needs_the_token(onboard):
    base, *_ = onboard
    with urllib.request.urlopen(base + "/onboard", timeout=10) as r:
        assert r.status == 200 and b"Private terms onboarding" in r.read()
    for method, path in [("GET", "/api/terms/suggestions"), ("POST", "/api/terms/review"), ("GET", "/api/terms/backup"),
                         ("DELETE", "/api/terms/rejections"), ("POST", "/api/terms/lint")]:
        assert call(base, method, path, {} if method != "GET" else None, token="")[0] == 401


def test_suggestions_merge_seed_and_local_sources_minus_what_is_saved(onboard):
    base, *_ = onboard
    code, s = call(base, "GET", "/api/terms/suggestions")
    v = _values(s)
    assert code == 200 and s["seed_present"]
    assert ("PERSON", "Robin Example") in v and ("EMAIL", "robin@example.org") in v
    assert ("PERSON", "Git Example") in v and ("EMAIL", "git@example.org") in v      # git identity
    assert ("PII", "Example Corp") in v                                                 # unknown kind -> PII
    assert not any(val.casefold() == "jane q. example" for _, val in v)                 # already saved, any case
    assert ("PII", "x") not in v                                                         # too short to be a term
    assert ("PERSON", "Example") in v and ("PERSON", "r. example") not in v             # name variants (last name)
    assert ("PERSON", "R. Example") in v
    robin = next(x for x in s["suggestions"] if x["value"] == "Robin Example")
    assert robin["confidence"] == "high" and robin["source"] == "test seed"
    last = next(x for x in s["suggestions"] if x["value"] == "Example")
    assert any("single name" in w for w in last["warnings"])
    assert s["suggestions"][0]["confidence"] == "high"                                  # high first


def test_review_accepts_and_remembers_rejections_only_as_hashes(onboard):
    base, tmp_path, terms, _ = onboard
    code, r = call(base, "POST", "/api/terms/review", {"accept": [{"kind": "PERSON", "value": "Robin  Example"}],
                                                       "reject": [{"kind": "EMAIL", "value": "robin@example.org"}]})
    assert code == 200 and r["added"] == 1
    saved = json.loads(terms.read_text())
    assert "Robin Example" in next(g for g in saved["terms"] if g["kind"] == "PERSON")["values"]
    assert oct(terms.stat().st_mode & 0o777) == "0o600"
    v = _values(r)
    assert ("PERSON", "Robin Example") not in v and ("EMAIL", "robin@example.org") not in v
    rej = (tmp_path / "state" / "terms-rejected.json")
    assert "robin@example.org" not in rej.read_text() and oct(rej.stat().st_mode & 0o777) == "0o600"
    code, again = call(base, "GET", "/api/terms/suggestions")
    assert ("EMAIL", "robin@example.org") not in _values(again) and again["rejected"] == 1
    code, f = call(base, "DELETE", "/api/terms/rejections")
    assert f["forgotten"] == 1
    assert ("EMAIL", "robin@example.org") in _values(call(base, "GET", "/api/terms/suggestions")[1])


def test_backup_status_tracks_the_terms_file(onboard):
    base, _, terms, stamp = onboard
    assert call(base, "GET", "/api/terms/backup")[1]["in_sync"] is False      # never backed up
    import hashlib
    stamp.write_text(hashlib.sha256(terms.read_bytes()).hexdigest() + "\n")
    b = call(base, "GET", "/api/terms/backup")[1]
    assert b["configured"] and b["in_sync"] is True
    call(base, "POST", "/api/terms/review", {"accept": [{"kind": "PHONE", "value": "555 0100 222"}]})
    assert call(base, "GET", "/api/terms/backup")[1]["in_sync"] is False      # changed since the stamp


def test_lint_flags_terms_that_would_over_mask(onboard):
    base, *_ = onboard
    items = [{"kind": "PERSON", "value": "the"}, {"kind": "ACCOUNT", "value": "ab"}, {"kind": "PHONE", "value": "123"},
             {"kind": "EMAIL", "value": "nobody"}, {"kind": "PERSON", "value": "Robin Example"}]
    w = call(base, "POST", "/api/terms/lint", {"items": items})[1]["warnings"]
    assert w[0] and w[1] and w[2] and w[3] and w[4] == []
