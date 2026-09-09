"""Tokens-saved estimate: per-turn maths, aggregation, prices merge/override, ledger, report."""
import json

from local_llm_mcp import savings as sv

MODELS = [
    {"provider": "A", "model_id": "m-big", "display_name": "Big", "input_per_m": 5, "output_per_m": 25, "cache_read_per_m": 0.5},
    {"provider": "B", "model_id": "m-small", "display_name": "Small", "input_per_m": 1, "output_per_m": 5, "cache_read_per_m": None},
]
ASSUME = {"chars_per_token": 4, "context_reuse_calls": 10, "caller_model": "m-big"}


def prices(tmp_path, over=None, caller=""):
    p = tmp_path / "prices.json"
    if over is not None:
        p.write_text(json.dumps(over))
    return sv.Prices(p, caller_model=caller)


def test_estimate_by_kind():
    a = sv.Prices.merge({}, {"assumptions": ASSUME})["assumptions"]
    run = sv.estimate_turn({"kind": "run", "gathered_chars": 40000, "out_chars": 2000}, a)
    assert run == {"gathered_tokens": 10000, "returned_tokens": 500, "avoided_input": 9500, "avoided_output": 0, "carried": 95000,
                   "measured": False}
    inline = sv.estimate_turn({"kind": "delegate", "gathered_chars": 0, "out_chars": 800}, a)
    assert (inline["avoided_input"], inline["avoided_output"], inline["carried"]) == (0, 200, 0)
    files = sv.estimate_turn({"kind": "delegate", "gathered_chars": 8000, "out_chars": 400}, a)
    assert (files["avoided_input"], files["avoided_output"]) == (1900, 100)
    verb = sv.estimate_turn({"kind": "delegate", "verbatim": True, "gathered_chars": 8000, "out_chars": 400}, a)
    assert (verb["avoided_input"], verb["avoided_output"]) == (1900, 0)
    assert sv.estimate_turn({"kind": "compaction", "out_chars": 5000}, a)["avoided_input"] == 0
    assert sv.estimate_turn({"kind": "delegate", "out_chars": 800, "error": True}, a)["avoided_output"] == 0
    assert sv.estimate_turn({"kind": "run", "gathered_chars": 100, "out_chars": 2000}, a)["avoided_input"] == 0  # digest longer than raw


def test_costs_carry_rate_and_caller_model(tmp_path):
    pr = prices(tmp_path, {"assumptions": ASSUME, "models": MODELS})
    agg = sv.aggregate([{"kind": "run", "gathered_chars": 40000, "out_chars": 2000},
                        {"kind": "delegate", "out_chars": 800}, {"kind": "mode"}], pr.assumptions)
    assert agg["turns"] == 2 and agg["avoided_input"] == 9500 and agg["avoided_output"] == 200
    big = sv.cost(agg, pr.model("m-big"))
    assert big["direct_usd"] == round(9500 * 5 / 1e6 + 200 * 25 / 1e6, 4)
    assert big["carried_usd"] == round(95000 * 0.5 / 1e6, 4)
    small = sv.cost(agg, pr.model("m-small"))
    assert small["carried_usd"] == round(95000 * 1 / 1e6, 4)  # no cache price: input rate
    assert {"m-big", "m-small"} <= set(sv.costs(agg, pr))  # override merges over the package defaults
    assert pr.caller_model() == "m-big"
    assert prices(tmp_path, caller="m-small").caller_model() == "m-small"
    assert prices(tmp_path, caller="nope").caller_model() == "m-big"  # unknown override ignored


def test_package_defaults_are_seeded_and_priced():
    pr = sv.Prices(None)
    assert len(pr.models) >= 20 and pr.doc["checked"]
    providers = {m["provider"] for m in pr.models}
    assert {"Anthropic", "OpenAI", "Google"} <= providers
    for m in pr.models:
        assert m["input_per_m"] > 0 and m["output_per_m"] > 0 and m["source_url"].startswith("https://"), m
    assert pr.caller_model() == pr.assumptions["caller_model"]


def test_override_merges_disables_hot_reloads_and_resets(tmp_path):
    p = tmp_path / "prices.json"
    pr = sv.Prices(p)
    n = len(pr.models)
    first = pr.models[0]["model_id"]
    second = pr.models[1]["model_id"]
    p.write_text(json.dumps({"assumptions": {"chars_per_token": 3.0},
                             "models": [{"model_id": first, "input_per_m": 99},
                                        {"model_id": second, "enabled": False},
                                        {"provider": "Mine", "model_id": "custom-1", "input_per_m": 1, "output_per_m": 2}]}))
    assert pr.assumptions["chars_per_token"] == 3.0 and pr.override_present
    assert pr.model(first)["input_per_m"] == 99 and pr.model(first)["output_per_m"] > 0  # merged, not replaced
    assert pr.model(second) is None and pr.model("custom-1")["provider"] == "Mine"
    assert len(pr.models) == n  # one disabled, one added
    assert pr.reset_override() and not p.exists()
    assert len(pr.models) == n + 1 - 1 + 0 and pr.model(second) is not None and pr.assumptions["chars_per_token"] == 3.8


def test_save_override_round_trip(tmp_path):
    p = tmp_path / "prices.json"
    pr = sv.Prices(p)
    hidden = pr.models[0]["model_id"]
    doc = pr.save_override({"assumptions": {"context_reuse_calls": 3, "caller_model": "custom-2"},
                            "models": [{"provider": "X", "model_id": "custom-2", "input_per_m": "2.5", "output_per_m": 10,
                                        "cache_read_per_m": ""}, {"model_id": hidden, "enabled": False}]})
    assert p.is_file() and doc["assumptions"]["context_reuse_calls"] == 3
    m = pr.model("custom-2")
    assert m["input_per_m"] == 2.5 and m["cache_read_per_m"] is None and pr.caller_model() == "custom-2"
    assert pr.model(hidden) is None  # a disabled default stays hidden across reloads
    assert any(r.get("enabled") is False for r in json.loads(p.read_text())["models"])


def test_ledger_reprices_history_with_current_assumptions(tmp_path):
    led = sv.Ledger(tmp_path / "state" / "savings.jsonl")
    led.append("s1", {"kind": "run", "gathered_chars": 40000, "out_chars": 2000, "ts": "2026-01-01T00:00:00"})
    led.append("s2", {"kind": "delegate", "gathered_chars": 0, "out_chars": 800})
    led.append("s2", {"kind": "mode"})  # not counted, not written
    assert len(led.records()) == 2
    t = led.totals(sv.Prices.merge({}, {"assumptions": ASSUME})["assumptions"])
    assert (t["turns"], t["sessions"], t["avoided_input"], t["avoided_output"], t["since"]) == (2, 2, 9500, 200, "2026-01-01T00:00:00")
    t2 = led.totals(sv.Prices.merge({}, {"assumptions": {"chars_per_token": 2, "context_reuse_calls": 0}})["assumptions"])
    assert t2["avoided_input"] == 19000 and t2["carried"] == 0


def test_report_shape(tmp_path):
    pr = prices(tmp_path, {"assumptions": ASSUME, "models": MODELS})
    led = sv.Ledger(tmp_path / "savings.jsonl")
    led.append("other", {"kind": "run", "gathered_chars": 4000, "out_chars": 400})
    led.append("s1", {"kind": "run", "gathered_chars": 40000, "out_chars": 2000})
    led.append("pid-9", {"kind": "run", "gathered_chars": 4000, "out_chars": 400, "gathered_tokens": 1000, "returned_tokens": 100})
    r = sv.report(["s1", "pid-9"], led, pr, pending=1)
    assert r["caller_model"] == "m-big" and r["session"]["avoided_input"] == 9500 + 900 and r["all_time"]["turns"] == 3
    assert r["session"]["turns"] == 2 and r["session"]["measured_turns"] == 1 and r["session"]["pending_measurements"] == 1
    assert r["prices_age_days"] is not None and r["prices_stale"] is False
    assert r["session"]["cost"]["with_carry_usd"] > r["session"]["cost"]["direct_usd"] > 0
    assert {"m-big", "m-small"} <= set(r["per_model"])
    assert sv.fmt_tokens(950) == "950" and sv.fmt_tokens(9500) == "9.5K" and sv.fmt_tokens(2_400_000) == "2.4M"


def test_gathered_inference_for_turns_older_than_the_ledger():
    assert sv.gathered_chars({"kind": "run", "raw_chars": 5000}) == 5000
    assert sv.gathered_chars({"kind": "delegate", "raw_chars": 5000, "source": "inline (5000 chars)"}) == 0
    assert sv.gathered_chars({"kind": "delegate", "raw_chars": 9000, "source": "inline (1000 chars); paths: …/a.py, …/b.py"}) == 8000
    assert sv.gathered_chars({"kind": "delegate", "raw_chars": 7000, "source": "command: ls -la"}) == 7000
    assert sv.gathered_chars({"kind": "delegate", "raw_chars": 7000, "source": "…/src/module.py"}) == 7000  # single-file verbatim
    assert sv.gathered_chars({"kind": "delegate", "raw_chars": 7000, "gathered_chars": 123}) == 123  # recorded wins
    assert sv.gathered_chars({"kind": "compaction", "raw_chars": 7000}) == 0


def test_ledger_backfill_is_idempotent(tmp_path):
    sessions = tmp_path / "sessions"
    for key, turns in {"s1": [{"id": "t_1", "kind": "run", "raw_chars": 4000, "out_chars": 400, "ts": "2026-01-01T00:00:00"},
                              {"id": "t_2", "kind": "mode"}],
                       "s2": [{"id": "t_3", "kind": "delegate", "raw_chars": 3000, "out_chars": 300, "source": "inline (3000 chars)",
                               "result": "ERROR: boom"}]}.items():
        (sessions / key).mkdir(parents=True)
        (sessions / key / "context.jsonl").write_text("".join(json.dumps(t) + "\n" for t in turns))
    led = sv.Ledger(tmp_path / "savings.jsonl")
    assert led.backfill(sessions) == 2 and led.backfill(sessions) == 0
    recs = led.records()
    assert {(r["session"], r["turn"]) for r in recs} == {("s1", "t_1"), ("s2", "t_3")}
    assert next(r for r in recs if r["turn"] == "t_3")["error"] is True
    led.append("s3", {"id": "t_9", "kind": "run", "gathered_chars": 10, "out_chars": 1})
    assert led.backfill(sessions) == 0 and len(led.records()) == 3


def test_measured_counts_win_over_the_chars_estimate():
    a = sv.Prices.merge({}, {"assumptions": ASSUME})["assumptions"]
    e = sv.estimate_turn({"kind": "run", "gathered_chars": 40000, "out_chars": 2000, "gathered_tokens": 9000, "returned_tokens": 400}, a)
    assert e["measured"] and (e["gathered_tokens"], e["returned_tokens"], e["avoided_input"], e["carried"]) == (9000, 400, 8600, 86000)
    half = sv.estimate_turn({"kind": "run", "gathered_chars": 40000, "out_chars": 2000, "gathered_tokens": 9000, "returned_tokens": None}, a)
    assert not half["measured"] and half["gathered_tokens"] == 10000  # one count missing -> chars for both
    assert sv.estimate_turn({"kind": "run", "gathered_chars": 40000, "out_chars": 2000, "gathered_tokens": True, "returned_tokens": 5}, a)["measured"] is False
    err = sv.estimate_turn({"kind": "run", "gathered_chars": 40000, "out_chars": 2000, "gathered_tokens": 9000, "returned_tokens": 400, "error": True}, a)
    assert err["avoided_input"] == 0 and err["avoided_output"] == 0
    agg = sv.aggregate([{"kind": "run", "gathered_chars": 400, "out_chars": 40, "gathered_tokens": 100, "returned_tokens": 10},
                        {"kind": "run", "gathered_chars": 400, "out_chars": 40}], a)
    assert agg["turns"] == 2 and agg["measured_turns"] == 1 and agg["avoided_input"] == 90 + 90


def test_ledger_keeps_measured_counts_and_nulls(tmp_path):
    led = sv.Ledger(tmp_path / "l.jsonl")
    led.append("s", {"kind": "run", "gathered_chars": 40, "out_chars": 4, "gathered_tokens": 10, "returned_tokens": None})
    led.append("s", {"kind": "run", "gathered_chars": 40, "out_chars": 4})
    r1, r2 = led.records()
    assert r1["gathered_tokens"] == 10 and r1["returned_tokens"] is None and "gathered_tokens" not in r2


def test_price_staleness(tmp_path):
    p = tmp_path / "prices.json"
    p.write_text(json.dumps({"checked": "2020-01-01", "assumptions": {"stale_after_days": 30}, "models": MODELS}))
    pr = sv.Prices(p)
    assert pr.age_days() > 2000 and pr.stale()
    p.write_text(json.dumps({"checked": "2020-01-01", "assumptions": {"stale_after_days": 100000}, "models": MODELS}))
    assert not pr.stale()
    p.write_text(json.dumps({"checked": "not a date", "models": MODELS}))
    assert pr.age_days() is None and pr.stale()  # unreadable date reads as stale
    assert not sv.Prices(None).stale()  # the package defaults are fresh on the day they ship


def test_tokenizer_factor_scales_cost_per_model(tmp_path):
    """Counts are the worker tokenizer's; a model whose tokenizer yields more tokens saves proportionally more."""
    import json
    p = tmp_path / "prices.json"
    p.write_text(json.dumps({"models": [
        {"provider": "T", "model_id": "same", "input_per_m": 10, "output_per_m": 10, "cache_read_per_m": 1},
        {"provider": "T", "model_id": "double", "input_per_m": 10, "output_per_m": 10, "cache_read_per_m": 1, "tokenizer_factor": 2.0},
        {"provider": "T", "model_id": "absurd", "input_per_m": 10, "output_per_m": 10, "cache_read_per_m": 1, "tokenizer_factor": 99},
    ]}))
    pr = sv.Prices(p, caller_model="double")
    agg = {"avoided_input": 1_000_000, "avoided_output": 0, "carried": 1_000_000}
    c = sv.costs(agg, pr)
    assert c["same"]["tokenizer_factor"] == 1.0 and c["same"]["direct_usd"] == 10 and c["same"]["carried_usd"] == 1
    assert c["double"]["tokenizer_factor"] == 2.0 and c["double"]["direct_usd"] == 20 and c["double"]["carried_usd"] == 2
    assert c["double"]["model_tokens"]["avoided_input"] == 2_000_000
    assert c["absurd"]["tokenizer_factor"] == 1.0  # out of range → ignored, not trusted
    assert next(m for m in sv.Prices(None).models if m["model_id"] == "claude-opus-5")["tokenizer_factor"] == 1.3
    assert next(m for m in sv.Prices(None).models if m["model_id"] == "claude-haiku-4-5")["tokenizer_factor"] == 1.0
