"""Disclosure lifecycle: tiers, policies per mode, dialog choices, the tool's state changes, config."""
import json

import pytest

from local_llm_mcp import prompts
from local_llm_mcp.config import Config, ConfigError
from local_llm_mcp.disclosure import CHOICES, Disclosure, DisclosureChoice, detected_tiers, dialog_message, found_text
from local_llm_mcp.scrub import TIERS, Policy, Scrubber, Vault


def test_defaults_meta_round_trip_and_garbage():
    d = Disclosure.from_meta({})
    assert (d.identity, d.numbers, d.asked) == ("undecided", "masked", 0)
    assert Disclosure.from_meta({}, "open").numbers == "open"
    d.set(identity="open", numbers="open", source="tool")
    again = Disclosure.from_meta({"disclosure": d.to_meta()})
    assert again.to_meta() == d.to_meta()
    bad = Disclosure.from_meta({"disclosure": {"identity": "bogus", "numbers": 7, "asked": "x"}})
    assert (bad.identity, bad.numbers, bad.asked) == ("undecided", "masked", 0)


def test_policy_by_mode_and_state():
    d = Disclosure()
    assert d.policy("pii") == Policy.everything() and d.policy("pii").entropy
    p = d.policy("assist")
    assert p.open == frozenset() and not p.entropy            # undecided: masked until the user answers
    d.set(identity="open")
    assert d.policy("assist").open == TIERS["identity"]
    d.set(numbers="open")
    assert d.policy("assist").open == TIERS["identity"] | TIERS["numbers"] and d.policy("assist").fast
    assert "SECRET" not in d.policy("assist").open              # never openable


def test_apply_dialog_choices():
    d = Disclosure()
    assert d.apply("continue") is False and (d.identity, d.numbers, d.source) == ("open", "masked", "dialog")
    d = Disclosure()
    assert d.apply("everything") is False and (d.identity, d.numbers) == ("open", "open")
    d = Disclosure()
    assert d.apply("switch") is True and d.identity == "undecided"   # the mode changes, the state need not
    with pytest.raises(ValueError):
        Disclosure().apply("maybe")
    with pytest.raises(ValueError):
        Disclosure().set(identity="sometimes")
    assert set(CHOICES) == set(DisclosureChoice.model_json_schema()["properties"]["choice"]["enum"])


def test_detection_signal_and_dialog_text():
    counts = {"EMAIL": 2, "PERSON": 1, "CARD": 1, "SECRET": 3, "PII": 0}
    assert detected_tiers(counts) == {"identity": 3, "numbers": 1}
    assert detected_tiers({"SECRET": 2}) == {}
    assert found_text(counts) == "1 CARD, 2 EMAIL, 1 PERSON"
    msg = dialog_message(counts, "command: ls -la " + "x" * 200)
    assert "2 EMAIL" in msg and "switch" in msg and "everything" in msg and "…" in msg and "SECRET" not in msg
    assert Disclosure().label("pii") == "pii" and Disclosure().label("assist") == "undecided"
    d = Disclosure(); d.apply("continue")
    assert d.label("assist") == "identity open, numbers masked (dialog)"


def test_scrub_policies_follow_the_tiers(tmp_path):
    terms = tmp_path / "terms.json"
    terms.write_text(json.dumps({"terms": [{"kind": "PERSON", "values": ["Jane Q. Example"]}]}))
    sc = Scrubber(None, terms)
    text = ("Jane Q. Example <jane@example.org>, card 4111 1111 1111 1111, SSN 123-45-6789, "
            "token sk-abcdefghijklmnopqrstuvwxyz0123, sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b")  # gitleaks:allow
    shown = sc.scrub(text, Vault(tmp_path / "v1.json"), policy=Policy.assist(identity_open=True))
    assert "jane@example.org" in shown.text and "Jane Q. Example" in shown.text
    assert "4111 1111 1111 1111" not in shown.text and "123-45-6789" not in shown.text and "sk-abcdefghijklmnop" not in shown.text
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b" in shown.text   # no entropy rule in ASSIST
    masked = sc.scrub(text, Vault(tmp_path / "v2.json"), policy=Policy.assist())
    assert "jane@example.org" not in masked.text and "[PERSON-1]" in masked.text
    everything = sc.scrub(text, Vault(tmp_path / "v3.json"), policy=Policy.assist(True, True))
    assert "4111 1111 1111 1111" in everything.text and "sk-abcdefghijklmnop" not in everything.text
    pii = sc.scrub(text, Vault(tmp_path / "v4.json"), policy=Policy.everything())
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b" not in pii.text
    # registering detects everything whatever may later be shown; open vault kinds still pass
    v = Vault(tmp_path / "v5.json")
    counts = sc.register_material(text, v, policy=Policy.register(entropy=False))
    assert {"PERSON", "EMAIL", "CARD", "SSN", "SECRET"} <= set(counts) and detected_tiers(counts) == {"identity": 2, "numbers": 2}
    assert "jane@example.org" in sc.scrub("mail jane@example.org", v, policy=Policy.assist(identity_open=True)).text
    assert "jane@example.org" not in sc.scrub("mail jane@example.org", v, policy=Policy.assist()).text


def test_escalation_config(monkeypatch, tmp_path):
    for k in ("ESCALATION", "ASSIST_NUMBERS", "FALLBACK_BASE_URL", "API_KEY", "API_KEY_FILE", "RULES"):
        monkeypatch.delenv("LOCAL_LLM_MCP_" + k, raising=False)
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    cfg = Config.from_env()
    assert (cfg.escalation, cfg.assist_numbers, cfg.dialog_timeout) == ("ask", "masked", 600.0)
    monkeypatch.setenv("LOCAL_LLM_MCP_ESCALATION", "auto")
    monkeypatch.setenv("LOCAL_LLM_MCP_ASSIST_NUMBERS", "open")
    cfg = Config.from_env()
    assert (cfg.escalation, cfg.assist_numbers) == ("auto", "open")
    monkeypatch.setenv("LOCAL_LLM_MCP_ESCALATION", "sometimes")
    with pytest.raises(ConfigError):
        Config.from_env()


def test_client_instructions_fit_and_mention_disclosure():
    for mode in ("pii", "assist"):
        t = prompts.client_instructions(mode, "m", "http://127.0.0.1:8000/v1")
        assert len(t) <= 2040 and t.endswith("material.") and "local_llm_disclosure" in t
    assert "asks the USER" in prompts.client_instructions("assist", "m", "http://127.0.0.1:8000/v1")
